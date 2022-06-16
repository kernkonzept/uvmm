/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2013-2020 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#pragma once

#include <l4/sys/l4int.h>
#include <l4/cxx/bitfield>
#include <l4/cxx/ref_ptr>
#include <l4/cxx/unique_ptr>
#include <l4/cxx/utils>

#include <cassert>
#include <condition_variable>
#include <cstdio>
#include <mutex>

#include "debug.h"
#include "gic_iface.h"
#include "mmio_device.h"
#include "irq.h"
#include "vcpu_ptr.h"

#include "monitor/gic_cmd_handler.h"

extern __thread unsigned vmm_current_cpu_id;

namespace Gic {

/**
 * Item on an Atomic_fwd_list.
 */
class Atomic_fwd_list_item
{
  template<typename T>
  friend class Atomic_fwd_list;

  enum {
    // Element is not in a list. Distinct from nullptr which is is the end of
    // list.
    Mark_deleted = 1,
  };

public:
  Atomic_fwd_list_item() : _next((Atomic_fwd_list_item*)Mark_deleted) {}

  bool in_list() const { return _next != (Atomic_fwd_list_item*)Mark_deleted; }

private:
  Atomic_fwd_list_item(Atomic_fwd_list_item *n) : _next(n) {}

  Atomic_fwd_list_item *_next;
};

/**
 * A single linked, lock-free list, where parallel insertion is supported.
 *
 * Items that are stored on the list must be derived from Atomic_fwd_list_item.
 * The only supported concurrent methods are push() and swap(). All other
 * methods are *not* thread safe. Internally it is a single linked list.
 */
template<typename T>
class Atomic_fwd_list
{
public:
  Atomic_fwd_list() : _head(nullptr) {}

  class Iterator
  {
    friend class Atomic_fwd_list;

  public:
    Iterator() : _e(nullptr), _pn(nullptr) {}

    Iterator operator++()
    {
      _pn = &_e->_next;
      _e = _e->_next;
      return *this;
    }

    T *operator*() const { return static_cast<T*>(_e); }
    T *operator->() const { return static_cast<T*>(_e); }

    bool operator==(Iterator const &other) const { return other._e == _e; }
    bool operator!=(Iterator const &other) const { return other._e != _e; }

  private:
    Iterator(Atomic_fwd_list_item **pn, Atomic_fwd_list_item *e)
    : _e(e), _pn(pn) {}
    Iterator(Atomic_fwd_list_item **head) : _e(*head), _pn(head) {}
    Iterator(Atomic_fwd_list_item *e) : _e(e), _pn(nullptr) {}

    Atomic_fwd_list_item *_e;

    // Pointer to _next pointer of previous element that points to _e.
    Atomic_fwd_list_item **_pn;
  };

  Iterator before_begin() { return Iterator(&_head); }
  Iterator begin() { return Iterator(&_head._next); }
  Iterator end() { return Iterator(); }

  /**
   * Add element to front of list.
   *
   * It is safe against concurrent insert attempts, even of the same element.
   * This is achieved by synchronizing on the _next pointer. Elements that are
   * not on a list are marked as "logically deleted" (Mark_deleted), as done by
   * erase(). This guarantees that the object is currently not visible on the
   * list. If setting that pointer fails, some other thread was faster and the
   * element is being inserted currently.
   *
   * We do *not* wait until being inserted if the _next pointer could not be
   * set. It is the responsibility of the caller to cope with the possibility
   * that the element is not yet visible on the list on such concurrent
   * inserts.
   */
  void push(T *e)
  {
    Atomic_fwd_list_item *old_next = __atomic_load_n(&e->_next, __ATOMIC_ACQUIRE);
    if (old_next != (Atomic_fwd_list_item*)Atomic_fwd_list_item::Mark_deleted)
      return;

    Atomic_fwd_list_item *head = __atomic_load_n(&_head._next, __ATOMIC_ACQUIRE);
    if (!__atomic_compare_exchange_n(&e->_next, &old_next, head,
                                     false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
      return;

    // We now "own" the element and must complete the insert. It's not yet
    // visible on the list. There could still be other concurrent inserts on
    // the same list for different elements, though.
    while (!__atomic_compare_exchange_n(&_head._next, &head,
                                        static_cast<Atomic_fwd_list_item*>(e),
                                        true, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
      __atomic_store_n(&e->_next, head, __ATOMIC_RELEASE);
  }

  /**
   * Atomically swap this and the other list.
   *
   * The content of this instance must no be manipulated concurrently.
   * Atomicity is only guaranteed wrt. the \a other list.
   */
  void swap(Atomic_fwd_list &other)
  {
    Atomic_fwd_list_item *cur = _head._next;
    Atomic_fwd_list_item *o = __atomic_load_n(&other._head._next,
                                              __ATOMIC_ACQUIRE);
    while (!__atomic_compare_exchange_n(&other._head._next, &o, cur, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
      ;

    _head._next = o;
  }

  /**
   * Remove item from list.
   *
   * This method is *not* thread safe. There must be no concurrent
   * manipulations of the list!
   */
  static Iterator erase(Iterator const &e)
  {
    Iterator ret(e._pn, e._e->_next);
    *e._pn = e._e->_next;
    __atomic_store_n(&e._e->_next,
                     (Atomic_fwd_list_item*)Atomic_fwd_list_item::Mark_deleted,
                     __ATOMIC_RELEASE);
    return ret;
  }

  /**
   * Move item from \a other list to this one after \a pos.
   *
   * The moved element is always seen as if it is on a list. Protects against
   * concurrent push() calls for the element that is moved between the lists.
   * This method is *not* thread safe.
   *
   * \return Iterator pointing to element after \a e on the \a other list.
   */
  static Iterator move_after(Iterator const &pos, Atomic_fwd_list& /*other*/,
                             Iterator const &e)
  {
    Iterator ret(e._pn, e._e->_next);

    *e._pn = e._e->_next;
    e._e->_next = pos._e->_next;
    pos._e->_next = e._e;

    return ret;
  }

private:
  Atomic_fwd_list_item _head;
};

class Irq;

/**
 * Base class for GIC CPU interface that corresponds to a vCPU threads handling
 * its IRQs.
 *
 * Each vCPU that is visible on the GIC has an instance of this class. The
 * X-CPU Irq notification handler is always bound to the right vCPU thread. As
 * long as the vCPU is online the migration handler is bound there too. Only
 * in case a CPU is offline the migration handler will be bound to the boot CPU
 * to keep IRQ migration working.
 *
 * In any case, it must be guaranteed that only one thread will ever handle the
 * queued Irqs on this object! Only queuing Irqs is thread safe.
 */
class Vcpu_handler : public L4::Irqep_t<Vcpu_handler>
{
  /**
   * Dummy handler for X-CPU IPIs.
   *
   * Only exists so that the target vCPU traps into the vmm on X-CPU
   * interrupts. Is always bound to the target vCPU thread even when the CPU
   * is offline.
   */
  struct Irq_event_receiver : public L4::Irqep_t<Irq_event_receiver>
  {
  public:
    void handle_irq() {}
  };

public:
  Vcpu_handler(Vmm::Vcpu_ptr vcpu)
  : _cpu_id(vcpu.get_vcpu_id())
  {
    auto *registry = vcpu.get_ipc_registry();
    L4Re::chkcap(registry->register_irq_obj(&_irq_event),
                 "Cannot register X-CPU irq event");

    // Migration event is initially only bound on boot vCPU. For all others
    // offline() needs to be called.
    _migration_event = L4Re::chkcap(L4Re::Util::make_unique_cap<L4::Irq>(),
                                   "allocate migration event");
    L4Re::chksys(L4Re::Env::env()->factory()->create(_migration_event.get()),
                 "create migration event");
  }

  /// Send a notification to this vCPU that an Irq is pending.
  void notify_irq()
  { _irq_event.obj_cap()->trigger(); }

  /// Signal that migration maintenance is necessary
  void notify_migration()
  { _migration_event->trigger(); }

  /**
   * Queue Irq as pending on this vCPU.
   *
   * The vCPU is not notified. It is the responsibility of the caller to
   * trigger X-CPU notifications if necessary.
   */
  void queue(Irq *e)
  {
    _pending_irqs.push(e);
  }

  inline bool online() const { return _online; }

  /**
   * Mark CPU interface as online.
   *
   * Transfers the responsibility of the migration work back to the actual
   * vcpu. This must of course not be done for the VCPU that acts as sentinel.
   * Must be called from the vCPU that comes online.
   */
  void online(Vmm::Vcpu_ptr vcpu, bool boot_cpu)
  {
    _online = true;

    // The vCPU is about to take over IRQ injection and migration. The old
    // sentinel vCPU must reliquish its ownership and pass it to us.
    if (!boot_cpu)
      {
        std::unique_lock<std::mutex> lock(_migration_lock);
        _migration_rebind = vcpu;
        notify_migration();
        while (*_migration_rebind != nullptr)
          _migration_cv.wait(lock);
      }
  }

  /**
   * Mark CPU interface as offline.
   *
   * Most importantly it pushes the migration handling to the sentinel vCPU
   * (read: the boot CPU). Because this must be called from the vCPU that goes
   * offline there can be no migration handling running. Hence there is no need
   * to synchronize the rebinding.
   */
  void offline(Vmm::Vcpu_ptr sentinel_vcpu)
  {
    rebind(sentinel_vcpu.get_ipc_registry());
    _online = false;
  }

  /**
   * Push away Irqs that are on our pending list but that do not belong here.
   */
  void handle_migrations();

  // L4::Irqep_t<> callback for _migration_event
  void handle_irq()
  {
    handle_migrations();

    // relinquish migration responsibility if requested
    std::lock_guard<std::mutex> lock(_migration_lock);
    if (*_migration_rebind != nullptr)
      {
        rebind(_migration_rebind.get_ipc_registry());
        _migration_rebind = Vmm::Vcpu_ptr(nullptr);
        _migration_cv.notify_one();
      }
  }

  unsigned vcpu_id() const { return _cpu_id; }

protected:
  /// Priority sorted list of pending IRQs owned by this vCPU.
  Atomic_fwd_list<Irq> _owned_pend_irqs;

  /// The logical CPU number this interface belongs to
  unsigned _cpu_id;

  /**
   * Move all new pending Irqs to our priority sorted _owned_pend_irqs
   * list.
   */
  void fetch_pending_irqs();

private:
  /// The list of pending IRQs for this (or an invalid) vCPU.
  Atomic_fwd_list<Irq> _pending_irqs;

  /// The x-CPU pending IRQ notification
  Irq_event_receiver _irq_event;

  /// The pending migration signal
  L4Re::Util::Unique_cap<L4::Irq> _migration_event;

  /// Mutex protecting the migration handler rebinding
  std::mutex _migration_lock;

  /// Condition variable to sync the transition of the migration handler
  std::condition_variable _migration_cv;

  /// The new migration handler (or nullptr if ownership is kept)
  Vmm::Vcpu_ptr _migration_rebind = Vmm::Vcpu_ptr(nullptr);

  /// Is the corresponding vCPU online?
  bool _online = false;

  void rebind(L4Re::Util::Object_registry *registry)
  {
    L4Re::chkcap(registry->register_obj(this, _migration_event.get()),
                       "Cannot register migration event");
  }
};

class Irq_info
{
private:
  template<bool T, typename V>
  friend class Monitor::Gic_cmd_handler;

  using State = l4_uint32_t;
  State _state = 0;

public:
  CXX_BITFIELD_MEMBER_RO( 0,  0, pending,     _state); // GICD_I[SC]PENDRn
  CXX_BITFIELD_MEMBER_RO( 1,  1, active,      _state); // GICD_I[SC]ACTIVERn
  CXX_BITFIELD_MEMBER_RO( 3,  3, enabled,     _state); // GICD_I[SC]ENABLERn
  CXX_BITFIELD_MEMBER_RO( 4, 11, cpu,         _state); // the owning vcpu

  CXX_BITFIELD_MEMBER_RO(12, 19, target,      _state); // GICD_ITARGETSRn ...
  CXX_BITFIELD_MEMBER_RO(20, 27, prio,        _state); // GICD_IPRIORITYRn
  CXX_BITFIELD_MEMBER_RO(28, 29, config,      _state); // GICD_ICFGRn
  CXX_BITFIELD_MEMBER_RO(30, 30, group,       _state); // GICD_IGROUPRn

  enum { Invalid_cpu = 0xff }; // special case for cpu field

private:
  template<typename BFM, typename STATET, typename VALT>
  static bool atomic_set(STATET *state, VALT v)
  {
    State old = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    State nv;
    do
      {
        nv = BFM::set_dirty(old, v);
        if (old == nv)
          return false;
      }
    while (!__atomic_compare_exchange_n(state, &old, nv,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return true;
  }

  enum
  {
    Pending_and_enabled = pending_bfm_t::Mask | enabled_bfm_t::Mask,
    Pecpu_mask = Pending_and_enabled | cpu_bfm_t::Mask,
  };

  static bool is_pending_and_enabled(State state)
  { return (state & Pending_and_enabled) == Pending_and_enabled; }

  static bool is_pending_or_enabled(State state)
  { return state & Pending_and_enabled; }

  static bool is_active(State state)
  { return state & active_bfm_t::Mask; }

  Irq_info(Irq_info const &) = delete;
  Irq_info operator = (Irq_info const &) = delete;

  /**
   * Set the pending or enabled bit.
   *
   * \return True if we made the IRQ pending&enabled. False if the IRQ was
   *         already pending&enabled or is not yet pending&enabled.
   */
  bool set_pe(unsigned char set)
  {
    State old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    do
      {
        if (old & set)
          return false;
      }
    while (!__atomic_compare_exchange_n(&_state, &old, old | set,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return is_pending_or_enabled(old);
  }

  /**
   * Clear the pending or enabled flag.
   */
  void clear_pe(unsigned char clear)
  {
    State old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    do
      {
        if (!(old & clear))
          return;
      }
    while (!__atomic_compare_exchange_n(&_state, &old, old & ~clear,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  }

public:
  Irq_info() = default;

  bool enable()
  { return set_pe(enabled_bfm_t::Mask); }

  void disable()
  { return clear_pe(enabled_bfm_t::Mask); }

  bool set_pending()
  { return set_pe(pending_bfm_t::Mask); }

  void clear_pending()
  { return clear_pe(pending_bfm_t::Mask); }

  class Take_result
  {
  public:
    enum Result { Ok, Drop, Keep };
    constexpr Take_result(Result r) : _r(r) {}
    explicit constexpr operator bool() const { return _r == Ok; }
    constexpr bool drop() const { return _r == Drop; }
    constexpr bool keep() const { return _r == Keep; }
  private:
    Result _r;
  };

  /**
   * Try to atomically take a pending&enabled Irq for injection on \a cpu.
   *
   * Depending on the status this might succeed or, if failed, requires
   * different actions. Either the Irq is still relevant for the cpu. In this
   * case Take_result::Keep is returned. Or the Irq should be removed from the
   * pending list of the \a cpu. This might be because the Irq is not p&e any
   * more or needs to be pushed to a different CPU.
   */
  Take_result take_on_cpu(unsigned char cpu)
  {
    State old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    State nv;
    do
      {
        if (!is_pending_and_enabled(old))
          return Take_result::Drop;

        // Pending&enabled IRQs are always queued on the right CPU even if they
        // are still active on the old cpu. If the target CPU is invalid the
        // original CPU retains the burden of coping with this rogue IRQ.
        if (cpu_bfm_t::get(old) != cpu)
          return cpu_bfm_t::get(old) == Invalid_cpu ? Take_result::Keep
                                                    : Take_result::Drop;

        // Already active? Cannot take twice!
        if (is_active(old))
          return Take_result::Keep;

        nv = (old & ~pending_bfm_t::Mask) | active_bfm_t::Mask;
      }
    while (!__atomic_compare_exchange_n(&_state, &old, nv,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return Take_result::Ok;
  }

  bool eoi()
  {
    State old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    while (!__atomic_compare_exchange_n(&_state, &old,
                                        old & ~active_bfm_t::Mask,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
      ;

    return is_pending_and_enabled(old);
  }

  bool prio(unsigned char p)
  { return atomic_set<prio_bfm_t>(&_state, p); }

  bool active(bool a)
  { return atomic_set<active_bfm_t>(&_state, a); }

  bool group(bool grp1)
  { return atomic_set<group_bfm_t>(&_state, grp1); }

  bool config(unsigned cfg)
  { return atomic_set<config_bfm_t>(&_state, cfg); }

  void target(unsigned char reg, unsigned char cpu)
  {
    State old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    State nv;
    do
      {
        nv = target_bfm_t::set_dirty(old, reg);
        nv = cpu_bfm_t::set_dirty(nv, cpu);
        if (old == nv)
          return;
      }
    while (!__atomic_compare_exchange_n(&_state, &old, nv, true,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  }

  bool is_pending_and_enabled() const
  {
    State state = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    return is_pending_and_enabled(state);
  }
};

class Irq : public Atomic_fwd_list_item
{
public:
  Irq() = default;

  Irq(const Irq &) = delete;
  Irq(Irq &&) noexcept = delete;
  Irq& operator=(const Irq &) = delete;
  Irq& operator=(Irq &&) noexcept = delete;

  enum { Invalid_cpu = Irq_info::Invalid_cpu };

  bool enabled() const { return _irq.enabled(); }
  bool pending() const { return _irq.pending(); }
  bool active() const { return _irq.active(); }
  bool group() const { return _irq.group(); }
  unsigned char config() const { return _irq.config(); }
  unsigned char prio() const { return _irq.prio(); }
  unsigned char target() const { return _irq.target(); }

  Eoi_handler *get_eoi_handler() const { return _eoi; }

  bool is_pending_and_enabled() const { return _irq.is_pending_and_enabled(); }
  bool is_for_cpu(unsigned char cpu_id)
  { return _irq.cpu() == cpu_id || _irq.cpu() == Invalid_cpu; }

  unsigned char cpu() const { return _irq.cpu(); }
  unsigned id() const { return _id; }
  unsigned lr() const { return _lr; }

  void set_eoi(Eoi_handler *eoi) { _eoi = eoi; }
  void set_id(uint16_t id) { _id = id; }

  Vcpu_handler *enable(bool ena)
  {
    Vcpu_handler *ret = nullptr;
    if (ena)
      {
        if (_irq.enable())
          ret = __atomic_load_n(&_vcpu, __ATOMIC_ACQUIRE);
      }
    else
      _irq.disable();

    if (ret)
      ret->queue(this);

    return ret;
  }

  Vcpu_handler *pending(bool pend)
  {
    Vcpu_handler *ret = nullptr;
    if (pend)
      {
        if (_irq.set_pending())
          ret = __atomic_load_n(&_vcpu, __ATOMIC_ACQUIRE);
      }
    else
      _irq.clear_pending();

    if (ret)
      ret->queue(this);

    return ret;
  }

  Irq_info::Take_result take_on_cpu(unsigned char cpu)
  {
    return _irq.take_on_cpu(cpu);
  }

  void eoi()
  {
    if (_irq.eoi())
      vcpu_handler()->notify_irq();
    if (_eoi)
      _eoi->eoi();
  }

  void prio(unsigned char p) { _irq.prio(p); }
  void active(bool act) { _irq.active(act); }
  void group(bool grp1) { _irq.group(grp1); }
  void config(unsigned char cfg) { _irq.config(cfg); }

  void set_lr(unsigned idx) { _lr = idx; }
  void clear_lr() { set_lr(0); }

  /**
   * Change target of Irq to potentially different vCPU.
   *
   * *Must* not be called concurrently from multiple CPUs. Other operations
   * can still be invoked in parallel from other CPUs.
   *
   * \param reg    The field value in GICD_ITARGETSRn register.
   * \param vcpu   The new vCPU that handles pending Irqs. May be nullptr in
   *               case the irq targets no valid vCPU (e.g. only offline or
   *               non-exiting vCPUs).
   *
   * If there is no valid target for the Irq the old vCPU still has to cope
   * with the pending Irqs. This is considered an error of the guest because an
   * enabled Irq should always target a valid CPU.
   */
  void target(unsigned char reg, Vcpu_handler *vcpu)
  {
    Vcpu_handler *old = __atomic_load_n(&_vcpu, __ATOMIC_ACQUIRE);
    if (vcpu)
      __atomic_store_n(&_vcpu, vcpu, __ATOMIC_RELEASE);

    // New queues and notifications will already go to the new vCPU. It cannot
    // be taken there yet because the cpu field is not updated. But even then
    // it will stay on the right list.

    _irq.target(reg, vcpu ? vcpu->vcpu_id() : (unsigned char)Invalid_cpu);

    // If the IRQ is queued it must most likely be evicted from the old list.
    // It might also got queued during migration but waking the old vCPU does
    // not harm.
    if (in_list() && old != vcpu)
      old->notify_migration();
  }

  Vcpu_handler *vcpu_handler() const
  {
    return __atomic_load_n(&_vcpu, __ATOMIC_ACQUIRE);
  }

private:
  Vcpu_handler *_vcpu = nullptr;
  Eoi_handler *_eoi = nullptr;
  Irq_info _irq;
  uint16_t _id = 0;

  /*
   * Keeps track of the used lr, uses 0 for "no link register
   * assigned" (see #get_empty_lr())
   */
  unsigned char _lr = 0;
};

using Const_irq = const Irq;

class Irq_array
{
public:
  using Irq = ::Gic::Irq;
  using Const_irq = ::Gic::Const_irq;

  explicit Irq_array(unsigned irqs, unsigned first_irq)
  : _size(irqs)
  {
    _irqs = cxx::unique_ptr<Irq[]>(new Irq[irqs]);
    for (unsigned i = 0; i < irqs; i++)
      _irqs.get()[i].set_id(i + first_irq);
  }

  Irq &operator [] (unsigned i)
  { return _irqs.get()[i]; }

  Irq const &operator [] (unsigned i) const
  { return _irqs.get()[i]; }

  unsigned size() const { return _size; }

private:
  cxx::unique_ptr<Irq[]> _irqs;
  unsigned _size;
};

///////////////////////////////////////////////////////////////////////////////
// GIC CPU interface
class Cpu : public Vcpu_handler
{
  template<bool T, typename V>
  friend class Monitor::Gic_cmd_handler;

public:
  using Irq = ::Gic::Irq;
  using Const_irq = ::Gic::Const_irq;

  enum { Num_local = 32 };
  enum { Num_lrs = 4, Lr_mask = (1UL << Num_lrs) - 1U };

  static_assert(Num_lrs <= 32, "Can only handle up to 32 list registers.");

  Cpu(Vmm::Vcpu_ptr vcpu, Irq_array *spis)
  : Vcpu_handler(vcpu), _local_irq(Num_local, 0)
  {
    memset(&_sgi_pend, 0, sizeof(_sgi_pend));

    _vcpu = vcpu;
    _spis = spis;
  }

  /// Get the number of CPU local IRQs
  static unsigned num_local() { return Num_local; }

  /// Get if this is a valid CPU interface (with a vCPU.
  bool is_valid() const { return *_vcpu; }

  /**
   * Get the Processor_Number + Affinity_Value of GICv3+ GICR_TYPER.
   *
   * If this his not a valid CPU interface affinity willbe 0xffffffff.
   */
  l4_uint64_t get_typer() const
  {
    if (is_valid())
      return (((l4_uint64_t)_vcpu.get_vcpu_id()) << 8)
             | (((l4_uint64_t)affinity()) << 32);

    return 0xffffffff00000000;
  }

  /// get the local IRQ for irqn (irqn < 32)
  Irq& local_irq(unsigned irqn) { return _local_irq[irqn]; }
  /// get the array of local IRQs of this CPU
  Irq_array &local_irqs() { return _local_irq; }

  /*
   * Get empty list register
   *
   * We might try to preempt a lower priority interrupt from the
   * link registers here. But since our main guest does not use
   * priorities we ignore this possibility.
   *
   * \return Returns 0 if no empty list register is available, (lr_idx
   *         + 1) otherwise
   */
  unsigned get_empty_lr() const
  { return __builtin_ffs(l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_ELSR) & Lr_mask); }

  /// return if there are pending IRQs in the LRs
  bool pending_irqs() const
  {
    l4_uint32_t elsr = l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_ELSR) & Lr_mask;
    return elsr != Lr_mask;
  }

  /// Get in Irq for the given `intid`, works for SGIs, PPIs, and SPIs
  Irq& irq_from_intid(unsigned intid)
  {
    if (intid < Num_local)
      return _local_irq[intid];
    else
      return (*_spis)[intid - Num_local];
  }

  /// Get the associated vCPU
  Vmm::Vcpu_ptr vcpu() const { return _vcpu; }

  /**
   * Set a GICv2 SGI pending and notify this vCPU.
   * \pre `irq` < 16.
   */
  void ipi(unsigned irq)
  {
    if (set_sgi(irq))
      notify_irq();
  }

  /// Read GICv2 GICD_[SC]PENDSGIR<reg>
  l4_uint32_t read_sgi_pend(unsigned reg)
  { return _sgi_pend[reg]; }

  /// Write GICv2 GICD_SPENDSGIR<reg>
  void write_set_sgi_pend(unsigned reg, l4_uint32_t value);
  /// Write GICv2 GICD_CPENDSGIR<reg>
  void write_clear_sgi_pend(unsigned reg, l4_uint32_t value);

  /// Handle pending EOIs
  template<typename CPU_IF>
  void handle_eois();

  /// Handle pending GICv2 SGIs
  template<typename GIC_IMPL>
  void handle_ipis();

  /// Add a pending IRQ into a list register (LR).
  template<typename CPU_IF>
  void add_pending_irq(unsigned lr, Irq &irq, unsigned src_cpu = 0);

  /// Try to inject an SPI on this CPU
  template<typename CPU_IF>
  bool inject(Irq &irq, unsigned src_cpu = 0);

  /// Handle pending vGIC maintenance IRQs
  template<typename CPU_IF>
  void handle_maintenance_irq()
  { handle_eois<CPU_IF>(); }

  /**
   * Find and take a pending&enabled IRQ targeting this CPU.
   *
   * If an Irq is returned it *must* be added to a Lr. The Irq will already be
   * marked as active.
   */
  Irq *take_pending_irq(unsigned char min_prio)
  {
    bool rescan;
    do
      {
        rescan = false;
        fetch_pending_irqs();

        for (auto it = _owned_pend_irqs.begin(); it != _owned_pend_irqs.end();)
          {
            if (it->prio() >= min_prio)
              break;

            auto took = it->take_on_cpu(_cpu_id);
            if (took)
              {
                Irq *ret = *it;
                _owned_pend_irqs.erase(it);
                if (ret->is_pending_and_enabled())
                  queue_and_notify(ret);
                return ret;
              }
            else if (took.drop())
              {
                Irq *removed = *it;
                it = _owned_pend_irqs.erase(it);
                if (removed->is_pending_and_enabled())
                  rescan = queue_and_notify(removed) || rescan;
              }
            else
              ++it;
          }
      }
    while (rescan);

    return nullptr;
  }


  /**
   * Set a GICv2 SGI for this CPU pending
   * \pre `irq` < 16.
   */
  bool set_sgi(unsigned irq);

  /**
   * Clear a pending GICv2 SGI from `src` on this CPU.
   * \pre `irq` < 16.
   */
  void clear_sgi(unsigned irq, unsigned src);

  /**
   * Dump GICv2 SGI state.
   */
  void dump_sgis() const;

  /// read GICV_HCR / ICH_HCR_EL2
  Vmm::Arm::Gic_h::Hcr hcr() const
  {
    using Vmm::Arm::Gic_h::Hcr;
    return Hcr(l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_HCR));
  }

  /// write GICV_HCR / ICH_HCR_EL2
  void write_hcr(Vmm::Arm::Gic_h::Hcr hcr) const
  { l4_vcpu_e_write_32(*_vcpu, L4_VCPU_E_GIC_HCR, hcr.raw); }

  /// read GICV_MISR / ICH_MISR_EL2
  Vmm::Arm::Gic_h::Misr misr() const
  {
    using Vmm::Arm::Gic_h::Misr;
    return Misr(l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_MISR));
  }

  /// read GICH_VTR / ICH_VTR_EL2
  Vmm::Arm::Gic_h::Vtr vtr() const
  {
    using Vmm::Arm::Gic_h::Vtr;
    return Vtr(l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_VTR));
  }

  /**
   * Get the affinity from the vCPU MPIDR.
   * \pre the CPU interface must be initialized (see initialize()).
   */
  l4_uint32_t affinity() const
  {
    l4_uint64_t mpidr = l4_vcpu_e_read(*_vcpu, L4_VCPU_E_VMPIDR);
    return (mpidr & 0x00ffffff) | ((mpidr >> 8) & 0xff000000);
  }

private:
  /// GICv2 SGI pending registers
  l4_uint32_t _sgi_pend[4]; // 4 * 4 == 16 SGIs a 8 bits

  /// SGI and PPI IRQ array
  Irq_array _local_irq;

  /// SPI IRQ array from distributor
  Irq_array *_spis;

  /// The associated vCPU
  Vmm::Vcpu_ptr _vcpu = Vmm::Vcpu_ptr(nullptr);

  void _set_elsr(l4_uint32_t bits) const
  {
    unsigned id = L4_VCPU_E_GIC_ELSR;
    l4_uint32_t e = l4_vcpu_e_read_32(*_vcpu, id);
    l4_vcpu_e_write_32(*_vcpu, id, e | bits);
  }

  void _clear_elsr(l4_uint32_t bits) const
  {
    unsigned id = L4_VCPU_E_GIC_ELSR;
    l4_uint32_t e = l4_vcpu_e_read_32(*_vcpu, id);
    l4_vcpu_e_write_32(*_vcpu, id, e & ~bits);
  }

  bool queue_and_notify(Irq *irq)
  {
    Vcpu_handler *cpu = irq->vcpu_handler();
    cpu->queue(irq);
    if (cpu == this)
      return true;

    cpu->notify_irq();
    return false;
  }
};

inline void
Cpu::write_set_sgi_pend(unsigned reg, l4_uint32_t value)
{
  l4_uint32_t o = _sgi_pend[reg];
  l4_uint32_t n = o | value;
  if (o == n)
    return;

  _sgi_pend[reg] = n;

  for (unsigned i = 0; i < 4; ++i)
    {
      if ((o ^ n) & 0xff)
        local_irq(i + (reg * 4)).pending(true);

      o >>= 8;
      n >>= 8;
    }
}

inline void
Cpu::write_clear_sgi_pend(unsigned reg, l4_uint32_t value)
{
  l4_uint32_t o = _sgi_pend[reg];
  l4_uint32_t n = o & ~value;
  if (o == n)
    return;

  _sgi_pend[reg] = n;
  for (unsigned i = 0; i < 4; ++i)
    {
      if ((o ^ n) & 0xff)
        local_irq(i + (reg * 4)).pending(false);

      o >>= 8;
      n >>= 8;
    }
}

template<typename CPU_IF>
inline void
Cpu::handle_eois()
{
  using Lr = typename CPU_IF::Lr;
  using namespace Vmm::Arm;
  Gic_h::Misr misr(l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_MISR));

  if (!misr.eoi())
    return;

  l4_uint32_t eisr = l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_EISR);
  if (!eisr)
    return;

  for (unsigned i = 0; i < Num_lrs; ++i, eisr >>= 1)
    {
      if (!(eisr & 1))
        continue;

      Lr lr = CPU_IF::read_lr(_vcpu, i);
      Irq &c = irq_from_intid(lr.vid());
      assert(lr.state() == Lr::Empty);

      c.clear_lr();
      c.eoi();
      CPU_IF::write_lr(_vcpu, i, Lr(0));
      _set_elsr(1U << i);
    }

  // all EOIs are handled
  l4_vcpu_e_write_32(*_vcpu, L4_VCPU_E_GIC_EISR, 0);
  misr.eoi() = 0;
  l4_vcpu_e_write_32(*_vcpu, L4_VCPU_E_GIC_MISR, misr.raw);
}

template<typename CPU_IF>
inline void
Cpu::add_pending_irq(unsigned lr, Irq &irq, unsigned src_cpu)
{
  using Lr = typename CPU_IF::Lr;
  Lr new_lr(0);
  new_lr.state() = Lr::Pending;
  new_lr.eoi()   = 1; // need an EOI IRQ
  new_lr.vid()   = irq.id();
  new_lr.set_cpuid(src_cpu);
  new_lr.prio()  = irq.prio();
  new_lr.grp1()  = irq.group();

  // uses 0 for "no link register assigned" (see #get_empty_lr())
  irq.set_lr(lr + 1);
  CPU_IF::write_lr(_vcpu, lr, new_lr);
  _clear_elsr(1U << lr);
}

template<typename CPU_IF>
inline bool
Cpu::inject(Irq &irq, unsigned src_cpu)
{
  // free LRs if there are inactive LRs
  handle_eois<CPU_IF>();

  unsigned lr_idx = get_empty_lr();
  if (!lr_idx)
    return false;

  if (!irq.take_on_cpu(_cpu_id))
    return false;

  add_pending_irq<CPU_IF>(lr_idx - 1, irq, src_cpu);
  return true;
}

class Cpu_vector
{
private:
  using Cpu_ptr = cxx::unique_ptr<Cpu>;

  cxx::unique_ptr<Cpu_ptr[]> _cpu;
  unsigned _n = 0;
  unsigned _c = 0;

public:
  using Irq = Cpu::Irq;
  using Const_irq = Cpu::Const_irq;

  explicit Cpu_vector(unsigned capacity)
  : _cpu(cxx::make_unique<Cpu_ptr[]>(capacity)),
    _c(capacity)
  {}

  unsigned capacity() const { return _c; }
  unsigned size() const { return _n; }
  Cpu_ptr const *begin() const { return &_cpu[0]; }
  Cpu_ptr const *end() const { return &_cpu[_n]; }
  Cpu_ptr const &operator [] (unsigned idx) const { return _cpu[idx]; }

  bool set_at(unsigned idx, Cpu_ptr &&cpu)
  {
    if (idx >= capacity())
      return false;

    if ((idx + 1) > _n)
      _n = idx + 1;

    _cpu[idx] = cxx::move(cpu);
    return true;
  }
};


template<bool AFF_ROUTING>
class Dist
: public Dist_if,
  public Ic,
  public Monitor::Gic_cmd_handler<Monitor::Enabled, Dist<AFF_ROUTING>>
{
  friend Monitor::Gic_cmd_handler<Monitor::Enabled, Dist<AFF_ROUTING>>;

protected:
  Dbg gicd_trace;

public:
  using Irq = Cpu::Irq;
  using Const_irq = Cpu::Const_irq;

  enum { Num_local = 32 };

  enum Regs
  {
    CTLR  = 0x000,
    TYPER = 0x004, // RO
    IIDR  = 0x008, // RO
    SGIR  = 0xf00, // WO
  };

  l4_uint32_t ctlr;
  unsigned char tnlines;

  Dist(unsigned tnlines, unsigned max_cpus)
  : gicd_trace(Dbg::Irq, Dbg::Trace, "GICD"), ctlr(0), tnlines(tnlines),
    _cpu(max_cpus),
    _spis(tnlines * 32, Num_local)
  {
  }

  Irq &spi(unsigned spi)
  {
    assert (spi < _spis.size());
    return _spis[spi];
  }

  Const_irq &spi(unsigned spi) const
  {
    assert (spi < _spis.size());
    return _spis[spi];
  }

  /// \group Implementation of Ic functions
  /// \{
  void clear(unsigned) override {}

  void bind_eoi_handler(unsigned irq, Eoi_handler *handler) override
  {
    Irq &pin = spi(irq - Cpu::Num_local);

    if (handler && pin.get_eoi_handler())
      L4Re::chksys(-L4_EEXIST, "Assigning EOI handler to GIC");

    pin.set_eoi(handler);
  }

  Eoi_handler *get_eoi_handler(unsigned irq) const override
  { return spi(irq - Cpu::Num_local).get_eoi_handler(); }

  int dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const override
  {
    enum Irq_types
    {
      Irq_ppi_base = 16,
      Irq_ppi_max = 16,
      Irq_spi_base = 32,
    };

    enum Dts_interrupt_cells
    {
      Irq_cell_type = 0,
      Irq_cell_number = 1,
      Irq_cell_flags = 2,
      Irq_cells = 3
    };

    if (propsz < Irq_cells)
      return -L4_ERANGE;

    int irqnr = fdt32_to_cpu(prop[Irq_cell_number]);

    if (fdt32_to_cpu(prop[Irq_cell_type]) == 0)
      irqnr += Irq_spi_base;
    else
      {
        if (irqnr >= Irq_ppi_max)
          L4Re::chksys(-L4_EINVAL, "Only 16 PPI interrupts allowed");

        irqnr += Irq_ppi_base;
      }

    if (read)
      *read = Irq_cells;

    return irqnr;
  }
  /// \} end of Ic implementation

  /// \group abstract GIC interface for different GIC versions
  /// \{

  /// Setup the CPU interface for the given `vcpu` running on `thread`.
  Cpu *add_cpu(Vmm::Vcpu_ptr vcpu)
  {
    unsigned cpu = vcpu.get_vcpu_id();
    if (cpu >= _cpu.capacity())
      return nullptr;

    gicd_trace.printf("set CPU interface for CPU %02d (%p) to %p\n",
                      cpu, &_cpu[cpu], *vcpu);
    _cpu.set_at(cpu, cxx::make_unique<Cpu>(vcpu, &_spis));
    Cpu *ret = _cpu[cpu].get();
    if (cpu == 0)
      {
        _prio_mask = ~((1U << (7 - ret->vtr().pri_bits())) - 1U);

        // By default all SPIs are bound to the boot CPU even if they initially
        // target no CPU on GICv2.
        for (unsigned i = 0; i < _spis.size(); i++)
          _spis[i].target(0, ret);
      }

    ret->offline(_cpu[0]->vcpu());

    return ret;
  }

  /// write to the GICD_CTLR.
  virtual void write_ctlr(l4_uint32_t val)
  {
    ctlr = val;
  }

  /// read to the GICD_TYPER.
  virtual l4_uint32_t get_typer() const
  {
    return tnlines | ((l4_uint32_t)(_cpu.size() - 1) << 5);
  }

  /// read to the CoreSight IIDRs.
  virtual l4_uint32_t iidr_read(unsigned offset) const = 0;
  /// \}

  void update_gicc_state(Vmm::Arm::Gic_h::Misr, unsigned)
  {}

protected:
  Cpu *cpu(unsigned id)
  {
    if (id >= _cpu.capacity())
      return nullptr;
    else
      return _cpu[id].get();
  }

  /**
   * Check targets of SPIs and possibly divert them to a different vCPU.
   *
   * When affinity routing is not used the target vCPU of a SPI might change
   * if the set of online vCPUs changes.
   */
  void retarget_spis()
  {
    if (AFF_ROUTING)
      return;

    std::lock_guard<std::mutex> lock(_target_lock);
    for (unsigned i = 0; i < _spis.size(); i++)
      {
        Irq &irq = _spis[i];
        unsigned char vcpu = tgt2cpu(irq.target());
        if (vcpu != irq.cpu())
          irq.target(irq.target(), cpu(vcpu));
      }
  }

private:
  /**
   * Get the first usable vCPU number from the given target mask.
   *
   * Might be Irq::Invalid_cpu if the irq targets no CPU or only offline CPUs.
   */
  unsigned char tgt2cpu(unsigned char tgt)
  {
    while (tgt)
      {
        unsigned first = __builtin_ffs(tgt) - 1;
        if (first >= _cpu.capacity())
          return Irq::Invalid_cpu;

        Vcpu_handler *cpu = _cpu[first].get();
        if (cpu && cpu->online())
          return first;

        tgt &= ~(1U << first);
      }

    return Irq::Invalid_cpu;
  }

  /// \group Per IRQ register interfaces
  /// \{
  enum Reg_group_idx
  {
    R_group = 0,
    R_isenable,
    R_icenable,
    R_ispend,
    R_icpend,
    R_isactive,
    R_icactive,
    R_prio,
    R_target,
    R_cfg,
    R_grpmod,
    R_nsacr,
    R_route
  };

  l4_uint32_t irq_mmio_read(Const_irq const &irq, unsigned rgroup)
  {
    switch (rgroup)
      {
      case R_group:    return irq.group();
      case R_isenable:
      case R_icenable: return irq.enabled();
      case R_ispend:
      case R_icpend:   return irq.pending();
      case R_isactive:
      case R_icactive: return irq.active();
      case R_prio:     return irq.prio();
      case R_target:   return AFF_ROUTING ? 0 : irq.target();
      case R_cfg:      return irq.config();
      case R_grpmod:   return 0;
      case R_nsacr:    return 0;
      default:         assert (false); return 0;
      }
  }

  void irq_mmio_write(Irq &irq, unsigned rgroup, l4_uint32_t value)
  {
    switch (rgroup)
      {
      case R_group:    irq.group(value);               return;
      case R_isenable:
        if (value)
          {
            Vcpu_handler *dest_cpu = irq.enable(true);
            if (dest_cpu)
              dest_cpu->notify_irq();
          }
          return;
      case R_icenable: if (value) irq.enable(false);   return;
      case R_ispend:
        if (value)
          {
            Vcpu_handler *dest_cpu = irq.pending(true);
            if (dest_cpu)
              dest_cpu->notify_irq();
          }
          return;
      case R_icpend:   if (value) irq.pending(false);  return;
      case R_isactive: if (value) irq.active(true);    return;
      case R_icactive: if (value) irq.active(false);   return;
      case R_prio:     irq.prio(value & _prio_mask);   return;
      case R_target:
        if (!AFF_ROUTING && irq.id() >= Cpu::Num_local)
          {
            std::lock_guard<std::mutex> lock(_target_lock);
            irq.target(value, cpu(tgt2cpu(value)));
          }
        return;
      case R_cfg:      irq.config(value);              return;
      case R_grpmod:   /* GICD_CTRL.DS=1 -> RAZ/WI */  return;
      case R_nsacr:    /* GICD_CTRL.DS=1 -> RAZ/WI */  return;
      default:         assert (false);                 return;
      }
  }
  /// \} end of per IRQ registers

  /**
   * Helper to demux multiple IRQs-per register accesses.
   * \note Local IRQs vs SPIs must be resolved already.
   */
  template<unsigned SHIFT, typename OP>
  void _demux_irq_reg(Irq_array &irqs,
                      unsigned s, unsigned n,
                      unsigned reg, OP &&op)
  {
    unsigned const rshift = 8 >> SHIFT;
    l4_uint32_t const mask = 0xff >> (8 - rshift);
    for (unsigned x = 0; x < n; ++x)
      {
        unsigned const i = x + s;
        op(irqs[i], reg, mask, rshift * x);
      }
  }

  /**
   * Helper to demux multiple IRQs-per register accesses.
   * \note Local IRQs vs SPIs must be resolved already.
   */
  template<unsigned SHIFT, typename OP>
  void _demux_irq_reg(unsigned reg, unsigned offset,
                      unsigned size,
                      unsigned cpu_id, OP &&op)
  {
    unsigned const irq_s = (offset & (~0U) << size) << SHIFT;
    unsigned const nirq = (1 << size) << SHIFT;

    if (irq_s < Num_local)
      _demux_irq_reg<SHIFT>(_cpu[cpu_id]->local_irqs(), irq_s, nirq, reg, op);
    else if (irq_s - Num_local < _spis.size())
      _demux_irq_reg<SHIFT>(_spis, irq_s - Num_local, nirq, reg, op);
  }

  /**
   * Helper to demux a complete range of multi IRQ registers with
   * equal number of IRQs per register (given by SHIFT).
   * \pre `reg` >= `START`
   * \retval false if `reg` >= END
   * \retval true if `reg` < END;
   */
  template<unsigned BLK, unsigned START, unsigned END,
           unsigned SHIFT, typename OP>
  bool _demux_irq_block(unsigned reg, unsigned size, unsigned cpu_id, OP &&op)
  {
    unsigned const rsh = 10 - SHIFT;
    static_assert((START & ((1U << rsh) - 1)) == 0U, "low bits of START zero");
    static_assert((END   & ((1U << rsh) - 1)) == 0U, "low bits of END zero");
    if (reg < END)
      {
        unsigned const x = reg >> rsh;
        _demux_irq_reg<SHIFT>(x - (START >> rsh) + BLK,
                              reg & ~((~0U) << rsh), size, cpu_id, op);
        return true;
      }
    return false;
  }

  /**
   * Demux the access to the whole multi-IRQ register range of the
   * GIC distributor.
   */
  template<typename OP>
  bool _demux_per_irq(unsigned reg, unsigned size, unsigned cpu_id, OP &&op)
  {
    if (reg < 0x80)
      return false;

    if (_demux_irq_block<R_group, 0x80, 0x400, 3>(reg, size, cpu_id, op))
      return true;

    if (_demux_irq_block<R_prio, 0x400, 0xc00, 0>(reg, size, cpu_id, op))
      return true;

    if (_demux_irq_block<R_cfg,  0xc00, 0xe00, 2>(reg, size, cpu_id, op))
      return true;

    if (_demux_irq_block<R_grpmod, 0xd00, 0xd80, 3>(reg, size, cpu_id, op))
      return true;

    if (_demux_irq_block<R_nsacr, 0xe00, 0xf00, 2>(reg, size, cpu_id, op))
      return true;

    return false;
  }

  /**
   * Helper to access the IIDR register range of CoreSight GICs
   * This helper forwards to the iidr_read interface.
   * \retval true if `reg` is in the IIDR range of the device.
   * \retval false otherwise
   */
  bool _iidr_try_read(unsigned reg, char size, l4_uint64_t *val)
  {
    if (size == 2 && reg >= 0xffd0 && reg <= 0xfffc)
      {
        *val = iidr_read(reg - 0xffd0);
        return true;
      }

    return false;
  }

  /**
   * Helper for reads in the GICD header area 0x00 - 0x10
   */
  l4_uint32_t _read_gicd_header(unsigned reg)
  {
    unsigned r = reg >> 2;
    switch (r)
      {
      case 0: return ctlr;        // GICD_CTRL
      case 1: return get_typer(); // GICD_TYPER
      case 2: return 0x43b;       // GICD_IIDR
      default: break;             // includes GICD_TYPER2
      }
    return 0;
  }

protected:

  /**
   * Read a register in the multi IRQs register range of GICD.
   * \retval true  if `reg` is handled by the function.
   * \retval false otherwise.
   */
  bool
  read_multi_irq(unsigned reg, char size, unsigned cpu_id, l4_uint64_t *res)
  {
    auto rd = [this,res](Const_irq const &irq, unsigned r, l4_uint32_t mask,
                        unsigned shift)
      {
        *res |= (this->irq_mmio_read(irq, r) & mask) << shift;
      };

    return _demux_per_irq(reg, size, cpu_id, rd);
  }

  /**
   * Write a register in the multi IRQs register range of GICD.
   * \retval true  if `reg` is handled by the function.
   * \retval false otherwise.
   */
  bool
  write_multi_irq(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
  {
    auto wr = [this,value](Irq &irq, unsigned r, l4_uint32_t mask,
                           unsigned shift)
      {
        this->irq_mmio_write(irq, r, (value >> shift) & mask);
      };

    return _demux_per_irq(reg, size, cpu_id, wr);
  }

  /**
   * Read for generic GICD registers.
   *
   * \retval true  if `reg` is handled by the function.
   * \retval false otherwise.
   *
   * This function is a helper for specific GICD mmio read implementations.
   */
  bool dist_read(unsigned reg, char size, unsigned cpu_id, l4_uint64_t *res)
  {
    if (reg < 0x10) // GICD_CTRL..GICD_TYPER2
      {
        *res = _read_gicd_header(reg);
        return true;
      }

    if (reg == 0x10) // GICD_STATUS
      {
        *res = 0;
        return true;
      }

    if (reg < 0x80) // < GICD_IGROUPR
      return true;

    if (read_multi_irq(reg, size, cpu_id, res))
      return true;

    return _iidr_try_read(reg, size, res);
  }

  /**
   * Write for generic GICD registers.
   *
   * \retval true  if `reg` is handled by the function.
   * \retval false otherwise.
   *
   * This function is a helper for specific GICD mmio write implementations.
   */
  bool dist_write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
  {
    if (reg == 0 && size == 2)
      {
        write_ctlr(value);
        return true;
      }

    if (reg < 0x80) // < GICD_IGROUPR
      return true; // all RO, WI, WO or not implemented

    return write_multi_irq(reg, size, value, cpu_id);
  }

protected:
  Cpu_vector _cpu;
  Irq_array _spis;
  l4_uint8_t _prio_mask;
  std::mutex _target_lock;
};

template<typename GIC_IMPL>
void
Cpu::handle_ipis()
{
  if (!GIC_IMPL::sgi_pend_regs())
    return;

  using Cpu_if = typename GIC_IMPL::Cpu_if;

  for (unsigned irq_num = 0; irq_num < 16; ++irq_num)
    {
      using Ma = Vmm::Mem_access;
      unsigned char const cpu_bits
        = Ma::read(_sgi_pend[irq_num / 4], irq_num, Ma::Wd8);

      if (!cpu_bits)
        continue;

      // inject one IPI, if another CPU posted the same IPI we keep it
      // pending
      unsigned src = __builtin_ffs((int)cpu_bits) - 1;
      Irq &irq = local_irq(irq_num);

      // set irq pending and try to inject
      if (irq.pending(true))
        {
          if (!inject<Cpu_if>(irq, src))
            {
              // Can happen if no LR was free. Will try again on next guest
              // entry before other iterrupts are injected.
              irq.pending(false);
              return;
            }
          clear_sgi(irq_num, src);
        }
    }
}

}

