/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once
#include "event_record.h"
#include "vm_state.h"
#include "debug.h"

#include <l4/re/error_helper>
#include <l4/cxx/bitmap>
#include <l4/cxx/minmax>
#include <vector>
#include <queue>
#include <cassert>


namespace Vmm {

/// Recorder of all events for a core.
class Event_recorder
{
public:
  ~Event_recorder() { clear(); }

  /**
   * Inject highest priority event.
   *
   * \retval true   Event injected.
   * \retval false  No event to inject or can't inject pending event.
   */
  bool inject(Vm_state *vms);

  /**
   * Record an event.
   *
   * \note Pending interrupts are recorded as placeholder item such that the
   *       caller knows the query the local APIC. NMI and IRQs are just
   *       recorded once.
   *
   * \post Ownership moves to `Event_recorder`.
   */
  void add(Event_record *event);

  /// Clears all recorded events.
  void clear();
  /// True, iff no event recorded.
  bool empty() const;
  /// FIXME for MSR interface lacking return value tristate.
  bool has_exception() const { return _has_exception; }
  /// true, iff IRQ event already recorded
  bool has_nmi() const { return _has_nmi; }
  /// true, iff IRQ event already recorded
  bool has_irq() const { return _has_irq; }

  /// debugging aid
  void dump(unsigned vcpu_id) const;

  /// Create an Event instance and record it.
  template <typename T, typename... ARGS>
  void make_add_event(ARGS... args)
  {
    add(allocate_event<T, ARGS...>(args...));
  }

private:
  static Dbg warn() { return Dbg(Dbg::Core, Dbg::Warn, "Event recorder"); }

  /**
   * Allocate memory for an object of type `T`.
   *
   * \tparam T  Type derived from `Event_record`.
   *
   */
  template <typename T, typename... ARGS>
  Event_record *allocate_event(ARGS... args)
  {
    static bool warn_once = true;
    char *addr = _memory.alloc(sizeof(T));
    if (addr)
      return new (addr) T(std::forward<ARGS>(args)...);
    else
      {
        // Print message once, if dynamic allocation is necessary on any core.
        if (warn_once)
          {
            warn_once = false;
            warn().printf("Usage of the slow path for event allocation. Memory "
                          "preallocation exceeded for the first time.");
          }
        return new T(std::forward<ARGS>(args)...);
      }
  }

  /**
   * Destruct object derived from `Event_record` and free the memory.
   *
   * \param object  Address of the object to destruct and free.
   */
  void free_event(Event_record *object)
  {
    if (_memory.in_memory(reinterpret_cast<char *>(object)))
      {
        object->~Event_record();
        _memory.free(reinterpret_cast<char *>(object));
      }
    else
      delete object;
  }

  /**
   * Encapsulate all memory management for Event_records within this class.
   *
   * We want to avoid dynamic memory allocation during VM exit handling and
   * thus preallocate the memory and create events within this memory range.
   * The memory is split into chunks that fit all Event_records object sizes
   * and returns one such chunk on request.
   *
   * It's an open question how to handle OOM situations.
   */
  class Event_memory
  {
    struct Bin_if
    {
      virtual ~Bin_if() = default;
      virtual char *alloc() = 0;
      virtual bool free(char *) = 0;
      virtual bool managed_addr(char *addr) const = 0;
    };

    template <unsigned BIN_SIZE, unsigned SLOTS>
    struct Bin : Bin_if
    {
      Bin() { slot_used.clear_all(); }

      ~Bin() = default;

      char *alloc() noexcept override
      {
        int free_idx = slot_used.scan_zero(0);
        if (free_idx >= 0)
          {
            slot_used[free_idx] = true;
            return mem + free_idx * BIN_SIZE;
          }

        warn().printf("no space in bin left to allocate. Bin addr %p, num bins "
                     "%u, bin size %u\n",
                     &mem, SLOTS, BIN_SIZE);
        return nullptr;
      }

      bool free(char *addr) noexcept override
      {
        unsigned bin_idx = (addr - mem) / BIN_SIZE;
        assert(slot_used[bin_idx] == true);

        slot_used[bin_idx] = false;
        return true;
      }

      bool managed_addr(char * addr) const noexcept override
      {
        if (addr < mem || addr >= mem + MEM_SIZE)
          {
            info().printf("Address %p not in bin-managed range[%p, %p]. Bin "
                          "size: 0x%x\n",
                          addr, mem, mem + MEM_SIZE, BIN_SIZE);
            return false;
          }

        return true;
      }

      static unsigned constexpr MEM_SIZE = BIN_SIZE * SLOTS;
      cxx::Bitmap<SLOTS> slot_used;
      char mem[MEM_SIZE];
    };

    /**
     * Compute maximum object size of all events.
     *
     * This depends on static_asserts for Event_nmi & Event_irq.
     */
    static unsigned constexpr max_event_size()
    {
      // Event types: Event_exc, Real_mode_exc, Event_sw_generic, Event_nmi,
      // Event_irq

      unsigned constexpr size =
        cxx::max(sizeof(Event_exc), sizeof(Real_mode_exc),
                 sizeof(Event_sw_generic<0>));

      // round to next power of two to fit to cache lines.
      return next_pow2(size);
    }

    /**
     * Compute the next larger value which is a power of two.
     *
     * \param num  Number to start from.
     */
    static unsigned constexpr next_pow2(unsigned num)
    {
      static_assert(sizeof(unsigned) <= 4,
                    "Next power of 2 algorithm only supports 32-bit numbers.");

      if (num == 0U)
        return 1;

      --num;
      num |= num >> 1;
      num |= num >> 2;
      num |= num >> 4;
      num |= num >> 8;
      num |= num >> 16;

      return ++num;
    }

  public:
    Event_memory()
    {
      // instead of one preallocated bin per event size, we simplify and
      // use one bin for all events and accept the additional temporary memory
      // usage within a bin. Only the bin size affects the total memory usage.
      unsigned constexpr size = max_event_size();
      _bin = new Bin<size, 32>();
    }

    ~Event_memory()
    {
      if (_bin)
        delete _bin;
    }

    char *alloc(l4_size_t /* size */)
    {
      char *addr = _bin->alloc();
      return addr;
    }

    // pre: in_memory(addr) == true
    void free(char *addr)
    {
      assert(in_memory(addr));

      _bin->free(addr);
    }

    bool in_memory(char *addr)
    {
      return _bin->managed_addr(addr);
    }

  private:
    static Dbg warn() { return Dbg(Dbg::Core, Dbg::Warn, "Event memory"); }
    static Dbg info() { return Dbg(Dbg::Core, Dbg::Info, "Event memory"); }

    Bin_if *_bin;
  }; // class Event_memory

  using Qtype = Event_record *;

  struct QGreater
  {
    bool operator()(Qtype const &item1, Qtype const &item2) const
    { return *item1 > *item2; }
  };

  std::priority_queue<Qtype, std::vector<Qtype>, QGreater> _queue;
  Event_memory _memory;
  bool _has_exception = false;
  bool _has_nmi = false;
  bool _has_irq = false;
};

/// Interface to get the event recorder for a specific core.
struct Event_recorders
{
  virtual Event_recorder *recorder(unsigned num) = 0;
};

/**
 * Management entity for one `Event_recorder` per core.
 */
class Event_recorder_array : public Event_recorders
{
public:
  virtual ~Event_recorder_array() = default;

  void init(unsigned size)
  { _recorders.resize(size); }

  Event_recorder *recorder(unsigned num) override
  {
    assert(num < _recorders.size());
    return &_recorders[num];
  }

private:
  std::vector<Event_recorder> _recorders;
};

} // namespace Vmm
