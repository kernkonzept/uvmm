/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <type_traits>
#include <vector>

#include <l4/cxx/bitmap>
#include <l4/cxx/unique_ptr>

#include "cpu_dev_array.h"
#include "irq.h"
#include "mmio_device.h"
#include "vcpu_ic.h"

namespace Gic {

/**
 * The platform-level interrupt controller (PLIC) distributes external
 * interrupts asserted by peripheral devices to the CPUs in the system.
 *
 * This class emulates a virtual PLIC for the guest that supports all the
 * features mandated by the RISC-V specification, such as claiming and
 * acknowledging interrupts, prioritizing interrupt sources or disabling
 * certain interrupts on certain vCPUs. The virtual PLIC toggles the external
 * interrupt of a vCPU via the corresponding Vcpu_ic, thereby signaling that
 * external interrupts are pending in the PLIC.
 */
class Plic
: public Vmm::Mmio_device_t<Plic>,
  public Ic
{
public:
  enum Config
  {
    /// Configures the maximum number of interrupts the PLIC implements.
    Num_irqs = 32,
  };
  static_assert(Num_irqs % 32 == 0, "Number of IRQs must be a multiple of 32.");

  explicit Plic(Vdev::Dt_node const &node, unsigned num_dt_interrupt_targets);

  /**
   * Setup PLIC state for the given vCPU.
   */
  void setup_target(Vmm::Vcpu_ptr vcpu, cxx::Ref_ptr<Vcpu_ic> vcpu_ic);

  /**
   * Read memory-mapped register.
   *
   * \param reg     Register offset.
   * \param size    Access size.
   * \param cpu_id  The ID of the vCPU making the read.
   *
   * \return  Value read from the register.
   */
  l4_umword_t read(unsigned reg, char size, unsigned cpu_id);

  /**
   * Write memory-mapped register.
   *
   * \param reg     Register offset.
   * \param size    Access size.
   * \param value   Value to write.
   * \param cpu_id  The ID of the vCPU making the write.
   */
  void write(unsigned reg, char size, l4_umword_t value, unsigned cpu_id);

  // The following functions implement the Ic interface.
  void set(unsigned irq) override;
  void clear(unsigned irq) override;
  void bind_irq_src_handler(unsigned irq, Irq_src_handler *handler) override;
  Irq_src_handler *get_irq_src_handler(unsigned irq) const override;
  int dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const override;

  char const *dev_name() const override { return "Plic"; }

private:
  /**
   * Thread-safe gateway for an interrupt source connected to the PLIC. The
   * gateway manages the state changes that an interrupt may undergo.
   *
   * The gateway ensures that an interrupt can only be triggered again
   * when the previous interrupt has been completed. Furthermore, it ensures
   * that once an interrupt has been forwarded, it can no longer be retracted.
   */
  class Irq_gateway
  {
  public:
    /**
     * Set interrupt as pending.
     *
     * \return True if interrupt was not already in pending or claimed state.
     */
    bool set()
    {
      l4_uint8_t prev = _state.fetch_or(State_pending);
      return !(prev & (State_pending | State_claimed));
    };

    /**
     * Claim interrupt.
     *
     * \return True if interrupt was successfully claimed.
     */
    bool claim()
    {
      l4_uint8_t expected = State_pending;
      return _state.compare_exchange_strong(expected, State_claimed);
    }

    /**
     * Complete interrupt.
     *
     * \return True if interrupt is again pending.
     */
    bool complete()
    {
      l4_uint8_t prev = _state.fetch_and(~State_claimed);
      return prev & State_pending;
    };

  private:
    /**
     * Possible state changes:
     *
     * NONE            -- set()      -> Pending
     * Pending         -- claim()    -> Claimed
     * Claimed         -- set()      -> Claimed_Pending
     * Claimed         -- complete() -> NONE
     * Claimed_Pending -- complete() -> Pending
     */
    enum : l4_uint8_t
    {
      // Pending state of interrupt.
      State_pending     = 1 << 0,
      // Pending interrupt was claimed by CPU and is currently handled.
      State_claimed     = 1 << 1,
    };

    std::atomic<l4_uint8_t> _state = 0;
  };

  /**
   * Bitmap sized to provide a bit for each interrupt implemented by the PLIC.
   */
  class Per_irq_bitmap : public cxx::Bitmap_base
  {
  public:
    Per_irq_bitmap() throw() : Bitmap_base(_words) {}

    static unsigned words()
    {
      return Bitmap_base::words(Num_irqs);
    }

    static constexpr unsigned Word32_size = sizeof(l4_uint32_t);

    static_assert(   sizeof(Bitmap_base::word_type) == Word32_size
                  || sizeof(Bitmap_base::word_type) == (Word32_size * 2));

    void set_word32(unsigned index, l4_uint32_t word)
    {
      if constexpr (sizeof(Bitmap_base::word_type) == Word32_size)
        _words[index] = word;

      unsigned word32_shift = (index & 1) ? Word32_size : 0;
      auto mask32 = ~(Bitmap_base::word_type{0xffff'ffff} << word32_shift);
      _words[index / 2] = (_words[index / 2] & mask32) | (word << word32_shift);
    }

    l4_uint32_t word32(unsigned index) const
    {
      if constexpr (sizeof(Bitmap_base::word_type) == Word32_size)
        return _words[index];

      unsigned word32_shift = (index & 1) ? Word32_size : 0;
      return _words[index / 2] >> word32_shift;
    }

    /**
     * Optional return value to control callback-driven loops.
     */
    enum Cb
    {
      Break,
      Continue,
    };

    template<typename F, typename... Args>
    inline static Cb invoke_cb(F f, Args... args)
    {
      if constexpr (std::is_void_v<std::result_of_t<F(Args...)>>)
        {
          f(args...);
          return Continue;
        }
      else
        return f(args...);
    }

    /**
     * Iterate over all set bits in the intersection of the given bitmaps.
     *
     * \param f        Callback to invoke for each set bit.
     * \param bitmaps  The bitmaps to work on.
     */
    template<typename F, typename... Bitmaps>
    inline static void for_set_bits(F f, Bitmaps const &... bitmaps)
    {
      for (unsigned word_index = 0; word_index < words(); word_index++)
        {
          l4_uint32_t cur_word = (bitmaps._words[word_index] & ...);
          if (!cur_word)
            // Skip empty words.
            continue;

          for (unsigned i = 0; i < W_bits; i++)
            {
              l4_uint32_t bit = cur_word & (1UL << i);
              if (bit && invoke_cb(f, word_index * W_bits + i) == Break)
                // Stop iteration of set bits
                return;
            }
        }
    }

  private:
    Bitmap_base::word_type _words[Bitmap_base::Word<Num_irqs>::Size] = {};
  };

  /**
   * This class holds per vCPU PLIC state and implements signaling, claiming
   * and completion of interrupts.
   *
   * The flow of an interrupt is as follows:
   * 1. Interrupt is marked pending via `set()`.
   * 2. Pending interrupt is claimed by a vCPU via `claim()`.
   * 3. vCPU handles the interrupt and once finished completes it via `complete()`.
   *    Note: In between steps 2 and 3, the interrupt might have been `set()`
   *          again, in which case `complete()` immediately transitions it into
   *          Pending state again.
   *
   * \note For calling any of the functions on this class, except `vcpu()`, the
   *       PLIC lock must be held.
   */
  class Plic_target
  {
  public:
    Plic_target(Plic *plic, Vmm::Vcpu_ptr vcpu, cxx::Ref_ptr<Vcpu_ic> vcpu_ic);

    Vmm::Vcpu_ptr vcpu() const
    {
      return _vcpu;
    }

    /**
     * Write register in enable register array.
     *
     * Also reevaluates the external interrupt pending bit of the vCPU this
     * Plic_target belongs to.
     *
     * \param offset        Offset of the register, must be `<= Num_irqs / 32`.
     * \param value         The value to write to the register.
     * \param current_vcpu  The current vCPU.
     */
    void enable(l4_uint32_t offset, l4_uint32_t value, Vmm::Vcpu_ptr current_vcpu);

    /**
     * Read register from enable register array.
     *
     * \param offset Offset of the register, must be `<= Num_irqs / 32`.
     *
     * \return  Register value.
     */
    l4_uint32_t enabled(l4_uint32_t offset) const;

    /**
     * Claim the pending interrupt with highest priority if any.
     *
     * On success, also reevaluates the external interrupt pending bit of the
     * vCPU this Plic_target belongs to.
     *
     * \param current_vcpu  The current vCPU.
     *
     * \return  The claimed interrupt, 0 if non was claimed.
     */
    l4_uint32_t claim(Vmm::Vcpu_ptr current_vcpu);

    /**
     * Complete handling of interrupt.
     *
     * \param irq           The interrupt to complete, must be `< Num_irqs`.
     * \param current_vcpu  The current vCPU.
     */
    void complete(l4_uint32_t irq, Vmm::Vcpu_ptr current_vcpu);

    /**
     * Read the priority threshold.
     *
     * \return Priority threshold.
     */
    l4_uint32_t threshold() const;

    /**
     * Write the priority threshold.
     *
     * Also reevaluates the external interrupt pending bit of the vCPU this
     * Plic_target belongs to.
     *
     * \param threshold     The priority threshold to write.
     * \param current_vcpu  The current vCPU.
     */
    void threshold(l4_uint32_t threshold, Vmm::Vcpu_ptr current_vcpu);

    /**
     * Set the external interrupt pending bit of the vCPU this Plic_target
     * belongs to.
     *
     * \param pending       The new state of the external interrupt.
     * \param current_vcpu  The current vCPU.
     */
    void update_ext_int_pending(bool pending, Vmm::Vcpu_ptr current_vcpu);

    /**
     * Find the pending interrupt with highest priority.
     *
     * Interrupts that are not enabled for this PLIC target or whose priority is
     * below its priority threshold are not considered.
     *
     * \param[out]  best_irq    The pending interrupt with highest priority.
     * \param[out]  nr_pending  Number of interrupts pending for this target.
     *
     * \retval false  No pending interrupt with sufficient priority found.
     * \retval true   Pending interrupt found.
     */
    bool find_best_irq(unsigned &best_irq, unsigned &nr_pending) const;

    /**
     * Check if this PLIC target has pending interrupts with sufficient priority.
     */
    bool pending_irq() const;

    Plic *_plic;                    //< PLIC that this Plic_target is part of
    Vmm::Vcpu_ptr _vcpu;            //< vCPU that this Plic_target belongs to
    cxx::Ref_ptr<Vcpu_ic> _vcpu_ic; //< Interrupt controller of vCPU
    Per_irq_bitmap _enable;         //< Per-IRQ enable state
    l4_uint32_t _threshold;         //< Priority threshold
  };

  enum : unsigned
  {
    Priority_base     = 0x0,
    Pending_base      = 0x1000,

    Enable_base       = 0x2000,
    Enable_per_hart   = 0x80,
    Enable_mask       = 0x7f,

    Context_base      = 0x200000,
    Context_threshold = 0x0,
    Context_claim     = 0x4,
    Context_per_hart  = 0x1000,
    Context_mask      = 0xfff,
  };

  Vmm::Vcpu_ptr get_vcpu(unsigned cpu_id);
  bool check_access(unsigned reg, char size, char const *operation);
  bool check_irq(unsigned irq, char const *operation);
  bool check_irq_range(unsigned offset, char const *operation);
  bool check_target(unsigned target_id);

  Plic_target *get_target(unsigned target)
  {
    return _targets[target].get();
  }

  /**
   * Claim the given interrupt, i.e. update its state accordingly.
   */
  bool claim_irq(unsigned irq);

  /**
   * Set the given interrupt as pending, i.e. update its state accordingly.
   *
   * Also updates the external interrupt pending bit of all targeted vCPUs.
   *
   * \param irq           The interrupt to set pending.
   * \param current_vcpu  The current vCPU.
   */
  void set_irq(unsigned irq, Vmm::Vcpu_ptr current_vcpu);

  // Only used for debugging purposes, to warn if less interrupt targets were
  // referenced in the device tree than there are vCPUs.
  unsigned _num_dt_interrupt_targets;
  unsigned _num_targets_created = 0;

  Irq_gateway _gateways[Num_irqs];                    //< Per-IRQ state machine
  l4_uint32_t _priorities[Num_irqs] = {};             //< Per-IRQ priority
  /// Per-IRQ pending flag, duplicates information stored in Irq_gateway, but
  /// used as an optimization for querying and selecting pending IRQs.
  Per_irq_bitmap _pending;
  Irq_src_handler *_sources[Num_irqs] = {};           //< Per-IRQ source handler
  std::vector<cxx::unique_ptr<Plic_target>> _targets; //< Per-vCPU PLIC state

  std::mutex _lock;
};

}
