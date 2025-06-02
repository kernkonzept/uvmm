/*
 * Copyright (C) 2021-2022,2024, 2023-2024 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
/**
 * Emulation of the PL031 real-time clock device.
 *
 * Based on the ARM PrimeCell Real Time Clock (PL031) Revision: r1p3
 * specification.
 *
 * Configure this device using the following device tree node adapted to your
 * platform needs.
 *
 * \code{.dtb}
 *   virt_pl031 {
 *       compatible = "arm,pl031", "arm,primecell";
 *       reg = <0x13000 0x1000>;
 *       interrupts = <0x00 0x02 0x04>;
 *       clocks = <&apb_dummy_pclk>;
 *       clock-names = "apb_pclk";
 *   };
 * \endcode

 * Linux also wants to have an entry for clocks like this:
 *
 * \code{.dtb}
 *   apb_dummy_pclk: dummy_clk {
 *       compatible = "fixed-clock";
 *       #clock-cells = <0>;
 *       clock-frequency = <1000000>;
 *   };
 * \endcode
 *
 */
#include "debug.h"
#include "device.h"
#include "device_factory.h"
#include "guest.h"
#include "mmio_device.h"
#include "irq_dt.h"

#include "../rtc-hub.h"

namespace Vdev {

class Pl031
: public Vmm::Mmio_device_t<Pl031>,
  public Vdev::Timer,
  public Vdev::Device
{
  struct Alarm_timeout : public L4::Ipc_svr::Timeout_queue::Timeout
  {
    Alarm_timeout(Pl031 *pl031) : _pl031(pl031) {}

    /**
     * Handle expired alarms.
     *
     * This function is called from the timer thread.
     */
    void expired() override
    {
      trace().printf("PL031 IRQ due to alarm expired()\n");
      _pl031->set_irq();
    }

    Pl031 *_pl031;
  }; // struct Alarm_timeout

  enum Registers
  {
    Dr = 0x0,    ///< Data register, RO
    Mr = 0x4,    ///< Match register, RW
    Lr = 0x8,    ///< Load register, RW
    Cr = 0xC,    ///< Control register, RW
    Imsc = 0x10, ///< Interrupt mask set or clear register, RW
    Ris = 0x14,  ///< Raw interrupt status register, RO
    Mis = 0x18,  ///< Masked interrupt status register, RO
    Icr = 0x1C,  ///< Interrupt clear register, WO

    // 0x020 - 0xFDF Reserved and undefined areas

    // Read-only
    Periph_id0 = 0xFE0, ///< Peripheral ID register 7:0
    Periph_id1 = 0xFE4, ///< Peripheral ID register 15:8
    Periph_id2 = 0xFE8, ///< Peripheral ID register 23:16
    Periph_id3 = 0xFEC, ///< Peripheral ID register 31:24

    // Read-only
    Pcell_id0 = 0xFF0,  ///< PrimeCell ID register 7:0
    Pcell_id1 = 0xFF4,  ///< PrimeCell ID register 15:8
    Pcell_id2 = 0xFF8,  ///< PrimeCell ID register 23:16
    Pcell_id3 = 0xFFC,  ///< PrimeCell ID register 31:24
  };

public:
  Pl031(cxx::Ref_ptr<Gic::Ic> const &ic, int irq) : _irq(ic, irq), _alarm(this)
  {
    reset();
#if !defined(CONFIG_UVMM_EXTERNAL_RTC) and !(CONFIG_RELEASE_MODE)
    warn().printf(
      "No external clock source. Rtc time will not represent wallclock time.\n"
      "Set CONFIG_UVMM_EXTERNAL_RTC = y if you have an external clock "
      "source.\n");
#endif
  }

  l4_uint32_t read(unsigned reg, char size, unsigned /*cpu_id*/)
  {
    if (size != Vmm::Mem_access::Width::Wd32)
    {
      warn().printf("Read access width not 32-bit, ignoring access: "
                    "Reg: 0x%x, Wd: %i\n", reg, size);
      return 0;
    }

    l4_umword_t retval = 0;

    switch (reg)
      {
      case Registers::Dr: retval = counter(); break;
      case Registers::Mr: retval = _match_reg; break;
      case Registers::Lr: retval = _load_reg; break;
      case Registers::Cr: retval = 1U; break; // always on.
      case Registers::Imsc: retval = _imsc & 1U; break;
      case Registers::Ris: retval = _intr; break;
      case Registers::Mis: retval = _intr & (_imsc & 1U); break;

      case Registers::Icr: // error: read of WO register
        warn().printf("Reading write-only ICR register\n");
        break;

      case Registers::Periph_id0: [[fallthrough]];
      case Registers::Periph_id1: [[fallthrough]];
      case Registers::Periph_id2: [[fallthrough]];
      case Registers::Periph_id3:
        retval = periph_id[(reg - Periph_id0) >> 2];
        break;

      case Registers::Pcell_id0: [[fallthrough]];
      case Registers::Pcell_id1: [[fallthrough]];
      case Registers::Pcell_id2: [[fallthrough]];
      case Registers::Pcell_id3:
        retval = pcell_id[(reg - Pcell_id0) >> 2];
        break;

      default: break;
      }

    return retval;
  }

  void write(unsigned reg, char size, l4_umword_t value, unsigned /*cpu_id*/)
  {
    if (size != Vmm::Mem_access::Width::Wd32)
      {
        info().printf("Write access width not 32-bit, ignoring access: "
                      "Reg: 0x%x, Wd: %i\n",
                      reg, size);
        return;
      }

    trace().printf("Writing 0x%lx to reg 0x%x\n", value, reg);

    switch (reg)
      {
      case Registers::Dr:
        info().printf("Writing read-only register DR. Ignoring.\n");
        break;

      case Registers::Mr:
        _match_reg = value;
        update_alarm();
        break;

      case Registers::Lr:
        _load_reg = value;
        update_load();
        break;

      case Registers::Cr:
        // writing resets -- not implemented -- always on;
        break;

      case Registers::Imsc: _imsc = value & 1U; break;

      case Registers::Ris: [[fallthrough]];
      case Registers::Mis:
        warn().printf("Writing read-only register 0x%x. Ignoring.\n", reg);
        break;

      case Registers::Icr:
        if (value & 0x1U && _intr)
          {
            _intr = 0;
            _irq.ack();
          }
        break;

      default:
        info()
          .printf("Writing read-only register or unspecified register 0x%x\n",
                  reg);
      }
  }

  char const *dev_name() const override { return "PL031"; }

private:
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PL031"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PL031"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PL031"); }

  static l4_uint64_t ns_to_s(l4_uint64_t ns) { return ns / 1'000'000'000; }
  static l4_uint64_t s_to_us(l4_uint64_t s) { return s * 1'000'000; }
  static l4_uint64_t s_to_ns(l4_uint64_t s) { return s * 1'000'000'000; }

  /// Return current counter value with 1Hz granularity. Wraps after 136 years.
  static l4_uint32_t counter()
  { return ns_to_s(L4rtc_hub::ns_since_epoch()) & 0xffff'ffffU; }

  /// Flag the IRQ and if not masked also send it.
  void set_irq()
  {
    _intr = 1U;

    if (_imsc == 0U)
      _irq.inject();
  }

  /**
   * Update the alarm timeout or inject IRQ if timeout already passed.
   *
   * \param counter_val  Counter value, if already queried from L4rtc.
   */
  void update_alarm(l4_uint32_t const counter_val = counter())
  {
    if (_match_reg <=  counter_val)
      set_irq();
    else
      {
        l4_uint64_t next_alarm = _match_reg - counter_val;

        trace().printf("enqueue alarm for %lli seconds from now. (counter: %u,"
                       " 0x%u)\n",
                      next_alarm, counter_val, _match_reg);
        enqueue_timeout(&_alarm, l4_kip_clock(l4re_kip()) + s_to_us(next_alarm));
      }
  }

  void update_load()
  {
    L4rtc_hub::set_ns_since_epoch(s_to_ns(_load_reg));
    update_alarm();
  }

  void reset()
  {
    _load_reg = 0;
    _match_reg = 0;
    _imsc = 0;
    _intr = 0;
    _irq.ack();
  }

  l4_uint8_t const periph_id[4] = {0x31, 0x10, 0x04, 0x00};
  l4_uint8_t const pcell_id[4] = {0x0D, 0xF0, 0x05, 0xB1};

  Vmm::Irq_sink _irq;
  Alarm_timeout _alarm;

  l4_uint32_t _match_reg;
  l4_uint32_t _load_reg;
  l4_uint8_t _imsc; // 1 = masked, 0 = clear
  l4_uint8_t _intr; // interrupt status
};

} // namespace Vdev

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    Dbg info = Dbg(Dbg::Dev, Dbg::Info, "PL031");
    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) < 0)
      return nullptr;

    if (!it.ic_is_virt())
      {
        info.printf("PL031 requires a virtual interrupt controller.");
        return nullptr;
      }

    auto dev = Vdev::make_device<Vdev::Pl031>(it.ic(), it.irq());

    devs->vmm()->register_mmio_device(dev, Vmm::Region_type::Virtual, node);
    devs->vmm()->register_timer_device(dev);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t1 = { "arm,pl031", nullptr, &f };

} // namespace
