/*
 * Copyright (C) 2025 Kernkonzept GmbH.
 * Author(s): Jakub Jermar <jakub.jermar@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

/**
 * \file
 * Virtual SBSA Generic Watchdog Timer device.
 *
 * The implementation is split into a frontend and a backend. The frontend
 * takes care of providing the SBSA Generic Watchdog Timer hardware interface to
 * the guest, while the backend implements the actual watchdog functionality.
 * Currently only a backend which uses the vWatchdog service is provided.
 *
 * To enable this device, add the following snippet to your device tree:
 *
 * \code{.dtb}
 *   virt_sbsa_gwdt@3000 {
 *       compatible = "arm,sbsa-gwdt";
 *       reg = <0x3000 0x1000>,  // Watchdog Control
 *             <0x4000 0x1000>;  // Refresh
 *       interrupt-parent = <&gic>;
 *       interrupts = <0 124 4>;
 *       l4vmm,ctrlcap = "wdt_ctrl";
 *       l4vmm,stages = <2>;     // Default <1>: (sbsa_wdog.action=0)
 *                               //         <2>: (sbsa_wdog.action=1)
 *   };
 * \endcode
 */

#include <l4/sys/cxx/ipc_epiface>
#include <l4/re/error_helper>
#include <l4/re/rm>
#include <l4/cxx/bitfield>
#include <l4/cxx/utils>

#include "debug.h"
#include "device_factory.h"
#include "guest.h"
#include "irq.h"
#include "irq_dt.h"
#include "mmio_device.h"

#include <l4/vwatchdog/vdev.h>
#include <l4/vwatchdog/watchdog_ctrl_obj.h>

#define DNAME "sbsa_gwdt"

using namespace Watchdog;

namespace {

/**
 * The backend implementation for the Sbsa_gwdt which communicates with the
 * vWatchdog service.
 */
struct Vwdog : L4::Irqep_t<Vwdog>
{
  Vwdog(L4::Registry_iface *registry, L4::Cap<Watchdog_ctrl_obj> ctrl,
        unsigned stages)
  : ctrl(ctrl)
  {
    L4Re::Util::Unique_cap<L4Re::Dataspace> ds =
      L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dataspace>(),
                   "Allocating dataspace capability.");

    ctrl->get_ds(ds.get());
    L4Re::chkcap(ds, "Getting dataspace from vWatchdog.");

    L4Re::chksys(L4Re::Env::env()->rm()->attach(
                   &wdog_mem, L4_PAGESIZE,
                   L4Re::Rm::F::Search_addr | L4Re::Rm::F::RWX, ds.get()),
                 "Attaching to watchdog memory.");

    if ((read32(REG_ID0) != ID0_VALUE) || (read32(REG_ID1) != ID1_VALUE))
      L4Re::chksys(-L4_EINVAL, "vWatchdog identification mismatch");

    L4Re::chkcap(registry->register_irq_obj(this), "Registering IRQ object.");
    L4Re::chksys(ctrl->register_notification(obj_cap(), stages - 1),
                 "Registering notification IRQ.");

    ds.release();
  }

  virtual ~Vwdog() {}

  /** Timeout callback to be implemented by the frontend. */
  virtual void timeout() = 0;

  void handle_irq()
  { timeout(); }

  l4_uint32_t read32(unsigned offset) const
  {
    return cxx::access_once<l4_uint32_t>(
      reinterpret_cast<l4_uint32_t *>(wdog_mem.get() + offset));
  }

  void write32(unsigned offset, l4_uint32_t value)
  {
    cxx::write_now<l4_uint32_t>(
      reinterpret_cast<l4_uint32_t *>(wdog_mem.get() + offset), value);
  }

  void ping()
  {
    l4_uint32_t lo;

    lo = read32(REG_COUNTER_LO);

    lo++;
    if (lo == 0)
      {
        l4_uint32_t hi = read32(REG_COUNTER_HI);
        write32(REG_COUNTER_HI, hi + 1);
      }

    write32(REG_COUNTER_LO, lo);
  }

  void enable()
  {
    l4_uint32_t val = read32(REG_CTRL) | CTRL_RUNNING;
    write32(REG_CTRL, val);
  }

  void disable()
  {
    l4_uint32_t val = read32(REG_CTRL) & ~CTRL_RUNNING;
    write32(REG_CTRL, val);
  }

  void set_period(l4_uint64_t period)
  {
    ctrl->set_period((unsigned)period);
  }

  L4::Cap<Watchdog_ctrl_obj> ctrl;
  L4Re::Rm::Unique_region<l4_addr_t> wdog_mem;
};

/**
 * Frontend implementation for the SBSA Generic Watchdog Timer device.
 *
 * \tparam WDOG_IMPL  Class implementing the backend functionality, such as
 *                    pinging (a.k.a refreshing), timeout notifications,
 *                    enabling/disabling and period setting.
 *
 * As the device is a two-stage watchdog, the behavior on a timeout notification
 * depends on its internal state. Upon entering the WS0 state, a configured
 * interrupt is injected into the guest (it is up to the guest to decide how to
 * handle it). Upon entering the WS1 state, the whole VM shuts down with the
 * provision that it may or may not be restarted by an external service, such as
 * vWatchdog.
 */
template <typename WDOG_IMPL>
class Sbsa_gwdt
: public Vdev::Device,
  public WDOG_IMPL
{
public:
  class Refresh_frame : public Vmm::Mmio_device_t<Refresh_frame>
  {

  public:
    Refresh_frame(Sbsa_gwdt *parent) : _parent(parent) {}

    l4_uint32_t read(unsigned reg, char size, unsigned cpu_id)
    { return _parent->ref_read(reg, size, cpu_id); }

    void write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
    { _parent->ref_write(reg, size, value, cpu_id); }

    char const *dev_name() const override { return DNAME "_ref"; }

  private:
    Sbsa_gwdt *_parent;
  };

  class Watchdog_control_frame
  : public Vmm::Mmio_device_t<Watchdog_control_frame>
  {
  public:
    Watchdog_control_frame(Sbsa_gwdt *parent) : _parent(parent) {}

    l4_uint32_t read(unsigned reg, char size, unsigned cpu_id) const
    { return _parent->ctl_read(reg, size, cpu_id); }

    void write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
    { _parent->ctl_write(reg, size, value, cpu_id); }

    char const *dev_name() const override { return DNAME "_ctl"; }

  private:
    Sbsa_gwdt *_parent;
  };

  enum Reg_frames
  {
    Watchdog_control_frame_idx = 0,
    Refresh_frame_idx = 1
  };

  enum Refresh_regs
  {
    WRR = 0U,        ///< Watchdog Refresh Register
    W_IID = 0xfccU   ///< Watchdog Interface Identification Register
  };

  enum Watchdog_control_regs
  {
    WCS = 0U,        ///< Watchdog Control and Status Register
    WOR_LO = 0x8U,   ///< Watchdog Offset Register (low)
    WOR_HI = 0xcU,   ///< Watchdog Offset Register (high)
    WCV_LO = 0x10U,  ///< Watchdog Compare Value (low)
    WCV_HI = 0x14U,  ///< Watchdog Compare Value (high)
    W_IIDR = 0xfccU, ///< Watchdog Interface Identification Register
  };

  struct W_iidr_reg
  {
    l4_uint32_t raw;

    explicit W_iidr_reg() : raw(0)
    {
      impl_low() = 'K' - 'A';
      impl_high() = 'K' - 'A';
      ver() = 1;
    }

    CXX_BITFIELD_MEMBER(0, 6, impl_low, raw);
    CXX_BITFIELD_MEMBER(8, 11, impl_high, raw);
    CXX_BITFIELD_MEMBER(16, 19, ver, raw);
  };

  struct Wcs_reg
  {
    l4_uint32_t raw;

    explicit Wcs_reg() : raw(0) {}
    explicit Wcs_reg(l4_uint32_t v) : raw(v) {}

    CXX_BITFIELD_MEMBER(0, 0, we, raw);
    CXX_BITFIELD_MEMBER(1, 1, ws0, raw);
    CXX_BITFIELD_MEMBER(2, 2, ws1, raw);
  };

  /**
   * Ctor for virtual SBSA Generic Watchdog Timer device.
   *
   * \tparam Ts   Types for the ctor of the WDOG_IMPL base class.
   *
   * \param ic    Interrupt controller for \c irq.
   * \param irq   IRQ to inject upon entering WS0 state.
   * \param vmm   Guest to shutdown upon entering WS1 state.
   * \param args  Arguments for the ctor of the WDOG_IMPL base class.
   */
  template <typename... Ts>
  explicit Sbsa_gwdt(cxx::Ref_ptr<Gic::Ic> const &ic, int irq, Vmm::Guest *vmm,
                     Ts &&... args)
  : WDOG_IMPL(cxx::forward<Ts>(args)...),
    ref_frame(cxx::make_ref_obj<Refresh_frame>(this)),
    ctl_frame(cxx::make_ref_obj<Watchdog_control_frame>(this)),
    _vmm(vmm),
    _ws0_sink(ic, irq)
  {
  }

  l4_uint32_t ref_read(unsigned reg, char size, unsigned cpu_id) const
  {
    l4_uint32_t ret = 0;
    switch (reg)
      {
      case WRR:
        ret = 0;
        break;
      case W_IID:
        ret = _w_iidr.raw;
        break;
      default:
        Dbg(Dbg::Dev, Dbg::Warn, ref_frame->dev_name())
          .printf("Unhandled read: register: %x, size: %u cpu: %u\n", reg, size,
                  cpu_id);
        break;
      }

    return ret;
  }

  void ref_write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
  {
    switch (reg)
      {
      case WRR:
        explicit_refresh();
        break;
      default:
        Dbg(Dbg::Dev, Dbg::Warn, ref_frame->dev_name())
          .printf("Unhandled write: register: %x, value: %x size: %u cpu: %u\n",
                  reg, value, size, cpu_id);
        break;
      }
  }

  l4_uint32_t ctl_read(unsigned reg, char size, unsigned cpu_id) const
  {
    l4_uint32_t ret = 0;
    switch (reg)
      {
      case WCS:
        ret = _wcs.raw;
        break;
      case WOR_LO:
        ret = _wor_lo;
        break;
      case WOR_HI:
        ret = _wor_hi;
        break;
      case WCV_LO:
        ret = _wcv_lo;
        break;
      case WCV_HI:
        ret = _wcv_hi;
        break;
      case W_IIDR:
        ret = _w_iidr.raw;
        break;
      default:
        Dbg(Dbg::Dev, Dbg::Warn, ctl_frame->dev_name())
          .printf("Unhandled read: register: %x size: %u cpu: %u\n", reg, size,
                  cpu_id);
        break;
      }

    return ret;
  }

  void ctl_write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
  {
    switch (reg)
      {
      case WCS:
        {
          Wcs_reg r(value);
          _wcs.we() = r.we();
          if (_wcs.we())
            WDOG_IMPL::enable();
          else
            WDOG_IMPL::disable();
        }
        explicit_refresh();
        break;
      case WOR_LO:
        {
          bool update = value != _wor_lo;
          _wor_lo = value;
          if (update)
            WDOG_IMPL::set_period(wor_to_usec());
        }
        explicit_refresh();
        break;
      case WOR_HI:
        {
          value &= 0xffffUL;
          bool update = value != _wor_hi;
          _wor_hi = value;
          if (update)
            WDOG_IMPL::set_period(wor_to_usec());
        }
        explicit_refresh();
        break;
      case WCV_LO:
        _wcv_lo = value;
        break;
      case WCV_HI:
        _wcv_hi = value;
        break;
      default:
        Dbg(Dbg::Dev, Dbg::Warn, ctl_frame->dev_name())
          .printf("Unhandled write: register: %x value: %x size: %u cpu: %u\n",
                  reg, value, size, cpu_id);
        break;
      }
  }

  void timeout() override
  {
    timeout_refresh();
  }

private:
  void update_compare_value()
  {
    l4_uint64_t cv = timer_cnt() + wor();
    _wcv_hi = cv >> 32;
    _wcv_lo = cv & 0xfffffffful;
  }

  void explicit_refresh()
  {
    update_compare_value();
    _wcs.ws0() = 0;
    _wcs.ws1() = 0;
    WDOG_IMPL::ping();
  }

  void timeout_refresh()
  {
    if (!_wcs.ws0())
      update_compare_value();
    if (!_wcs.we())
      {
        _wcs.ws0() = 0;
        _wcs.ws1() = 0;
      }
    else
      {
        if (!_wcs.ws0())
          {
            Dbg(Dbg::Dev, Dbg::Warn, DNAME).printf("Entering WS0 state.\n");
            _wcs.ws0() = 1;
            _ws0_sink.inject();
          }
        else
          {
            Dbg(Dbg::Dev, Dbg::Info, DNAME).printf("Entering WS1 state.\n");
            _wcs.ws1() = 1;
            _vmm->shutdown(Vmm::Guest::Reboot);
          }
      }
  }

  l4_uint64_t wor()
  { return (static_cast<l4_uint64_t>(_wor_hi) << 32) | _wor_lo; }

  static l4_uint32_t timer_freq()
  { return Vmm::Vcpu_ptr::cntfrq(); }

  static l4_uint64_t timer_cnt()
  { return Vmm::Vcpu_ptr::cntvct(); }

  l4_uint64_t wor_to_usec()
  {
    return (wor() / (timer_freq() / 1000)) * 1000;
  }

public:
  cxx::Ref_ptr<Vmm::Mmio_device> ref_frame;
  cxx::Ref_ptr<Vmm::Mmio_device> ctl_frame;
private:
  Vmm::Guest *_vmm;
  Vmm::Irq_sink _ws0_sink;

  W_iidr_reg _w_iidr;
  Wcs_reg _wcs;

  l4_uint32_t _wor_lo = 0;
  l4_uint32_t _wor_hi = 0;
  l4_uint32_t _wcv_lo = 0;
  l4_uint32_t _wcv_hi = 0;

  Device *dev() { return static_cast<Device *>(this); }
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info)
      .printf("Create virtual SBSA Generic Watchdog Timer device.\n");

    auto ctrl = Vdev::get_cap<Watchdog_ctrl_obj>(node, "l4vmm,ctrlcap");
    L4Re::chkcap(ctrl,
                 "arm,sbsa-gwdt node requires the 'l4vmm,ctrlcap' property!");

    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) < 0)
      return nullptr;

    if (!it.ic_is_virt())
      L4Re::chksys(
        -L4_EINVAL,
        "arm,sbsa-gwdt node requires a virtual interrupt controller");

    auto stages = node.get_prop<fdt32_t>("l4vmm,stages", nullptr);
    if (stages && (fdt32_to_cpu(*stages) < 1 || fdt32_to_cpu(*stages) > 2))
      L4Re::chksys(-L4_EINVAL, "Invalid l4vmm,stages property.");

    auto c =
      Vdev::make_device<Sbsa_gwdt<Vwdog>>(it.ic(), it.irq(), devs->vmm(),
                                          devs->vmm()->registry(), ctrl,
                                          stages ? fdt32_to_cpu(*stages) : 1);

    devs->vmm()->register_mmio_device(
      c->ctl_frame, Vmm::Region_type::Virtual, node,
      Sbsa_gwdt<Vwdog>::Watchdog_control_frame_idx);
    devs->vmm()->register_mmio_device(
      c->ref_frame, Vmm::Region_type::Virtual, node,
      Sbsa_gwdt<Vwdog>::Refresh_frame_idx);

    return c;
  }
};

}

static F f;
static Vdev::Device_type t = { "arm,sbsa-gwdt", nullptr, &f };
