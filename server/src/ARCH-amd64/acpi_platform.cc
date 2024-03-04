/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020-2023 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 */
#include "acpi.h"
#include "device_factory.h"
#include "irq_dt.h"

namespace Acpi {

/**
 * \file
 * Acpi platform support
 *
 * This implements minimal Acpi command support. Enough that Linux believes
 * that Acpi works and that it uses Acpi shutdown.
 *
 * This requires a device tree entry like this.
 *
 *      acpi_platform {
 *        compatible = "virt-acpi";
 *        interrupt-parent = <&PIC>;
 *        interrupts = <9>;
 *      };
 *
 * You may configure a different interrupt number for the system control
 * interrupt (SCI), but make sure it does not collide.
 *
 * The interrupt parent is mandatory. The SCI is currently only used during
 * Acpi probing.
 */
class Acpi_platform:
  public Vmm::Io_device,
  public Vdev::Device,
  public Acpi_device
{
private:
  enum Command_values : l4_uint16_t
  {
    Acpi_enable     = 0xf2,
    Acpi_disable    = 0xf1,
    Acpi_shutdown   = 0x7,
    Acpi_suspend    = 0x6,
    Reboot          = 0x4,
  };

public:
  enum Ports: l4_uint16_t
  {
    Ports_start     = 0x1800,
    Smi_command     = Ports_start,
    Pm1a_cmd_block  = Smi_command + 1, // 0x1801
    Pm1a_cmd_length = 2, // 2 ports
    Pm2_cmd_block   = Pm1a_cmd_block + Pm1a_cmd_length, // 0x1803
    Pm2_cmd_length  = 1,  // 1 port
    Pm1a_event_block= Pm2_cmd_block + Pm2_cmd_length,   // 0x1804
    Pm1a_sts        = Pm1a_event_block,
    Pm1a_en         = Pm1a_event_block + 2,
    Pm1_event_length= 4,
    Reset_register  = Pm1a_event_block + Pm1_event_length, // 0x1808
    Ports_last       = Reset_register, // inclusive end
  };

  Acpi_platform(Vmm::Guest *vmm, cxx::Ref_ptr<Gic::Ic> const &ic, int irq)
  : Acpi_device(),
    _vmm(vmm),
    _sci(ic, irq),
    _irq(irq),
    _acpi_enabled(false)
  {}

  char const *dev_name() const override
  { return "ACPI platform"; }

  void amend_fadt(ACPI_TABLE_FADT *t) const override
  {
    t->SmiCommand  = Ports::Smi_command; // 32-bit port address of SMI command port
    t->SciInterrupt = _irq;
    t->AcpiEnable  = Command_values::Acpi_enable;
    t->AcpiDisable = Command_values::Acpi_disable;

    // 32-bit port address of Power Mgt 1a Control Reg Block
    t->Pm1aControlBlock = Ports::Pm1a_cmd_block;
    // size of block
    t->Pm1ControlLength = Ports::Pm1a_cmd_length;

    // 32-bit port address of Power Mgt 2 Control Reg Block
    t->Pm2ControlBlock = Ports::Pm2_cmd_block;
    // size of block
    t->Pm2ControlLength = Ports::Pm2_cmd_length;

    t->Pm1aEventBlock = Ports::Pm1a_event_block;
    t->Pm1EventLength = Ports::Pm1_event_length;

    // set the reset register for ACPI reboot
    t->Flags                 |= ACPI_FADT_RESET_REGISTER;
    t->ResetRegister.Address  = Ports::Reset_register;
    t->ResetRegister.SpaceId  = ACPI_ADR_SPACE_SYSTEM_IO;
    t->ResetRegister.BitWidth = ACPI_RESET_REGISTER_WIDTH;
    t->ResetValue             = Command_values::Reboot;
  }

  /**
   * Write an ACPI control object to the DSDT table that allows the guest to
   * discover shutdown capability.
   *
   * This is described in section 7.4.2 of the ACPI specification.
   *
   * \param buf       The memory are where to put the object.
   * \param max_size  Maximum available size of the designated memory area.
   */
  l4_size_t amend_dsdt(void *buf, l4_size_t max_size) const override
  {
    // _S3 == suspend to ram
    // _S5 == shutdown
    unsigned char dsdt_S3S5 [] =
    {
      0x08, 0x5F, 0x53, '3', 0x5F, 0x12, 0x08, 0x04,
      0x0A, Command_values::Acpi_suspend,
      0x0A, Command_values::Acpi_suspend,
      0x00, 0x00,
      0x08, 0x5F, 0x53, '5', 0x5F, 0x12, 0x08, 0x04,
      0x0A, Command_values::Acpi_shutdown,
      0x0A, Command_values::Acpi_shutdown,
      0x00, 0x00,
    };

    l4_size_t size = sizeof(dsdt_S3S5);
    if (max_size < size)
      L4Re::throw_error(-L4_ENOMEM,
                        "Not enough space in DSDT");
    memcpy(buf, reinterpret_cast<void*>(dsdt_S3S5), size);
    return size;
  }

  /**
   * Handle pm1a enable register.
   *
   * This handles a subset of the PM1A enable register as described in section
   * 4.8.3.1 of the ACPI specification. We support GBL_EN, PRWBTN_EN,
   * SLPBTN_EN and the RTC_EN bits. If both the corresponding status and the
   * enable bit is set, we inject an SCI.
   */
  void handle_pm1a_en()
  {
    if (!_acpi_enabled)
      return;

    int events[] = { 5 /* gbl */,
                     8 /* pwr btn */,
                     9 /* slp btn */,
                     10 /* rtc */};

    for (auto i : events)
      {
        // if sts and en bits are set we issue an SCI
        if (_pm1a_sts & (1 << i)
            && _pm1a_en & (1 << i))
          {
            trace().printf("Injecting SCI\n");
            _sci.inject();
            _pm1a_sts &= ~(1 << i); // clear status
          }
      }
    trace().printf("_pm1a_sts = 0x%x _pm1a_en = 0x%x\n", _pm1a_sts, _pm1a_en);
  }

  /**
   * Handle a subset of the pm1a control register.
   *
   * This function handles the PM1A control register as described in section
   * 4.8.3.2 of the ACPI specification. We only handle the SLP_EN and SLP_TYPx
   * bits.
   *
   * \param value  The value written to the register.
   */
  void handle_pm1a_control(l4_uint32_t value)
  {
    enum
    {
      Slp_enable = 1 << 13,
      Slp_type_shutdown = Acpi_shutdown << 10,
      Slp_type_suspend = Acpi_suspend << 10,
      Slp_type_mask = 0x7 << 10,
    };
    static_assert((Slp_type_shutdown & Slp_type_mask) == Slp_type_shutdown,
                  "ACPI platform: Sleep type shutdown within field bounds");
    static_assert((Slp_type_suspend & Slp_type_mask) == Slp_type_suspend,
                  "ACPI platform: Sleep type suspend within field bounds");

    if (value & Slp_enable)
      {
        if ((value & Slp_type_mask) == Slp_type_shutdown)
          {
            trace().printf("Guest requested power off. Bye\n");
            _vmm->shutdown(Vmm::Guest::Shutdown);
          }
        else if ((value & Slp_type_mask) == Slp_type_suspend)
          {
            trace().printf("System suspend requested\n");
            // If Uvmm loaded a guest Linux kernel itself, it emulates
            // firmware behaviour by resuming the guest directly at the
            // address the guest specified in the FACS.
            // Otherwise the VM resumes at the reset vector where firmware
            // shall take care of guest resume.
            if (_vmm->guest_type() == Boot::Binary_type::Linux)
              _vmm->suspend(Facs_storage::get()->waking_vector());
            else
              _vmm->suspend(0xffff'fff0);
          }
      }
  }

  /**
   * Handle IO port reads to the device.
   *
   * \param      port   IO port
   * \param[out] value  The value read from the IO port.
   */
  void io_in(unsigned port, Vmm::Mem_access::Width /*width*/,
             l4_uint32_t *value) override
  {
    port += Smi_command;
    *value = -1U;
    switch (port)
      {
      case Smi_command:
        *value = 0;
        break;
      case Pm1a_cmd_block:
        if (_acpi_enabled)
          *value = 1; // SMI_EN == 1
        else
          *value = 0;
        break;
      case Pm1a_sts:
        *value = _pm1a_sts;
        break;
      case Pm1a_en:
        *value = _pm1a_en;
        break;
      default:
        trace().printf("IO IN port=%x value=%x\n", port, *value);
        break;
      }
  }

  /**
   * Handle IO port writes to device IO ports.
   *
   * \param port   IO Port
   * \param value  The value written to the port.
   */
  void io_out(unsigned port, Vmm::Mem_access::Width /*width*/,
              l4_uint32_t value) override
  {
    port += Smi_command;
    switch (port)
      {
      case Smi_command:
        if (value == Acpi_enable)
          {
            trace().printf("Acpi enabled\n");
            _acpi_enabled = true;
          }
        else if (value == Acpi_disable)
          {
            trace().printf("Acpi disabled\n");
            _acpi_enabled = false;
          }
        break;
      case Pm1a_cmd_block:
        handle_pm1a_control(value);
        break;
      case Pm1a_sts:
        _pm1a_sts = value;
        break;
      case Pm1a_en:
        _pm1a_en = value;
        handle_pm1a_en();
        break;
      case Reset_register:
        if (value == Command_values::Reboot)
          {
            trace().printf("Reboot requested. Bye\n");
            _vmm->shutdown(Vmm::Guest::Reboot);
          }
        break;
      default:
        trace().printf("IO OUT port=%x value=%x\n", port, value);
        break;
      }
  }

private:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "Acpi_platform"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "Acpi_platform"); }

  Vmm::Guest *_vmm;
  Vmm::Irq_edge_sink _sci;
  unsigned const _irq;
  bool _acpi_enabled;
  l4_uint32_t _pm1a_sts, _pm1a_en;
};

} // namespace Acpi

/***********************************************************************/

namespace
{

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {

    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) < 0)
      return nullptr;

    if (!it.ic_is_virt())
      L4Re::throw_error(-L4_EINVAL, "Acpi_platform requires a virtual "
                        "interrupt controller");

    auto dev = Vdev::make_device<Acpi::Acpi_platform>(devs->vmm(), it.ic(),
                                                      it.irq());

    Dbg().printf("Creating Acpi_platform\n");

    auto *vmm = devs->vmm();
    auto start = Acpi::Acpi_platform::Ports::Ports_start;
    auto end   = Acpi::Acpi_platform::Ports::Ports_last;
    vmm->add_io_device(Vmm::Io_region(start, end, Vmm::Region_type::Virtual),
                       dev);
    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"virt-acpi", nullptr, &f};

}
