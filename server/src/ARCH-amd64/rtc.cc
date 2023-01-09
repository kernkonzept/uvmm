/*
 * Copyright (C) 2017-2019, 2021-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

/**
 * Minimal viable implementation of a RTC.
 *
 * We do not support CMOS memory.
 * We do not support setting new time values.
 * We only support 24h mode (it is hard-wired).
 * We do not support alarms.
 * We do not support the century byte.
 *
 * On amd64 linux will assume the rtc is in BCD mode even when the format is
 * set to binary.
 *
 * Example device tree entry:
 *
 *      rtc {
 *          compatible = "virt-rtc";
 *          reg = <0x0 0x0 0x0 0x0>;
 *      };
 *
 * Optionally this emulation can use wallclock-time from an external source.
 */
#include "device_factory.h"
#include "guest.h"
#include "device.h"
#include "io_device.h"

#include "../device/rtc-hub.h"

namespace Vdev {

class Rtc : public Vmm::Io_device, public Vdev::Device
{
  unsigned _reg_sel = 0;
  unsigned _reg_a = 0;
  unsigned _reg_b = Mode_24h;
  unsigned _reg_c = 0;

  enum Register : unsigned
  {
    Seconds = 0,
    Seconds_alarm,
    Minutes,
    Minutes_alarm,
    Hours,
    Hours_alarm,
    Weekday,
    Day_of_month,
    Month,
    Year,
    Status_a = 0xa,
    Status_b = 0xb,
    Reg_c = 0xc,
    Reg_d = 0xd,

    // Cmos_ram
    Ram_start = 0xe,
    Ram_end = 0x80,
  };

  enum Status_reg_b : unsigned
  {
    Mode_24h = 0x2,
    Binary_format = 0x4,
    Update_ended_interrupt_enable = 0x10,
    Alarm_interrupt_enable = 0x20,
    Periodic_interrupt_enable = 0x40,

    Format_mask = 0xfffffff8,
  };

  enum Status_reg_c : unsigned
  {
    Update_ended_interrupt_flag = 0x10,
    Alarm_interrupt_flag = 0x20,
    Periodic_interrupt_flag = 0x40,
    Interrupt_request_flag = 0x80,
  };

  enum Status_reg_d : unsigned
  {
    Valid_ram_and_time = 0x80,
  };

  // convert to BCD if needed
  l4_uint32_t convert(int val)
  {
    if (_reg_b & Binary_format)
      return val;

    // See https://de.wikipedia.org/wiki/BCD-Code
    return (val % 10) + ((val / 10) << 4);
  }

  void handle_write(l4_uint32_t value)
  {
    switch (_reg_sel)
      {
      case Status_a:
        _reg_a = value;
        break;
      case Status_b:
        _reg_b = value | Mode_24h;
        break;
      case Reg_c:
      case Reg_d:
        warn().printf("Write to RO reg (%u)\n", _reg_sel);
        break;
      default:
        if (Ram_start > _reg_sel || _reg_sel > Ram_end)
          warn().printf("Register write not handled (%u)\n", _reg_sel);
        break;
      }
  }

  l4_uint32_t handle_read()
  {
    // these registers need to always work
    switch (_reg_sel)
      {
      case Status_a:
        return _reg_a;
        break;
      case Status_b:
        return _reg_b;
        break;
      case Reg_c:
        {
          unsigned ret = _reg_c;
          _reg_c = 0;
          return ret;
        }
      case Reg_d:
        return Valid_ram_and_time;
      }

    const time_t seconds = L4rtc_hub::get()->ns_since_epoch() / 1000000000;

    struct tm *t = localtime(&seconds);
    if (!t)
      {
        warn().printf("Could not determine time.\n");
        return 0;
      }

    l4_uint32_t ret = 0;
    switch (_reg_sel)
      {
      case Seconds:
        ret = convert(t->tm_sec);
        break;
      case Seconds_alarm:
        // not supported
        break;
      case Minutes:
        ret = convert(t->tm_min);
        break;
      case Minutes_alarm:
        // not supported
        break;
      case Hours:
        ret = convert(t->tm_hour);
        break;
      case Hours_alarm:
        // not supported
        break;
      case Weekday:
        ret = convert(t->tm_wday);
        break;
      case Day_of_month:
        ret = convert(t->tm_mday);
        break;
      case Month:
        ret = convert(t->tm_mon + 1); // localtime returns months counting from zero
        break;
      case Year:
        ret = convert(t->tm_year % 100);
        break;
      default:
        if (Ram_start > _reg_sel || _reg_sel > Ram_end)
          warn().printf("Unknown register read (%d)\n", _reg_sel);
        break;
      }
    return ret;
  }

public:
  /* IO write from the guest to device */
  void io_out(unsigned port, Vmm::Mem_access::Width, l4_uint32_t value) override
  {
    switch (port)
      {
      case 0:
        _reg_sel = value & 0xff;
        break;
      case 1:
        handle_write(value);
        break;
      default:
        warn().printf("Unknown port written (%u).\n", port);
        break;
      }
  }

  /* IO read from the guest */
  void io_in(unsigned port, Vmm::Mem_access::Width, l4_uint32_t *value) override
  {
    switch (port)
      {
      case 0:
        *value = _reg_sel;
        break;
      case 1:
        *value = handle_read();
        break;
      default:
        warn().printf("Unknown port read (%u).\n", port);
        break;
      };
  }

  ~Rtc()
  { L4rtc_hub::destroy(); }

private:
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "RTC"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "RTC"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "RTC"); }
};

} // namespace Vdev

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &) override
  {
    auto dev = Vdev::make_device<Vdev::Rtc>();

    auto region = Vmm::Io_region(0x70, 0x71, Vmm::Region_type::Virtual);
    devs->vmm()->add_io_device(region, dev);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"virt-rtc", nullptr, &f};

} // namespace
