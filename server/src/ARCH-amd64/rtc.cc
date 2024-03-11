/*
 * Copyright (C) 2017-2019, 2021-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

/**
 * Minimal viable implementation of a CMOS RTC (Motorola MC146818A).
 *
 * We do not support setting new time values.
 * We only support 24h mode (it is hard-wired).
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
 *          interrupt-parent = <&IOAPIC>;
 *          interrupts = <8>;
 *      };
 *
 * Optionally this emulation can use wallclock-time from an external source.
 */
#include "device_factory.h"
#include "guest.h"
#include "device.h"
#include "io_device.h"
#include "timer.h"
#include "irq_dt.h"

#include "../device/rtc-hub.h"

#include <time.h>
#include <errno.h>

#include <l4/bid_config.h>

namespace Vdev {

class Rtc :
  public Vdev::Timer,
  public Vdev::Pm_device,
  public Vmm::Io_device,
  public Vdev::Device
{
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
    Ram_size = Ram_end - Ram_start,
  };

  enum Status_reg_c : l4_uint8_t
  {
    Interrupt_request           = 0x80,
    Periodic_interrupt_flag     = 0x40,
    Alarm_interrupt_flag        = 0x20,
    Update_ended_interrupt_flag = 0x10,
  };

  enum Status_reg_d : l4_uint8_t
  {
    Valid_ram_and_time = 0x80,
  };

  struct Status_reg_a
  {
    l4_uint8_t reg = 0;
    CXX_BITFIELD_MEMBER(0, 3, rate_selection_bits, reg);
    CXX_BITFIELD_MEMBER(4, 6, divider_selection_bits, reg);
    CXX_BITFIELD_MEMBER(7, 7, update_in_progress, reg);
  };

  struct Status_reg_b
  {
    l4_uint8_t reg = 0x2; // mode_24 == 1
    CXX_BITFIELD_MEMBER(0, 0, daylight_savings_enable, reg);
    CXX_BITFIELD_MEMBER(1, 1, mode_24, reg);
    CXX_BITFIELD_MEMBER(2, 2, data_mode, reg);
    CXX_BITFIELD_MEMBER(3, 3, square_wave_enable, reg);
    CXX_BITFIELD_MEMBER(4, 4, update_ended_interrupt_enable, reg);
    CXX_BITFIELD_MEMBER(5, 5, alarm_interrupt_enable, reg);
    CXX_BITFIELD_MEMBER(6, 6, periodic_interrupt_enable, reg);
    CXX_BITFIELD_MEMBER(7, 7, set, reg);
  };

  struct Alarm : public L4::Ipc_svr::Timeout_queue::Timeout
  {
    Rtc *_rtc;

    Alarm(Rtc *rtc) : _rtc(rtc) {}

    /**
     * Handle expired alarms.
     *
     * This function is called from the timer thread.
     */
    void expired() override
    {
      if (!_rtc->_reg_b.alarm_interrupt_enable())
        {
          trace().printf("Alarm interrupt but alarm interrupt enable not set.\n");
          return;
        }
      {
        std::lock_guard<std::mutex> lock(_rtc->_mutex);

        _rtc->_reg_c |= Alarm_interrupt_flag;
        _rtc->_reg_c |= Interrupt_request;
      }
      trace().printf("RTC Irq due to alarm expired()\n");
      _rtc->_sink.inject();
    }
  }; // struct Alarm

  // allow Alarm access to private Rtc members.
  friend struct Alarm;

  // convert internal binary representation to BCD if needed
  l4_uint32_t convert_to_guest(int val)
  {
    if (_reg_b.data_mode())
      return val;

    // See https://de.wikipedia.org/wiki/BCD-Code
    return (val % 10) + ((val / 10) << 4);
  }

  // convert what the guest gave us to internal binary representation
  l4_uint8_t convert_from_guest(l4_uint8_t val)
  {
    if (_reg_b.data_mode()) // we are using binary mode
      return val;

    return (val & 0xf) + ((val & 0xf0) >> 4) * 10;
  }

  void handle_set_time(Status_reg_b r)
  {
    // As long as the set() bit is set, the guest assumes that the clock does
    // not update. We redirect all writes to shadow registers, and those
    // never get updated.

    // The strategy for updating is:
    // - the guest sets the set bit to 1
    // - the guest writes the new time value to the shadow registers
    // - the guest sets the set bit to 0
    // - once the set bit is 0, Uvmm retrieves the new time value from the
    //   shadow registers and updates its internal time.
    bool old_set_bit = _reg_b.set().get();
    bool new_set_bit = r.set().get();

    if (!old_set_bit || new_set_bit)
      return;

    time_t seconds = ns_to_s(L4rtc_hub::ns_since_epoch());
    struct tm *t = gmtime(&seconds);
    if (!t)
      {
        warn().printf("Could not determine time.\n");
        return;
      }
    t->tm_sec = _shadow_registers[Seconds];
    t->tm_min = _shadow_registers[Minutes];
    t->tm_hour = _shadow_registers[Hours];
    t->tm_mday = _shadow_registers[Day_of_month];
    t->tm_mon = _shadow_registers[Month] - 1;   // months start at '1'
    int centuries_since_1900 = t->tm_year / 100 * 100;
    // tm_year is defined as 'years since 1900'. The RTC spec instead
    // specifies the Year register as 'year in the range of 0-99'. Here we use
    // the previous centuries since 1900 (as calculated from "seconds since
    // epoch") and add them to the register value from the guest.
    t->tm_year = _shadow_registers[Year] + centuries_since_1900;

    _seconds = timegm(t);
    L4rtc_hub::set_ns_since_epoch(s_to_ns(_seconds));

    trace().printf("set time to %04d-%02d-%02d %02d:%02d:%02d\n",
                   t->tm_year + 1900, t->tm_mon, t->tm_mday,
                   t->tm_hour, t->tm_min, t->tm_sec);
  }

  // return next timeout in seconds
  time_t calc_next_alarm()
  {
    time_t seconds = ns_to_s(L4rtc_hub::ns_since_epoch());
    struct tm *alarm_time = gmtime(&seconds);
    struct tm *current_time = gmtime(&seconds);

    if (dont_care_not_set(_shadow_registers[Seconds_alarm]))
      alarm_time->tm_sec = _shadow_registers[Seconds_alarm];
    else
      {
        trace().printf("wildcard seconds\n");
        alarm_time->tm_sec += 1;
        alarm_time->tm_sec %= 60;
      }
    if (dont_care_not_set(_shadow_registers[Minutes_alarm]))
      alarm_time->tm_min = _shadow_registers[Minutes_alarm];
    else
      {
        trace().printf("wildcard minutes\n");
        alarm_time->tm_min += 1;
        alarm_time->tm_min %= 60;
      }
    if (dont_care_not_set(_shadow_registers[Hours_alarm]))
      alarm_time->tm_hour = _shadow_registers[Hours_alarm];
    else
      {
        trace().printf("wildcard hours\n");
        alarm_time->tm_hour += 1;
        alarm_time->tm_hour %= 24;
      }

    time_t alarm_seconds = mktime(alarm_time);
    if (alarm_seconds == -1)
      trace().printf("error calculating alarm_seconds. Errno %i\n", errno);

    time_t current_seconds = mktime(current_time);
    if (current_seconds == -1)
      trace().printf("error calculating current_seconds. Errno %i\n", errno);

    if (alarm_seconds < current_seconds)
      {
        trace().printf("Alarm is in the past\n");
        return ~0L;
      }

    trace().printf("alarm_seconds=%ld current_seconds=%ld\n", alarm_seconds,
                   current_seconds);
    return (alarm_seconds - current_seconds);
  }

  void handle_alarms(Status_reg_b r)
  {
    time_t next_alarm = 0;
    {
      std::lock_guard<std::mutex> lock(_mutex);

      if (r.update_ended_interrupt_enable())
        {
          trace().printf("Guest wants an update interrupt.\n");
          l4_cpu_time_t current_second = ns_to_s(l4_tsc_to_ns(l4_rdtsc()));
          _reg_c |= Update_ended_interrupt_flag;
          if (current_second > _previous_alarm_second)
            {
              _previous_alarm_second = current_second;
              _reg_c |= Interrupt_request;
              _sink.inject();
              trace().printf("Update ended interrupt injected immediately\n");
            }
        }

      if (!r.alarm_interrupt_enable())
        return;

      trace().printf("Guest wants an alarm interrupt.\n");

      next_alarm = calc_next_alarm();
      if (next_alarm == ~0L) // do not fire for alarms of the past
        return;

      if (next_alarm == 0) // guest wants an alarm right now
        {
          l4_cpu_time_t current_second = ns_to_s(l4_tsc_to_ns(l4_rdtsc()));
          _reg_c |= Alarm_interrupt_flag;
          _reg_c |= Interrupt_request;
          if (current_second > _previous_alarm_second)
            {
              _previous_alarm_second = current_second;
              _sink.inject();
              trace().printf("Alarm interrupt injected immediately\n");
            }
          return;
        }
    }

    // guest alarm is at least 1 second in the future
    // must not hold the lock when doing the IPC to the timer thread
    enqueue_timeout(&_alarm_timeout,
                    l4_kip_clock(l4re_kip()) + s_to_us(next_alarm));
    trace().printf("enqueue timeout %ld\n", next_alarm);
  }

  void handle_write(l4_uint32_t value)
  {
    trace().printf("write reg %d value = 0x%x\n", _reg_sel, value & 0xff);
    l4_uint8_t val = value & 0xff;
    switch (_reg_sel)
      {
      case Status_a:
        {
          std::lock_guard<std::mutex> lock(_mutex);
          trace().printf("reg a: 0x%x\n", val);
          _reg_a.reg = val;
        }
        break;
      case Status_b:
        {
          trace().printf("reg b: 0x%x\n", val);
          Status_reg_b r;
          r.reg = val;

          // set_time() and alarms() handle the lock themselves
          handle_set_time(r);
          handle_alarms(r);
          {
            std::lock_guard<std::mutex> lock(_mutex);
            _reg_b.reg = val;
            // we only allow mode_24
            _reg_b.mode_24().set(1);
          }
        }
        break;
      case Reg_c:
      case Reg_d:
        warn().printf("Write to RO reg (%u)\n", _reg_sel);
        break;
      default:
        if (_reg_sel <= Year)
          _shadow_registers[_reg_sel] = convert_from_guest(val);
        else if (_reg_sel >= Ram_start && _reg_sel < Ram_end)
          cmos_write(_reg_sel - Ram_start, val);
        else
          warn().printf("Register write not handled (%u)\n", _reg_sel);
        break;
      }
  }

  l4_uint32_t handle_read()
  {
    trace().printf("read reg %d\n", _reg_sel);
    // these registers need to always work
    switch (_reg_sel)
      {
      case Status_a:
        {
          std::lock_guard<std::mutex> lock(_mutex);
          return _reg_a.reg;
        }
      case Status_b:
        {
          std::lock_guard<std::mutex> lock(_mutex);
          return _reg_b.reg;
        }
      case Reg_c:
        {
          std::lock_guard<std::mutex> lock(_mutex);
          unsigned ret = _reg_c;
          trace().printf("reg c: %x\n", _reg_c);
          // reading clears the status bits
          _reg_c = 0;
          _sink.ack();
          return ret;
        }
      case Reg_d:
        return Valid_ram_and_time;
      }

    // only update time if guest does not currently try to set a new time
    if (!_reg_b.set())
      _seconds = ns_to_s(L4rtc_hub::ns_since_epoch());

    struct tm *t = gmtime(&_seconds);
    if (!t)
      {
        warn().printf("Could not determine time.\n");
        return 0;
      }

    l4_uint32_t ret = 0;
    switch (_reg_sel)
      {
      case Seconds:
        ret = convert_to_guest(t->tm_sec);
        break;
      case Seconds_alarm:
        ret = convert_to_guest(_shadow_registers[Seconds_alarm]);
        break;
      case Minutes:
        ret = convert_to_guest(t->tm_min);
        break;
      case Minutes_alarm:
        ret = convert_to_guest(_shadow_registers[Minutes_alarm]);
        break;
      case Hours:
        ret = convert_to_guest(t->tm_hour);
        break;
      case Hours_alarm:
        ret = convert_to_guest(_shadow_registers[Hours_alarm]);
        break;
      case Weekday:
        ret = convert_to_guest(t->tm_wday);
        break;
      case Day_of_month:
        ret = convert_to_guest(t->tm_mday);
        break;
      case Month:
        ret = convert_to_guest(t->tm_mon + 1); // gmtime returns months counting from zero
        break;
      case Year:
        ret = convert_to_guest(t->tm_year % 100);
        break;
      default:
        if (Ram_start > _reg_sel || _reg_sel > Ram_end)
          warn().printf("Unknown register read (%d)\n", _reg_sel);
        else
          ret = cmos_read(_reg_sel - Ram_start);
        break;
      }
    return ret;
  }

public:
 Rtc(cxx::Ref_ptr<Gic::Ic> const &ic, int irq)
 : Pm_device(), _alarm_timeout(this), _sink(ic, irq), _previous_alarm_second(0)
  {
    info().printf("Hello from RTC. Irq=%d\n", irq);
#if !defined(CONFIG_UVMM_EXTERNAL_RTC) and !(CONFIG_RELEASE_MODE)
    warn().printf(
      "No external clock source. Rtc time will not represent wallclock time.\n"
      "Set CONFIG_UVMM_EXTERNAL_CLOCK = y if you have an external clock "
      "source.\n");
#endif

    _seconds = ns_to_s(L4rtc_hub::ns_since_epoch());
  }

  void pm_suspend() override
  {}

  void pm_resume() override
  {
    // tell the guest that the machine has resumed from suspend
    // use the PS/2 shutdown status byte as expected by firmware
    cmos_write(1, 0xfe);
  }

  char const *dev_name() const override
  { return "RTC"; }

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
  {
    dequeue_timeout(&_alarm_timeout);
  }

private:
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "RTC"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "RTC"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "RTC"); }

  static l4_uint64_t ns_to_s(l4_uint64_t ns) { return ns / 1'000'000'000; }
  static l4_uint64_t s_to_us(l4_uint64_t s) { return s * 1'000'000; }
  static l4_uint64_t s_to_ns(l4_uint64_t s) { return s * 1'000'000'000; }

  /// Alarm registers with the highest bits set (0xC0 - 0xFF) are don't care.
  static bool dont_care_not_set(l4_uint8_t reg)
  {
    enum { Dont_care_bits = 0xC0 };
    return (reg & Dont_care_bits) != Dont_care_bits;
  }

  void cmos_write(l4_uint8_t regsel, l4_uint16_t value)
  {
    assert(regsel < Ram_size);
    trace().printf("cmos write(%u, 0x%x)\n", regsel, value);
    _cmos[regsel] = value;
  }

  l4_uint16_t cmos_read(l4_uint8_t regsel)
  {
    assert(regsel < Ram_size);
    trace().printf("cmos read(%u) = 0x%x\n", regsel, _cmos[regsel]);
    return _cmos[regsel];
  }

  l4_uint8_t _reg_sel = 0;
  Status_reg_a _reg_a;
  Status_reg_b _reg_b;
  l4_uint8_t _reg_c = 0;
  l4_uint8_t _reg_d = 0;

  // These are written to by the guest.
  l4_uint8_t _shadow_registers[Year + 1];

  // protect members from concurrent access
  std::mutex _mutex;

  Alarm _alarm_timeout; //< Object handling timeout expired events.

  // seconds since epoch as determined by external clock source
  time_t _seconds;

  l4_uint16_t _cmos[Ram_size];

  Vmm::Irq_sink _sink;
  l4_cpu_time_t _previous_alarm_second;
}; // class Rtc

} // namespace Vdev

namespace {

struct F : Vdev::Factory
{
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "RTC"); }

  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) < 0)
      return nullptr;

    if (!it.ic_is_virt())
      {
        info().printf("RTC requires a virtual interrupt controller.");
        return nullptr;
      }

    if (it.irq() != 8)
      {
        info().printf("DT Node must specify IRQ 8 for the RTC.");
        return nullptr;
      }

    auto dev = Vdev::make_device<Vdev::Rtc>(it.ic(), it.irq());

    auto region = Vmm::Io_region(0x70, 0x71, Vmm::Region_type::Virtual);
    devs->vmm()->add_io_device(region, dev);
    devs->vmm()->register_timer_device(dev);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"virt-rtc", nullptr, &f};

} // namespace
