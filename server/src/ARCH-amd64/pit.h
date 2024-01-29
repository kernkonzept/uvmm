/*
 * Copyright (C) 2017-2020, 2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <mutex>
#include <l4/cxx/bitfield>
#include <l4/cxx/unique_ptr>
#include <l4/re/env.h>

#include "device.h"
#include "io_device.h"
#include "irq.h"
#include "timer.h"

namespace Vdev {

/**
 * Limited implementation of 8254 PROGRAMMABLE INTERVAL TIMER.
 *
 * Supports only channel 0 and 2.
 * After a read-back command with status field, the following bits in the
 * status field latched are not supported: OUTPUT [7], NULL COUNT [6].
 *
 * Modes 0-3 are supported for both counters.
 * Mode 4 is only useable on counter 0, for the triggered interrupt.
 * Mode 5 is not supported.
 *
 * Modes 4 and 5 are not supported for counter 2, because the single tick
 * change in output is not emulated and its questionable, if the emulation
 * would be precise enough to allow visiblity to the guest.
 *
 * \note This timer model uses the KIP clock as time base. You need to
 *       configure the Microkernel with CONFIG_SYNC_TSC in order to achieve
 *       sufficient granularity.
 */
class Pit_timer
: public Vmm::Io_device,
  public Vdev::Device,
  public Vdev::Timer
{
  enum
  {
    Channels = 2,
    Pit_tick_rate = 1193182, // given in Herz
    Microseconds_per_second = 1000000ULL,
    Channel_0_data = 0,
    Channel_2_data = 2,
    Mode_command = 3,

    Low_byte_mask = 0xff,
    High_byte_mask = 0xff00,
    High_byte_shift = 0x8,
    Latch_cmd_null_mask = 0x3f,
    Latch_cmd_channel_mask = 0xc0,

    Access_latch = 0,
    Access_lobyte = 1,
    Access_hibyte = 2,
    Access_lohi = 3,

    Mode_terminal_count = 0,
    Mode_hw_oneshot = 1,
    Mode_rate_gen = 2,
    Mode_rate_gen2 = 6,
    Mode_square_wave = 3,
    Mode_square_wave2 = 7,
    Mode_sw_triggerd_strobe = 4,
    // mode 5 unsupported.
    Mode_periodic_mask = 0x2,
  };

  class Channel: public L4::Ipc_svr::Timeout_queue::Timeout
  {
    struct Status
    {
      Status() : raw(0) {}
      Status(l4_uint8_t v) : raw(v) {}

      l4_uint8_t raw = 0;
      CXX_BITFIELD_MEMBER(7, 7, output, raw);
      CXX_BITFIELD_MEMBER(6, 6, count, raw);
      CXX_BITFIELD_MEMBER(4, 5, access, raw);
      CXX_BITFIELD_MEMBER(1, 3, opmode, raw);
      CXX_BITFIELD_MEMBER(0, 0, bcd, raw);

      enum
      {
        // Bits not changed on mode command
        Retain_mask = output_bfm_t::Mask | count_bfm_t::Mask
      };

      void write(l4_uint8_t val)
      { raw = (val & ~Retain_mask) | (raw & Retain_mask); }

      bool is_periodic_mode() const { return opmode() > Mode_hw_oneshot; }
      bool is_one_shot_mode() const { return !is_periodic_mode(); }

      bool is_mode0() const { return opmode() == Mode_terminal_count; }
      bool is_mode1() const { return opmode() == Mode_hw_oneshot; }
      bool is_mode2() const
      { return opmode() == Mode_rate_gen || opmode() == Mode_rate_gen2; }
      bool is_mode3() const
      { return opmode() == Mode_square_wave || opmode() == Mode_square_wave2; }
      bool is_mode4() const
      { return opmode() == Mode_sw_triggerd_strobe; }
    };

    struct Latch
    {
      void reset()
      {
        value = 0;
        valid = false;
        read_lo = true;
      }

      l4_uint16_t value = 0;
      bool valid = false;
      bool read_lo = true;
    };

  public:
    Channel(Pit_timer *pit, bool is_channel2 = false)
    : _is_channel2(is_channel2), _gate(!is_channel2), _pit(pit)
    {}

    // called in the context of the timer thread, be careful with locking!
    void expired()
    {
      // Unimplemented: mode2, 4, 5: output shall be low for one tick
      // the single-tick output change in modes 2, 4 & 5 is not emulated
      if (_status.is_mode3())
        {
          // Toggle output
          set_output(!_status.output());
        }
      else
        set_output(true);

      if(!_is_channel2)
        _pit->_irq.inject();

      if (_status.is_mode2() || _status.is_mode3())
        {
          _reload_kip_clock = l4_kip_clock(l4re_kip());
          if (_reload)
            _pit->requeue_timeout(this, next_timeout_us());
        }
      else
        {
          // The timer in the non periodic modes does not stop, but rolls over
          // and continues counting until gate is low or counter is set to 0.
          // Mode0 would not fire an interrupt again, since out is high until
          // reprogrammed. We don't emulate any of this and just stop.
          _running = false;
        }
    }

    void latch_count()
    {
      // ignore all but the first latch command
      if (_count_latch.valid)
        return;

      _count_latch.value = current();
      _count_latch.valid = true;
      _count_latch.read_lo = true;
    }

    void latch_status()
    {
      if (_status_latch.valid)
        return;

      _status_latch.value = _status.raw;
      _status_latch.valid = true;
    }

    void write_count(l4_uint8_t value);
    void write_status(l4_uint8_t value);
    l4_uint8_t read();

    bool gate() const { return _gate; }
    void gate(bool high)
    {
      // We know we are on channel 2, as only channel 2's gate can change.
      trace().printf("Channel 2: set gate to %i from %i\n", high, _gate);

      if (_status.is_mode0())
        {
          if (!high && _gate)
            stop_counter();
          else if (high && !_gate)
            start_counter();
          // XXX this reloads the counter, but it should stop counting and
          // continue after gate goes high again, unless output is high;
        }
      else if (_status.is_mode1())
        {
          if (high && !_gate) // retrigger
            {
              stop_counter();
              start_counter();
              set_output(false);
            }
        }
      else if (_status.is_mode2() || _status.is_mode3())
        {
          // the single-tick output change in modes 2, 4 & 5 is not emulated
          if (high && !_gate)
            {
              start_counter();
              set_output(true);
            }
          else if (!high && _gate)
            stop_counter();
        }
      // modes 4 & 5 not supported

      _gate = high;
    }

  private:
    static l4_uint8_t low_byte(l4_uint16_t v)
    { return v & Low_byte_mask; }

    static l4_uint8_t high_byte(l4_uint16_t v)
    { return (v >> High_byte_shift) & Low_byte_mask; }

    static l4_uint16_t set_high_byte(l4_uint16_t reg, l4_uint8_t value)
    { return (reg & Low_byte_mask) | (value << High_byte_shift); }

    static l4_uint16_t set_low_byte(l4_uint16_t reg, l4_uint8_t value)
    { return (reg & High_byte_mask) | value; }

    static l4_uint8_t read_lo_hi(bool *read_lo, l4_uint16_t count)
    {
      l4_uint8_t ret = 0;
      if (*read_lo)
          ret = low_byte(count);
      else
          ret = high_byte(count);

      *read_lo = !*read_lo;
      return ret;
    }

    void write_lo_hi(l4_uint8_t value)
    {
      if (_write_lo)
        _reload = set_low_byte(_reload, value);
      else
        {
          _reload = set_high_byte(_reload, value);
          check_start_counter();
        }

      _write_lo = !_write_lo;
    }

    void set_output(bool out)
    {
      _status.output() = out;
      if (_is_channel2)
        out ? _pit->_port61->set_out() : _pit->_port61->clear_out();
    }

    void start_counter()
    {
      _reload_kip_clock = l4_kip_clock(l4re_kip());
      if (_reload)
        {
          _pit->enqueue_timeout(this, next_timeout_us());
          trace().printf("start counter for channel %i (was %s)\n",
                         _is_channel2 ? 2 : 0,
                         _running ? "running" : "not running");
          _running = true;
        }
    }

    void stop_counter()
    {
      trace().printf("stop counter for channel %i (was %s), reload: 0x%x\n",
                     _is_channel2 ? 2 : 0, _running ? "running" : "not running",
                     _reload);
      _pit->dequeue_timeout(this);
      _running = false;
    }

    void check_start_counter();

    /**
     * Next absolute timeout in microseconds.
     */
    inline l4_cpu_time_t next_timeout_us() const
    {
      assert(_reload != 0);

      l4_kernel_clock_t kip = l4_kip_clock(l4re_kip());
      l4_cpu_time_t timeout_us =
        _reload * Microseconds_per_second / Pit_tick_rate;

      // square wave with half-time toggle
      if (_status.is_mode3())
        timeout_us /= 2;

      return kip + timeout_us;
    }

    /**
     * Calculate the current value of the counter.
     *
     * The counters count down from _reload with the fixed Pit_tick_rate.
     *
     * Our Pit model does not update the tick value by itself. Instead it only
     * calculates the tick count when the guest reads the counter register. We
     * use the TSC as time basis.
     *
     * returns the current counter value of this channel
     */
    l4_uint32_t current()
    {
      // current time in microseconds
      l4_kernel_clock_t kip_us = l4_kip_clock(l4re_kip());
      // time that has gone by since _reload was set
      l4_cpu_time_t diff_us =  kip_us - _reload_kip_clock;
      // return current counter value
      l4_uint32_t ticks = diff_us * Pit_tick_rate / Microseconds_per_second;
      if (_status.is_mode3())
        {
          // in mode3 the counter decrements by two on each tick, since we
          // compare to _reload, we have to double the number of counter
          // decrements. expired() is called on each half-period, where
          // _reload_kip_clock is adapted to track only the time since the last
          // reload.
          ticks *= 2;
        }

      if (ticks >= _reload)
        return 0;
      return _reload - ticks;
    }

    l4_uint16_t _reload = 0U;
    Status _status;
    bool _is_channel2;
    bool _gate; //< 0 = low
    bool _running = false;
    Latch _count_latch;
    Latch _status_latch;
    Pit_timer *_pit;
    l4_cpu_time_t _reload_kip_clock = 0ULL;
    bool _read_lo = true;
    bool _write_lo = true;
  };

  struct Port61 : public Vmm::Io_device
  {
    Port61(Channel *ch2) : _ch2(ch2) {}

    char const *dev_name() const override
    { return "PIT port 61"; }

    void io_in(unsigned, Vmm::Mem_access::Width, l4_uint32_t *value) override
    {
      *value = val;
      val &= ~(1 << 5); // destructive read
    }

    void io_out(unsigned, Vmm::Mem_access::Width, l4_uint32_t value) override
    {
      _ch2->gate(value & 0x1);
      val = value & 0xff;
    }

    bool channel_2_on() const { return val & 0x1; }
    void set_out() { val |= (1 << 5); }
    void clear_out() { val &= ~(1 << 5); }

    l4_uint8_t val = 0;
    Channel *_ch2;
  };

  struct Control_reg
  {
    Control_reg(l4_uint8_t val) : raw(val) {}

    l4_uint8_t raw;
    CXX_BITFIELD_MEMBER(6, 7, channel, raw);
    CXX_BITFIELD_MEMBER(4, 5, access, raw);
    CXX_BITFIELD_MEMBER(1, 3, opmode, raw);
    CXX_BITFIELD_MEMBER(0, 0, bcd, raw);

    bool is_read_back_cmd() const { return channel() == 3; }
    bool is_latch_status() const { return !(raw & (1U << 4)); }
    bool is_latch_count() const { return !(raw & (1U << 5)); }
  };

  static constexpr int port2idx(int port) { return port >> 1; }

  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "PIT"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "PIT"); }

public:
  Pit_timer(cxx::Ref_ptr<Gic::Ic> const &ic, int irq);
  virtual ~Pit_timer() = default;

  char const *dev_name() const override
  { return "PIT"; }

  cxx::Ref_ptr<Vmm::Io_device> const port61() const { return _port61; }

  void io_out(unsigned port, Vmm::Mem_access::Width width,
              l4_uint32_t value) override;
  void io_in(unsigned port, Vmm::Mem_access::Width width,
             l4_uint32_t *value) override;

private:
  Vmm::Irq_edge_sink _irq;
  cxx::unique_ptr<Channel> _channel[Channels];
  std::mutex _mutex;
  cxx::Ref_ptr<Port61> _port61;
};

} // namespace Vdev
