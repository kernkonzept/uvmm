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

#include "device.h"
#include "io_device.h"
#include "irq.h"
#include "timer.h"

namespace Vdev {

/**
 * Limited implementation of 8254 PROGRAMMABLE INTERVAL TIMER.
 *
 * Supports only channel 0 and 2.
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
  struct Port61 : public Vmm::Io_device
  {
    l4_uint8_t val = 0;
    void io_in(unsigned, Vmm::Mem_access::Width, l4_uint32_t *value) override
    {
      *value = val;
      val &= ~(1 << 5); // destructive read
    }

    void io_out(unsigned, Vmm::Mem_access::Width, l4_uint32_t value) override
    { val = value & 0xff; }

    bool channel_2_on() const { return val & 0x1; }
    void set_output() { val |= (1 << 5); }
  };

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

    Read_back_cmd = 3,
    Read_back_latch_0 = 1,
    Read_back_latch_2 = (1 << 2),
    Read_back_latch_cnt = 2,
    Access_lobyte = 1,
    Access_hibyte = 2,
    Access_lohi = 3,
  };

  class Channel: public L4::Ipc_svr::Timeout_queue::Timeout
  {
  public:
    enum Mode : l4_uint8_t
    {
      Mode_terminal_count = 0x0,
      Mode_retriggerable_one_shot = 0x1,
      Mode_rate_generator = 0x2,
      Mode_disabled = 0xff,
    };

    Channel(Pit_timer *pit, bool is_channel2 = false)
    : _reload(0), _op_mode(Mode_disabled), _irq_on(false), _pit(pit),
      _is_channel2(is_channel2), _reload_kip_clock(0)
    {}

    /**
     * Next absolute timeout in microseconds.
     */
    inline l4_cpu_time_t next_timeout_us() const
    {
      assert(_reload != 0);

      l4_kernel_clock_t kip = l4_kip_clock(l4re_kip());
      l4_cpu_time_t timeout_us =
        _reload * Microseconds_per_second / Pit_tick_rate;
      return kip + timeout_us;
    }

    // called in the context of the timer thread, be careful with locking!
    void expired()
    {
      if (_is_channel2 && _pit->_port61->channel_2_on())
        _pit->_port61->set_output();

      _pit->_irq.inject();

      // only rate generator mode is periodic
      if (_op_mode == Mode_rate_generator)
        _pit->requeue_timeout(this, next_timeout_us());
    }

    /**
     * Load the counter with new value
     *
     * \param new_reload  Value to count down from.
     */
    void reset(l4_uint16_t new_reload)
    {
      _reload = new_reload;
      _reload_kip_clock = l4_kip_clock(l4re_kip());
      disable_irq();
    }

    void op_mode(Mode m)
    {
      assert(m < 8);
      _op_mode = m;
      disable_irq();
    }

    void reset_op_mode()
    {
      disable_irq();
      _op_mode = Mode_disabled;
    }

    void disable_irq()
    {
      _pit->dequeue_timeout(this);
    }

    void enable_irq()
    {
      if (_reload)
        _pit->enqueue_timeout(this, next_timeout_us());
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
      l4_cpu_time_t diff_us = _reload_kip_clock - kip_us;
      // return current counter value
      l4_uint32_t ticks = diff_us * Pit_tick_rate / Microseconds_per_second;
      if (ticks >= _reload)
        return 0;
      return _reload - ticks;
    }

  private:
    l4_uint16_t _reload;
    Mode _op_mode;
    bool _irq_on;
    Pit_timer *_pit;
    bool _is_channel2;
    l4_cpu_time_t _reload_kip_clock;
  };

  struct Control_reg
  {
    l4_uint8_t raw;
    CXX_BITFIELD_MEMBER(6, 7, channel, raw);
    CXX_BITFIELD_MEMBER(4, 5, access, raw);
    CXX_BITFIELD_MEMBER(1, 3, opmode, raw);
    CXX_BITFIELD_MEMBER(0, 0, bcd, raw);
  };

  bool is_latch_count_value_cmd(Control_reg m) const
  {
    return !(m.raw & Latch_cmd_null_mask);
  }

  bool is_current_channel(Control_reg m, int port) const
  {
    return m.channel() == port;
  }

  static constexpr int port2idx(int port) { return port >> 1; }

  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "PIT"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "PIT"); }

public:
  Pit_timer(cxx::Ref_ptr<Gic::Ic> const &ic, int irq);
  virtual ~Pit_timer() = default;

  cxx::Ref_ptr<Vmm::Io_device> const port61() const { return _port61; }

  void io_out(unsigned port, Vmm::Mem_access::Width width,
              l4_uint32_t value) override;
  void io_in(unsigned port, Vmm::Mem_access::Width width,
             l4_uint32_t *value) override;

private:
  Vmm::Irq_edge_sink _irq;
  l4_uint16_t _reload;
  cxx::unique_ptr<Channel> _channel[Channels];
  bool _read_high;
  bool _wait_for_high_byte;
  Control_reg _control_reg;
  std::mutex _mutex;
  cxx::Ref_ptr<Port61> const _port61;

  void set_high_byte(l4_uint16_t &reg, l4_uint8_t value);
  void set_low_byte(l4_uint16_t &reg, l4_uint8_t value);
};

} // namespace Vdev
