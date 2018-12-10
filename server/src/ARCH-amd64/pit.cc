/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/re/error_helper>
#include <l4/re/env.h> // l4re_kip

#include "irq_dt.h"
#include "pit.h"

namespace Vdev {

Pit_timer::Pit_timer(Gic::Ic *ic, int irq)
: _irq(ic, irq), _ch_mode {0xff, 0xff},
  _read_high(false), _wait_for_high_byte(false),
  _port61(make_device<Port61>())
{
  l4_tsc_init(L4_TSC_INIT_AUTO, l4re_kip());
}

void Pit_timer::set_high_byte(l4_uint16_t &reg, l4_uint8_t value)
{
  reg = (reg & Low_byte_mask) | (value << High_byte_shift);
}

void Pit_timer::set_low_byte(l4_uint16_t &reg, l4_uint8_t value)
{
  reg = (reg & High_byte_mask) | value;
}

void Pit_timer::io_out(unsigned port, Vmm::Mem_access::Width width,
                       l4_uint32_t value)
{
  if (width != Vmm::Mem_access::Width::Wd8)
    return;

  std::lock_guard<std::mutex> lock(_mutex);

  switch (port)
  {
    case Mode_command : // PIC_MODE
    {
      _mode.raw = value;
      if (_mode.channel() == 1)
        {
          warn().printf("set mode for channel 1 unsupported\n");
          return;
        }
      int ch = _mode.channel() >> 1;

      if (is_latch_count_value_cmd(_mode))
        {
          _latch[ch] = _counter[ch];
        }
      else if ((_mode.channel() == Read_back_cmd
                && _mode.access() == Read_back_latch_cnt))
        {
          if (_mode.opmode() == Read_back_latch_0)
            _latch[0] = _counter[0];
          if (_mode.opmode() == Read_back_latch_2)
            _latch[1] = _counter[1];
        }
      else
        _ch_mode[ch] = 0xFF;

      trace().printf("New timer mode: 0x%x\n", value);
      break;
    }
    case Channel_0_data:
    case Channel_2_data:
      trace().printf("Writing 0x%x for channel %d\n", value,
                   port);
      if (!is_latch_count_value_cmd(_mode) && is_current_channel(_mode, port))
        {
          unsigned ch = port2idx(port);
          unsigned v = value & 0xFF;

          if (_mode.access() == Access_lohi)
            {
              if (_wait_for_high_byte)
                {
                  set_high_byte(_reload[ch], v);
                  _wait_for_high_byte = false;
                }
              else
                {
                  // lobyte first
                  set_low_byte(_reload[ch], v);
                  // wait for sequential write to high byte
                  _wait_for_high_byte = true;
                  return;
                }
            }
          else if (_mode.access() == Access_lobyte)
            set_low_byte(_reload[ch], v);
          else if (_mode.access() == Access_hibyte)
            set_high_byte(_reload[ch], v);

          trace().printf("enable counter for %d\n", port);
          _counter[ch] = _reload[ch];
          if (_reload[ch] != 0)
            _ch_mode[ch] = _mode.opmode();

          _tsc_start[ch] = l4_rdtsc();
        }
      else
        warn().printf("PIT access to bad channel\n");
      break;
  }
}

void Pit_timer::io_in(unsigned port, Vmm::Mem_access::Width width,
                      l4_uint32_t *value)
{
  if (width != Vmm::Mem_access::Width::Wd8)
    return;

  switch (port)
    {
    case Mode_command: *value = _mode.raw; break;

    case Channel_0_data:
    case Channel_2_data:
      {
        l4_uint16_t reg;
        int ch = port2idx(port);

        if (!_read_high)
          {
            // take current time
            auto now = l4_rdtsc();
            auto diff_ns = l4_tsc_to_ns(now - _tsc_start[ch]);
            // ns / Hz
            l4_uint32_t pit_period_len = 1000UL * 1000 * 1000 / Pit_tick_rate;
            l4_uint32_t ticks = diff_ns / pit_period_len;

            {
              std::lock_guard<std::mutex> lock(_mutex);

              if (_ch_mode[ch] <= 1 && ticks / _reload[ch] >= 1)
                reg = 0;
              else
                reg = _counter[ch] - (l4_uint16_t)(ticks % _reload[ch]);

              // use latch to store the computed counter value to allow for
              // consistent reads of high an low bytes.
              _latch[ch] = reg;
            }
          }
        else
          reg = _latch[ch];

        switch (_mode.access())
          {
          case Access_lobyte: *value = reg & 0xff; break;

          case Access_hibyte: *value = (reg >> 8) & 0xff; break;

          case Access_lohi:
            *value = _read_high ? (reg >> 8) : (reg & 0xFF);
            _read_high = !_read_high;
            break;

          default:
            warn().printf("Invalid access mode during read: Mode: 0x%x\n",
                          _mode.raw);
          }
      }
    }
}

} // namespace Vdev

#include "device_factory.h"
#include "guest.h"

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) < 0)
      return nullptr;

    if (!it.ic_is_virt())
      L4Re::chksys(-L4_EINVAL, "PIT requires a virtual interrupt controller");

    auto dev = Vdev::make_device<Vdev::Pit_timer>(it.ic().get(), it.irq());

    auto *vmm = devs->vmm();
    vmm->register_io_device(Vmm::Io_region(0x40, 0x43), dev);
    vmm->register_io_device(Vmm::Io_region(0x61, 0x61), dev->port61());

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"virt-pit", nullptr, &f};

} // namespace
