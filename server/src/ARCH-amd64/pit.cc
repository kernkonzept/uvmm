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

Pit_timer::Pit_timer(cxx::Ref_ptr<Gic::Ic> const &ic, int irq)
: _irq(ic, irq),
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

      if (   is_latch_count_value_cmd(_mode)
          || (   _mode.channel() == Read_back_cmd
              && _mode.access() == Read_back_latch_cnt))
        {
          // We don't emulate the latch register
          break;
        }
      else
        _channel[ch].reset_op_mode();

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
                  set_high_byte(_reload, v);
                  _wait_for_high_byte = false;
                }
              else
                {
                  // lobyte first
                  set_low_byte(_reload, v);
                  // wait for sequential write to high byte
                  _wait_for_high_byte = true;
                  return;
                }
            }
          else if (_mode.access() == Access_lobyte)
            set_low_byte(_reload, v);
          else if (_mode.access() == Access_hibyte)
            set_high_byte(_reload, v);

          trace().printf("set counter for %d to %d\n", port, _reload);
          _channel[ch].reset(l4_rdtsc(), _reload);
          if (_reload != 0)
            _channel[ch].op_mode(_mode.opmode());
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
            std::lock_guard<std::mutex> lock(_mutex);

            unsigned wraps = _channel[ch].update(l4_rdtsc());

            if (_channel[ch].one_shot_mode() && wraps > 0)
              reg = 0;
            else
              reg = _channel[ch].current();
          }
        else
          {
            std::lock_guard<std::mutex> lock(_mutex);
            reg = _channel[ch].current();
          }

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

void Pit_timer::tick()
{
  std::lock_guard<std::mutex> lock(_mutex);

  auto now = l4_rdtsc();
  bool trigger = _channel[0].tick(now);

  if (_port61->channel_2_on() && _channel[1].tick(now))
    {
      trigger = true;
      _port61->set_output();
    }

  if (trigger)
    _irq.inject();
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

    auto dev = Vdev::make_device<Vdev::Pit_timer>(it.ic(), it.irq());

    auto *vmm = devs->vmm();
    auto region = Vmm::Io_region(0x40, 0x43, Vmm::Region_type::Virtual);
    vmm->register_io_device(region, dev);
    region = Vmm::Io_region(0x61, 0x61, Vmm::Region_type::Virtual);
    vmm->register_io_device(region, dev->port61());
    vmm->register_timer_device(dev);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"virt-pit", nullptr, &f};

} // namespace
