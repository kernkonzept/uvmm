/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
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
  _channel[0] = cxx::make_unique_ptr<Channel>(new Channel(this));
  _channel[1] = cxx::make_unique_ptr<Channel>(new Channel(this, true));
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
      _control_reg.raw = value;
      if (_control_reg.channel() == 1)
        {
          warn().printf("set mode for channel 1 unsupported\n");
          return;
        }
      int ch = _control_reg.channel() >> 1;

      if (   is_latch_count_value_cmd(_control_reg)
          || (   _control_reg.channel() == Read_back_cmd
              && _control_reg.access() == Read_back_latch_cnt))
        {
          // We don't emulate the latch register
          warn().printf("UNIMPLEMENTED: latch register programmed.\n");
          break;
        }
      else
        _channel[ch]->reset_op_mode();

      _channel[ch]->op_mode(static_cast<Channel::Mode>(_control_reg.opmode().get()));
      trace().printf("New timer mode on channel %d: 0x%x\n",
                     ch, _control_reg.opmode().get());
      break;
    }
    case Channel_0_data:
    case Channel_2_data:
      trace().printf("Writing 0x%x for channel %d\n", value,
                     port);
      if (!is_latch_count_value_cmd(_control_reg)
          && is_current_channel(_control_reg, port))
        {
          unsigned ch = port2idx(port);
          unsigned v = value & 0xFF;

          if (_control_reg.access() == Access_lohi)
            {
              if (_wait_for_high_byte)
                {
                  set_high_byte(_reload, v);
                  _wait_for_high_byte = false;
                  _channel[ch]->reset(_reload);
                  _channel[ch]->enable_irq();
                }
              else
                {
                  // lobyte first
                  set_low_byte(_reload, v);
                  _channel[ch]->disable_irq();
                  // wait for sequential write to high byte
                  _wait_for_high_byte = true;
                  return;
                }
            }
          else if (_control_reg.access() == Access_lobyte)
            set_low_byte(_reload, v);
          else if (_control_reg.access() == Access_hibyte)
            {
              set_high_byte(_reload, v);
              _channel[ch]->reset(_reload);
              _channel[ch]->enable_irq();
            }

          trace().printf("set counter for %d to %d\n", ch, _reload);
        }
      else
        warn().printf("PIT access to bad channel\n");
      break;
  }
}

void Pit_timer::io_in(unsigned port, Vmm::Mem_access::Width width,
                      l4_uint32_t *value)
{
  // *value contains the value returned to the guest. It defaults to -1 from
  // Guest::handle_io_access(). Therefore we do not set it here in case of an
  // unhandled path.

  if (width != Vmm::Mem_access::Width::Wd8)
    return;

  switch (port)
    {
    case Mode_command: *value = _control_reg.raw; break;

    case Channel_0_data:
    case Channel_2_data:
      {
        l4_uint16_t reg;
        int ch = port2idx(port);

        std::lock_guard<std::mutex> lock(_mutex);
        reg = _channel[ch]->current();

        switch (_control_reg.access())
          {
          case Access_lobyte: *value = reg & 0xff; break;
          case Access_hibyte: *value = (reg >> 8) & 0xff; break;
          case Access_lohi:
            *value = _read_high ? (reg >> 8) : (reg & 0xFF);
            _read_high = !_read_high;
            break;
          default:
            warn().printf("Invalid access mode during read: Mode: 0x%x\n",
                          _control_reg.raw);
            break;
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

    auto dev = Vdev::make_device<Vdev::Pit_timer>(it.ic(), it.irq());

    auto *vmm = devs->vmm();
    auto region = Vmm::Io_region(0x40, 0x43, Vmm::Region_type::Virtual);
    vmm->add_io_device(region, dev);
    region = Vmm::Io_region(0x61, 0x61, Vmm::Region_type::Virtual);
    vmm->add_io_device(region, dev->port61());
    vmm->register_timer_device(dev);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"virt-pit", nullptr, &f};

} // namespace
