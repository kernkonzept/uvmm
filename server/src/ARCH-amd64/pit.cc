/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <l4/cxx/utils>

#include <l4/re/error_helper>

#include "pit.h"

namespace Vdev {

Pit_timer::Pit_timer() : _port61(make_device<Port61>())
{
  _ch_mode[0] = -1;
  _ch_mode[1] = -1;
  _wait_for_high_byte = false;
}

void Pit_timer::init_device(Vdev::Device_lookup const *devs,
                            Vdev::Dt_node const &self)
{
  auto irq_parent = self.find_irq_parent();
  if (!irq_parent.is_valid())
    L4Re::chksys(-L4_ENODEV, "No interrupt handler found for PIT.\n");

  auto *ic = dynamic_cast<Gic::Ic *>(devs->device_from_node(irq_parent).get());

  if (!ic)
    L4Re::chksys(-L4_ENODEV, "Interrupt handler for PIT has bad type.\n");

  _irq.rebind(ic, Pit_irq_line);
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
          Dbg().printf("WARNING: set mode for channel 1 unsupported\n");
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

      Dbg().printf("!!! PIT !!!   New timer mode: 0x%x\n", value);
      break;
    }
    case Channel_0_data:
    case Channel_2_data:
      Dbg().printf("!!! PIT !!!   Writing 0x%x for channel %d\n", value,
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

          Dbg().printf("!!! PIT !!!   enable counter for %d\n", port);
          _counter[ch] = _reload[ch] >> 2;
          if (_reload[ch] != 0)
            _ch_mode[ch] = _mode.access();
        }
      else
        Dbg().printf("WARNING: PIT access to bad channel\n");
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
  case Mode_command:
    *value = _mode.raw;
    break;
  case Channel_0_data:
  case Channel_2_data:
    {
      l4_uint16_t reg = _counter[port2idx(port)] << 2;
      *value = _read_high ? (reg >> 8) : (reg & 0xFF);
      _read_high = !_read_high;
      break;
    }
  }
}

void Pit_timer::tick()
{
  std::lock_guard<std::mutex> lock(_mutex);

  if (_ch_mode[0] != 0xFF)
    {
      if (_ch_mode[0] <= 1 && _counter[0] == 0)
          _irq.inject();

      if (_ch_mode[0] > 1)
        {
// Note: The PIT sets the level of the IRQ line to low. This is not reflected
// by this implementation.
          _irq.inject();
        }

      _counter[0]--;
    }

  if (_ch_mode[1] != 0xFF)
    {
      _counter[1]--;

      if (_ch_mode[1] > 1 && _counter[1] == 0xFFFF)
        _counter[1] = _reload[1];

      if(_counter[1] == 0)
        {
          _irq.inject();
          _port61->val |= (1 << 5);
        }
    }
}

} // namespace Vdev

#include "device_factory.h"
#include "guest.h"

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup const *devs,
                                    Vdev::Dt_node const &) override
  {
    auto dev = Vdev::make_device<Vdev::Pit_timer>();

    auto *vmm = devs->vmm();
    vmm->register_io_device(dev, 0x40, 0x4);
    vmm->register_io_device(dev->port61(), 0x61, 0x1);
    vmm->register_timer_device(dev);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"virt-pit", nullptr, &f};

} // namespace



