/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <l4/re/error_helper>

#include "irq_dt.h"
#include "pit.h"

namespace Vdev {

Pit_timer::Pit_timer(cxx::Ref_ptr<Gic::Ic> const &ic, int irq)
: _irq(ic, irq)
{
  _channel[0] = cxx::make_unique_ptr<Channel>(new Channel(this));
  _channel[1] = cxx::make_unique_ptr<Channel>(new Channel(this, true));
  _port61 = make_device<Port61>(_channel[1].get());
}

void Pit_timer::io_out(unsigned port, Vmm::Mem_access::Width width,
                       l4_uint32_t value)
{
  if (width != Vmm::Mem_access::Width::Wd8)
    return;

  std::lock_guard<std::mutex> lock(_mutex);

  switch (port)
    {
    case Mode_command: // PIC_MODE
      {
        Control_reg control_reg(value);
        unsigned channel_select = control_reg.channel();
        if (channel_select == 1)
          {
            warn().printf("set mode for channel 1 unsupported\n");
            break;
          }
        // select either channel 0 or 2
        channel_select = (channel_select >> 1) & 0x1;

        if (control_reg.is_read_back_cmd())
          {
            // read-back command
            if (control_reg.raw & (1U << 1)) // channel 0
              {
                if (control_reg.is_latch_status())
                  _channel[0]->latch_status();
                if (control_reg.is_latch_count())
                  _channel[0]->latch_count();
              }
            if (control_reg.raw & (1U << 3)) // channel 2
              {
                if (control_reg.is_latch_status())
                  _channel[2]->latch_status();
                if (control_reg.is_latch_count())
                  _channel[2]->latch_count();
              }
            trace().printf("Read-back command: 0x%x\n", control_reg.raw);
            break;
          }

        _channel[channel_select]->write_status(control_reg.raw
                                                            & 0x3f);
        trace().printf("Mode command on channel %d: 0x%x\n", channel_select,
                       control_reg.raw);
        break;
      }
    case Channel_0_data:
    case Channel_2_data:
      {
        trace().printf("Writing 0x%x for channel %d\n", value, port);

        unsigned channel_select = port2idx(port);
        _channel[channel_select]->write_count(value & 0xff);
        break;
      }
    default:
      warn().printf("write to unimplemented channel 1\n");
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
    case Mode_command: /* Register is write only. Ignore read. */ break;

    case Channel_0_data:
    case Channel_2_data:
      {
        unsigned ch = port2idx(port);
        std::lock_guard<std::mutex> lock(_mutex);
        *value = _channel[ch]->read();
        break;
      }
    default:
      warn().printf("PIT read from unimplemented channel 1\n");
      break;
    }
}

void Pit_timer::Channel::write_count(l4_uint8_t value)
{
  _count_latch.reset();
  _status_latch.reset();

  if (_status.is_mode0())
    {
      // when writing a new count, out goes low.
      set_output(false);
    }

  switch(_status.access())
    {
    case Access_lobyte:
      _reload = set_low_byte(_reload, value);
      check_start_counter();
      break;
    case Access_hibyte:
      _reload = set_high_byte(_reload, value);
      check_start_counter();
      break;
    case Access_lohi:
      write_lo_hi(value);
      break;
    default:
      warn().printf("Invalid access value for write to counter: counter "
                    "%u, status 0x%x\n",
                    _is_channel2 ? 2U : 0U, _status.raw);
      return;
    }
  trace().printf("Written new counter value to channel %i: reload: 0x%x, value "
                 "0x%x\n",
                 _is_channel2 ? 2U : 0U, _reload, value);
}

void Pit_timer::Channel::check_start_counter()
{
  // Assumption: only called after the full write of a counter
  if (!_gate)
    {
      warn().printf("count written, but gate not high: Counter %i\n",
                    _is_channel2 ? 2 : 0);
      return;
    }

  if (_status.is_mode0() || _status.is_mode4())
    {
      if (_running)
        stop_counter();
      start_counter();
    }
  else if (!_running && (_status.is_mode2() || _status.is_mode3()))
    start_counter();

  // modes 1, 2, 3, 5 do not change their counter value on a new reload value.
}

void Pit_timer::Channel::write_status(l4_uint8_t value)
{
  if ((value & 0x30U) == 0) // latch command
    {
      latch_count();
      return;
    }

  // Spec states: When writing to control word, all control logic resets.
  stop_counter();
  _count_latch.reset();
  _status_latch.reset();
  _read_lo = true;
  _write_lo = true;

  _status.write(value);
  // initial output level depends on the mode. Only mode0 is initially low.
  set_output(!_status.is_mode0());

  trace().printf("New status on channel %i: 0x%x (mode %u)\n",
                 _is_channel2 ? 2 : 0, _status.raw, _status.opmode().get());
}

l4_uint8_t Pit_timer::Channel::read()
{
  if (_status_latch.valid)
    {
      _status_latch.valid = false;
      return _status_latch.value & 0xff;
    }

  if (_count_latch.valid)
    {
      switch (_status.access())
        {
        case Access_lobyte:
          _count_latch.valid = false;
          return low_byte(_count_latch.value);
        case Access_hibyte:
          _count_latch.valid = false;
          return high_byte(_count_latch.value);
        case Access_lohi:
          if (_count_latch.read_lo == false) // reading 2nd byte invalidates
            _count_latch.valid = false;
          return read_lo_hi(&_count_latch.read_lo, _count_latch.value);
        default:
          warn().printf("Read latch with invalid access mode: counter "
                        "%u, status 0x%x\n",
                        _is_channel2 ? 2U : 0U, _status.raw);
          return 0;
        }
    }

  // read counter
  l4_uint16_t curr = current();
  switch (_status.access())
    {
    case Access_lobyte: return low_byte(curr);
    case Access_hibyte: return high_byte(curr);
    case Access_lohi: return read_lo_hi(&_read_lo, curr);
    default:
      warn().printf("Read counter with invalid access mode: counter "
                    "%u, status 0x%x\n",
                    _is_channel2 ? 2U : 0U, _status.raw);
      return 0;
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
