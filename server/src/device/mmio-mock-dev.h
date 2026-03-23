/*
 * Copyright (C) 2026 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <memory>

#include "mmio_device.h"
#include "debug.h"

namespace Vdev {

/**
 * Device to record and return MMIO range accesses.
 *
 * This device stores writes to a given MMIO range and returns their value on
 * read.
 * It can also be used to trace all MMIO access to the MMIO range, by enabling
 * the print statements in read()/write().
 *
 * \code{.dtb}
 *   pinctrl@30330000 {
 *       compatible = "l4vmm,mock-mmio";
 *       reg = <0x0 0x30330000 0x0 0x10000>;
 *   };
 * \endcode
 */
class Mmio_mock_dev
: public Vmm::Mmio_device_t<Mmio_mock_dev>,
  public Vdev::Device
{
public:
  Mmio_mock_dev(l4_addr_t base, l4_size_t size)
  : _mmio_base(base), _mmio_size(size)
  {
    _mem = std::make_unique<l4_uint8_t[]>(size);
  }

  l4_uint64_t read(unsigned offset, char width, unsigned)
  {
    l4_addr_t const addr = _mmio_base + offset;

    if (offset >= _mmio_size)
      {
        warn().printf("Access out of bounds @offset 0x%x, max offset 0x%lx\n",
                      offset, _mmio_size);
        return -1ULL;
      }

    l4_uint64_t value = 0x0ULL;
    unsigned num_bytes = 1 << width;
    for (unsigned i = 0; i < num_bytes; ++i)
      value |= l4_uint64_t(_mem[offset + i]) << i;

    if (0)
      info().printf("READ @ 0x%lx, val 0x%llx, width 0x%x\n", addr, value,
                    width);
    return value;
  }

  void write(unsigned offset, char width, l4_uint64_t value, unsigned)
  {
    l4_addr_t const addr = _mmio_base + offset;
    if (0)
      info().printf("WRITE @ 0x%lx, val 0x%llx, width 0x%x\n", addr, value,
                    width);
    if (offset >= _mmio_size)
      {
        warn().printf("Access out of bounds @offset 0x%x, max offset 0x%lx\n",
                      offset, _mmio_size);
        return;
      }

    unsigned num_bytes = 1 << width;
    for (unsigned i = 0; i < num_bytes; ++i)
      _mem[offset + i] = value & (0xff << i);
  }

  char const *dev_name() const override { return "Mmio_mock_dev"; }

private:
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "MMIO mock"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Warn, "MMIO mock"); }

  l4_addr_t const _mmio_base;
  l4_size_t const _mmio_size;
  std::unique_ptr<l4_uint8_t[]> _mem;
};

}
