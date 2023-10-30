/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 */

#pragma once

#include "pci_host_bridge.h"

namespace Vdev { namespace Pci {

/**
 * Interface to handle ECAM access to the PCI configuration space and
 * translate it to an internal protocol.
 */
class Pci_bus_cfg_ecam : public Vmm::Mmio_device_t<Pci_bus_cfg_ecam>
{
private:
  /**
   * ECAM configuration space offset.
   *
   * This allows decoding of raw configuration space offsets into bus/device id's,
   * function number and register offsets.
   */
  struct Cfg_addr
  {
    l4_uint32_t raw = 0;
    CXX_BITFIELD_MEMBER(20, 31, bus, raw);  /// Bus id
    CXX_BITFIELD_MEMBER(15, 19, dev, raw);  /// Device id
    CXX_BITFIELD_MEMBER(12, 14, func, raw); /// Function number
    CXX_BITFIELD_MEMBER( 0, 11, reg, raw);  /// Register offset

    explicit Cfg_addr(l4_uint32_t r) : raw(r) {}
  };

public:
  Pci_bus_cfg_ecam(cxx::Ref_ptr<Pci_host_bridge> const &bus) : _bus(bus) {}

  /**
   * Read PCI configuration space.
   *
   * Device 0 is always the virtual host controller. Access to other regions is
   * forwarded to the corresponding device.
   */
  l4_uint32_t read(unsigned reg, char width, unsigned)
  {
    Cfg_addr cfg(reg);
    if (cfg.bus().get() > 0 || cfg.func().get() > 0)
      return -1U;
    return _bus->cfg_space_read(cfg.dev().get(), cfg.reg().get(),
                                (Vmm::Mem_access::Width)width);
  }

  /**
   * Write PCI configuration space.
   *
   * Device 0 is always the virtual host controller. Access to other regions is
   * forwarded to the corresponding device.
   */
  void write(unsigned reg, char width, l4_uint32_t val, unsigned)
  {
    Cfg_addr cfg(reg);
    if (cfg.bus().get() > 0 || cfg.func().get() > 0)
      return;
    _bus->cfg_space_write(cfg.dev().get(), cfg.reg().get(),
                          (Vmm::Mem_access::Width)width, val);
  }

  char const *dev_name() const override { return "Pci_bus_cfg_ecam"; }

  cxx::Ref_ptr<Pci_host_bridge> _bus;
};

} } // namespace Vdev::Pci
