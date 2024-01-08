/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "guest.h"
#include "virt_pci_device.h"
#include "device/pci_host_bridge.h"

namespace Vdev { namespace Pci {

Virt_pci_device::Virt_pci_device(Vdev::Dt_node const &node,
                                 Pci_bridge_windows *wnds)
: Virt_pci_device()
{
  l4_uint64_t size;
  Dtb::Reg_flags flags;

  // First reg entry shall be the config space. Note that we ignore the
  // assigned bus/device/function numbers. This might change in the future!
  if (node.get_reg_size_flags(0, nullptr, &flags) < 0)
    L4Re::throw_error(-L4_EINVAL, "extract PCI dev reg[0] property");
  if (!flags.is_cfgspace())
    L4Re::throw_error(-L4_EINVAL,
                      "PCI dev reg[0] property shall be the config space");

  for (int i = 1; node.get_reg_size_flags(i, &size, &flags) >= 0; i++)
    {
      unsigned bar = (flags.pci_reg() - Pci_hdr_base_addr0_offset) / 4U;
      if (bar >= Bar_num_max_type0)
        L4Re::throw_error(-L4_EINVAL,
                          "PCI dev reg property must reference valid BAR");
      if (bars[bar].type != Pci_cfg_bar::Type::Unused_empty)
        L4Re::throw_error(-L4_EINVAL, "BAR must be defined only once");
      check_power_of_2(size, "BAR size must be power of 2");

      if (flags.is_mmio64())
        {
          l4_addr_t addr =
            wnds->alloc_bar_resource(size, Pci_cfg_bar::Type::MMIO64);
          set_mem64_space<Pci_header::Type0>(bar, addr, size);
        }
      else if (flags.is_mmio32())
        {
          l4_addr_t addr =
            wnds->alloc_bar_resource(size, Pci_cfg_bar::Type::MMIO32);
          set_mem_space<Pci_header::Type0>(bar, addr, size);
        }
      else if (flags.is_ioport())
        {
          l4_addr_t addr =
            wnds->alloc_bar_resource(size, Pci_cfg_bar::Type::IO);
          set_io_space<Pci_header::Type0>(bar, addr, size);
        }
      else
        L4Re::throw_error(-L4_EINVAL,
                          "PCI dev reg property has invalid type");

      info().printf("  bar[%u] addr=0x%llx size=0x%llx type=%s\n", bar,
                    bars[bar].io_addr, bars[bar].size, bars[bar].to_string());
    }
}
void Virt_pci_device::add_decoder_resources(Vmm::Guest *vmm, l4_uint32_t access)
{
  unsigned i = 0;
  for (auto &bar : bars)
    {
      switch (bar.type)
        {
        case Pci_cfg_bar::Unused_empty:
        case Pci_cfg_bar::Reserved_mmio64_upper:
          break;
        case Pci_cfg_bar::MMIO32:
        case Pci_cfg_bar::MMIO64:
          if (!(access & Memory_space_bit))
            break;

          vmm->add_mmio_device(Vmm::Region::ss(Vmm::Guest_addr(bar.map_addr),
                                               bar.size,
                                               Vmm::Region_type::Virtual,
                                               Vmm::Region_flags::Moveable),
                               get_mmio_bar_handler(i));
          break;
        case Pci_cfg_bar::IO:
          if (!Vmm::Guest::Has_io_space || !(access & Io_space_bit))
            break;

          vmm->add_io_device(Vmm::Io_region::ss(bar.map_addr, bar.size,
                                                Vmm::Region_type::Virtual,
                                                Vmm::Region_flags::Moveable),
                             get_io_bar_handler(i));
          break;
        }
      i++;
    }
}

void Virt_pci_device::del_decoder_resources(Vmm::Guest *vmm, l4_uint32_t access)
{
  for (auto &bar : bars)
    {
      switch (bar.type)
        {
        case Pci_cfg_bar::Unused_empty:
        case Pci_cfg_bar::Reserved_mmio64_upper:
          break;
        case Pci_cfg_bar::MMIO32:
        case Pci_cfg_bar::MMIO64:
          if (access & Memory_space_bit)
            vmm->del_mmio_device(Vmm::Region::ss(Vmm::Guest_addr(bar.map_addr),
                                                 bar.size,
                                                 Vmm::Region_type::Virtual,
                                                 Vmm::Region_flags::Moveable));
          break;
        case Pci_cfg_bar::IO:
          if (Vmm::Guest::Has_io_space && access & Io_space_bit)
            vmm->del_io_device(Vmm::Io_region::ss(bar.map_addr, bar.size,
                                                  Vmm::Region_type::Virtual,
                                                  Vmm::Region_flags::Moveable));
          break;
        }
    }
}

}} // namespace Vdev::Pci
