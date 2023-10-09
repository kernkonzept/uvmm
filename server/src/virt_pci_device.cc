/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "guest.h"
#include "virt_pci_device.h"

namespace Vdev { namespace Pci {

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
