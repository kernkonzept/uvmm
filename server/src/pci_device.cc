/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Jan Klötzke <jan.kloetzke@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "guest.h"
#include "pci_device.h"

namespace Vdev { namespace Pci {

bool Pci_device::cfg_read_bar(unsigned reg, l4_uint32_t *value,
                              Vmm::Mem_access::Width width)
{
  bool type0 = get_header_type() == Pci_header_type::Type0;
  if (!is_bar_reg(type0, reg))
    return false;

  unsigned bar = (reg - Pci_hdr_base_addr0_offset) >> 2;
  *value = 0;

  // only naturally aligned accesses are allowed
  if (L4_UNLIKELY(reg & ((1UL << width) - 1U)))
    return true;

  // We don't support expansion ROMs at all. Silently ignore.
  unsigned expansion_rom = expansion_rom_reg(type0);
  if (reg >= expansion_rom && reg <= expansion_rom + 3)
    return true;

  // only read one bar per access
  if (width > Vmm::Mem_access::Wd32)
    warn().printf("Unsupported 64-bit read of BAR[%u] register!\n", bar);

  l4_uint64_t regval = get_bar_regval(bar);
  *value = Vmm::Mem_access::read_width(reinterpret_cast<l4_addr_t>(&regval),
                                       width);

  return true;
}

l4_uint32_t Pci_device::get_bar_regval(unsigned bar) const
{
  assert(bar < sizeof(bars) / sizeof(bars[0]));

  switch (bars[bar].type)
    {
    case Pci_cfg_bar::Unused_empty:
      return 0;
    case Pci_cfg_bar::Reserved_mmio64_upper:
      assert(bar > 0);
      return bars[bar-1U].map_addr >> 32;
    case Pci_cfg_bar::MMIO32:
      return static_cast<l4_uint32_t>(bars[bar].map_addr)
              | Bar_mem_type_32bit
              | (bars[bar].prefetchable ? Bar_mem_prefetch_bit
                                        : Bar_mem_non_prefetch_bit);
    case Pci_cfg_bar::MMIO64:
      return static_cast<l4_uint32_t>(bars[bar].map_addr)
              | Bar_mem_type_64bit
              | (bars[bar].prefetchable ? Bar_mem_prefetch_bit
                                        : Bar_mem_non_prefetch_bit);
    case Pci_cfg_bar::IO:
      return static_cast<l4_uint32_t>(bars[bar].map_addr)
              | Bar_io_space_bit;
    }

  return 0;
}

bool Pci_device::cfg_write_bar(unsigned reg, l4_uint32_t value,
                               Vmm::Mem_access::Width width)
{
  bool type0 = get_header_type() == Pci_header_type::Type0;
  if (!is_bar_reg(type0, reg))
    return false;

  // only naturally aligned accesses are allowed
  if (L4_UNLIKELY(reg & ((1UL << width) - 1U)))
    return true;

  // We don't support expansion ROMs at all. Silently ignore.
  unsigned expansion_rom = expansion_rom_reg(type0);
  if (reg >= expansion_rom && reg <= expansion_rom + 3)
    return true;

  unsigned bar = (reg - Pci_hdr_base_addr0_offset) >> 2;
  if (width != Vmm::Mem_access::Wd32)
    {
      warn().printf("Ignored non 32-bit write of BAR[%u] register\n", bar);
      return true;
    }

  update_bar(bar, value);
  return true;
}

void Pci_device::update_bar(unsigned bar, l4_uint32_t value)
{
  assert(bar < sizeof(bars) / sizeof(bars[0]));

  switch (bars[bar].type)
    {
    case Pci_cfg_bar::Unused_empty:
      break;
    case Pci_cfg_bar::Reserved_mmio64_upper:
    case Pci_cfg_bar::MMIO32:
    case Pci_cfg_bar::MMIO64:
      if (enabled_decoders & Memory_space_bit)
        {
          warn().printf("Ignore update of BAR[%u]! MMIO decoding enabled.\n",
                        bar);
          return;
        }
      break;
    case Pci_cfg_bar::IO:
      if (enabled_decoders & Io_space_bit)
        {
          warn().printf("Ignore update of BAR[%u]! IO decoding enabled.\n",
                        bar);
          return;
        }
      break;
    }

  // The BAR size (power of 2!) defines which bits are writable.
  switch (bars[bar].type)
    {
    case Pci_cfg_bar::Unused_empty:
      break;
    case Pci_cfg_bar::Reserved_mmio64_upper:
      {
        assert(bar > 0);
        l4_uint64_t mask = ~bars[bar-1U].size + 1U;
        bars[bar-1U].map_addr &= 0xffffffffULL;
        bars[bar-1U].map_addr |= (static_cast<l4_uint64_t>(value) << 32) & mask;
        break;
      }
    case Pci_cfg_bar::MMIO32:
      {
        l4_uint32_t mask = ~bars[bar].size + 1U;
        bars[bar].map_addr = value & mask;
        break;
      }
    case Pci_cfg_bar::MMIO64:
      {
        l4_uint64_t mask = ~bars[bar].size + 1U;
        bars[bar].map_addr &= ~0xffffffffULL;
        bars[bar].map_addr |= value & mask;
        break;
      }
    case Pci_cfg_bar::IO:
      {
        l4_uint32_t mask = (~bars[bar].size + 1U) & 0xffffU;
        bars[bar].map_addr = value & mask;
        break;
      }
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

} } // namespace Vdev::Pci
