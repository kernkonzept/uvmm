/*
 * Copyright (C) 2021-2022 Kernkonzept GmbH.
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

  unsigned expansion_rom = expansion_rom_reg(type0);
  if (reg >= expansion_rom && reg <= expansion_rom + 3)
    {
      l4_uint64_t regval = exp_rom.map_addr | exp_rom.virt_enabled;
      if (width > Vmm::Mem_access::Wd32)
        {
          warn().printf("Unsupported 64-bit read of expansion ROM register! Diminishing width.\n");
          width = Vmm::Mem_access::Wd32;
        }

      *value = Vmm::Mem_access::read_width(reinterpret_cast<l4_addr_t>(&regval),
                                           width);
      return true;
    }

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

void Pci_device::write_exp_rom_regval(l4_uint32_t value)
{
  if (exp_rom.virt_enabled && (enabled_decoders & Memory_space_bit))
    del_exp_rom_resource();

  exp_rom.virt_enabled = value & Pci_expansion_rom_bar::Enable_bit;
  exp_rom.map_addr = value & ~(exp_rom.size - 1U);

  if (exp_rom.virt_enabled)
    {
      if (enabled_decoders & Memory_space_bit)
        add_exp_rom_resource();

      if (!exp_rom.hw_enabled)
        {
          // unless the HW reported the expansion ROM BAR as enabled, we
          // enable it to allow the guest to access it. Currenlty, we don't
          // disable expansion ROM BAR decoding again.
          unsigned rom_reg =
            expansion_rom_reg(get_header_type() == Pci_header_type(0));
          cfg_write_raw(rom_reg,
                        exp_rom.io_addr | Pci_expansion_rom_bar::Enable_bit,
                        Vmm::Mem_access::Wd32);
          exp_rom.hw_enabled = true;
        }
    }

  trace()
    .printf("wrote to expansion rom register: map_addr: 0x%llx, raw: 0x%llx\n",
            exp_rom.map_addr | exp_rom.virt_enabled ,
            exp_rom.io_addr | exp_rom.hw_enabled);
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

  unsigned expansion_rom = expansion_rom_reg(type0);
  if (reg >= expansion_rom && reg <= expansion_rom + 3)
    {
      write_exp_rom_regval(value);
      return true;
    }

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
          info().printf(
            "Ignore update of BAR[%u] while MMIO decoding is enabled.\n", bar);
          return;
        }
      break;
    case Pci_cfg_bar::IO:
      if (enabled_decoders & Io_space_bit)
        {
          info().printf(
            "Ignore update of BAR[%u] while IO decoding is enabled.\n", bar);
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

} } // namespace Vdev::Pci
