/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */

#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>

#include "pci_host_bridge.h"
#include "mem_access.h"
#include "pci_device.h"
#include "ds_mmio_mapper.h"
#include "ds_mmio_handling.h"
#include "msi_memory.h"
#include "io_port_handler.h"

namespace Vdev { namespace Pci {

bool
parse_bus_range(Dt_node const &node, unsigned char *start, unsigned char *end)
{
  auto info = Dbg(Dbg::Dev, Dbg::Info, "PCI bus");
  auto trace = Dbg(Dbg::Dev, Dbg::Trace, "PCI bus");

  int sz;
  if (!node.has_prop("bus-range"))
    {
      info.printf("Bus range not specified in device tree.\n");
      return false;
    }

  auto bus_range = node.get_prop<fdt32_t>("bus-range", &sz);
  if (sz != 2)
    {
      info.printf("Bus range property of Pci_host_bridge has invalid size\n");
      return false;
    }

  *start = (l4_uint8_t)fdt32_to_cpu(bus_range[0]);
  *end = (l4_uint8_t)fdt32_to_cpu(bus_range[1]);

  trace.printf("Init host bridge: Found 'bus-range' 0x%x - 0x%x\n",
               *start, *end);

  return true;
}

void
Pci_host_bridge::Hw_pci_device::add_decoder_resources(Vmm::Guest *,
                                                      l4_uint32_t access)
{
  int bir = has_msix ? msix_cap.tbl.bir()
                     : Pci_config_consts::Bar_num_max_type0;

  for (int i = 0; i < Pci_config_consts::Bar_num_max_type0; ++i)
    {
      switch (bars[i].type)
        {
        case Pci_cfg_bar::Type::IO:
          if (Vmm::Guest::Has_io_space && access & Io_space_bit)
            add_io_bar_resources(bars[i]);
          break;

        case Pci_cfg_bar::Type::MMIO32:
        case Pci_cfg_bar::Type::MMIO64:
          if (!(access & Memory_space_bit))
            break;

          if (i == bir)
            add_msix_bar_resources(bars[i]);
          else
            add_mmio_bar_resources(bars[i]);
          break;

        default: break;
        }
    }

  if (access & Memory_space_bit && exp_rom.virt_enabled)
    add_exp_rom_resource();
}

void Pci_host_bridge::Hw_pci_device::add_exp_rom_resource()
{
  auto region =
    Vmm::Region::ss(Vmm::Guest_addr(exp_rom.map_addr), exp_rom.size,
                    Vmm::Region_type::Vbus, Vmm::Region_flags::Moveable);
  info().printf("Register expansion ROM region: [0x%lx, 0x%lx], vbus base "
                "0x%llx\n",
                region.start.get(), region.end.get(), exp_rom.io_addr);

  auto m = cxx::make_ref_obj<Ds_manager>("Pci_host_bridge: rom",
                                         parent->_vbus->io_ds(),
                                         exp_rom.io_addr, exp_rom.size);
  parent->_vmm->add_mmio_device(region, make_device<Ds_handler>(m));
}

void
Pci_host_bridge::Hw_pci_device::add_io_bar_resources(Pci_cfg_bar const &bar)
{
  Vmm::Guest_addr addr(bar.map_addr);
  l4_size_t size = bar.size;
  auto region = Vmm::Io_region::ss(addr.get(), size, Vmm::Region_type::Vbus,
                                   Vmm::Region_flags::Moveable);
  warn().printf("Register IO region: [0x%lx, 0x%lx], vbus base 0x%llx\n",
                region.start, region.end, bar.io_addr);

  l4vbus_resource_t res;
  res.type = L4VBUS_RESOURCE_PORT;
  res.start = bar.io_addr;
  res.end = res.start + size - 1U;
  res.provider = 0;
  res.id = 0;
  L4Re::chksys(parent->_vbus->bus()->request_ioport(&res),
               "Request IO port resource from vBus.");
  parent->_vmm->add_io_device(region,
                              make_device<Io_port_handler>(bar.io_addr));
}

void
Pci_host_bridge::Hw_pci_device::add_mmio_bar_resources(Pci_cfg_bar const &bar)
{
  Vmm::Guest_addr addr(bar.map_addr);
  l4_size_t size = bar.size;
  auto region = Vmm::Region::ss(addr, size, Vmm::Region_type::Vbus,
                                Vmm::Region_flags::Moveable);
  warn().printf("Register MMIO region: [0x%lx, 0x%lx], vbus base 0x%llx\n",
                region.start.get(), region.end.get(), bar.io_addr);

  auto m = cxx::make_ref_obj<Ds_manager>("Pci_host_bridge: mmio bar",
                                         parent->_vbus->io_ds(), bar.io_addr,
                                         size);
  parent->_vmm->add_mmio_device(region, make_device<Ds_handler>(m));
}

/**
 * Add MMIO resources of the BAR that holds the MSI-X table.
 *
 * Usually the BAR does not only hold the MSIX-table but other resources too.
 * Everything in the BAR before and after the table is mapped pass-through to
 * the guest. If the table is not page aligned the affected parts of the pages
 * are trapped and forwarded.
 *
 * The virtual MSI-X table is always registered, even if the bridge lacks a
 * virtual MSI-X controller. The guest might still access the MSI-X table
 * and we must support that even though the interrupt will not be deliverd.
 */
void
Pci_host_bridge::Hw_pci_device::add_msix_bar_resources(Pci_cfg_bar const &bar)
{
  unsigned max_msis = msix_cap.ctrl.max_msis() + 1;
  unsigned table_offset = msix_cap.tbl.offset();

  // the virtual MSI-X table
  l4_addr_t msix_table_start = bar.map_addr + table_offset;
  l4_addr_t msix_table_size = max_msis * Msix::Entry_size;

  // whole pages mapped to guest at start of BAR
  l4_addr_t before_pages_start = bar.map_addr;
  l4_addr_t before_pages_size = l4_trunc_page(table_offset);

  // partial page mapped to guest immediately before MSI-X table
  l4_addr_t before_partial_start = before_pages_start + before_pages_size;
  l4_addr_t before_partial_size = msix_table_start - before_partial_start;

  // whole pages mapped to guest at end of BAR
  l4_addr_t after_pages_start = l4_round_page(msix_table_start + msix_table_size);
  l4_addr_t after_pages_size = bar.size - (after_pages_start - bar.map_addr);

  // partial page mapped to guest immediately after MSI-X table
  l4_addr_t after_partial_start = msix_table_start + msix_table_size;
  l4_addr_t after_partial_size = after_pages_start - after_partial_start;

  // now add everything

  cxx::Ref_ptr<Vmm::Ds_manager> m;
  if (before_pages_size || after_pages_size)
    m = cxx::make_ref_obj<Vmm::Ds_manager>("Pci_host_bridge: io mem",
                                           parent->_vbus->io_ds(),
                                           bar.io_addr, bar.size);

  if (before_pages_size)
    {
      auto region = Region::ss(Vmm::Guest_addr(before_pages_start),
                               before_pages_size, Vmm::Region_type::Vbus,
                               Vmm::Region_flags::Moveable);
      warn().printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
      parent->_vmm->add_mmio_device(region, make_device<Ds_handler>(m));
    }

  if (before_partial_size)
    {
      auto region = Region::ss(Vmm::Guest_addr(before_partial_start),
                               before_partial_size, Vmm::Region_type::Vbus,
                               Vmm::Region_flags::Moveable);
      warn().printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
      auto con = make_device<Mmio_ds_converter>(msix_table_page_mgr, 0);
      parent->_vmm->add_mmio_device(region, con);
    }

  auto region = Region::ss(Vmm::Guest_addr(msix_table_start), msix_table_size,
                           Vmm::Region_type::Vbus, Vmm::Region_flags::Moveable);
  warn().printf("Register MSI-X MMIO table: [0x%lx, 0x%lx]\n",
                region.start.get(), region.end.get());
  parent->_vmm->add_mmio_device(region, msix_table);

  if (after_partial_size)
    {
      auto region = Region::ss(Vmm::Guest_addr(after_partial_start),
                               after_partial_size, Vmm::Region_type::Vbus,
                               Vmm::Region_flags::Moveable);
      warn().printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
      l4_addr_t mgr_offset = after_partial_start - before_partial_start;
      auto con = make_device<Mmio_ds_converter>(msix_table_page_mgr, mgr_offset);
      parent->_vmm->add_mmio_device(region, con);
    }

  if (after_pages_size)
    {
      auto region = Region::ss(Vmm::Guest_addr(after_pages_start),
                               after_pages_size, Vmm::Region_type::Vbus,
                               Vmm::Region_flags::Moveable);
      warn().printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
      l4_addr_t mgr_offset = after_pages_start - before_pages_start;
      parent->_vmm->add_mmio_device(region,
                                    make_device<Ds_handler>(m, L4_FPAGE_RW,
                                                            mgr_offset));
    }
}

void
Pci_host_bridge::Hw_pci_device::del_decoder_resources(Vmm::Guest *,
                                                      l4_uint32_t access)
{
  int bir = has_msix ? msix_cap.tbl.bir()
                     : Pci_config_consts::Bar_num_max_type0;

  for (int i = 0; i < Pci_config_consts::Bar_num_max_type0; ++i)
    {
      switch (bars[i].type)
        {
        case Pci_cfg_bar::Type::IO:
          if (Vmm::Guest::Has_io_space && access & Io_space_bit)
            del_io_bar_resources(bars[i]);
          break;

        case Pci_cfg_bar::Type::MMIO32:
        case Pci_cfg_bar::Type::MMIO64:
          if (!(access & Memory_space_bit))
            break;

          if (i == bir)
            del_msix_bar_resources(bars[i]);
          else
            del_mmio_bar_resources(bars[i]);
          break;

        default: break;
        }
    }

  if (access & Memory_space_bit && exp_rom.virt_enabled)
    del_exp_rom_resource();
}

void Pci_host_bridge::Hw_pci_device::del_exp_rom_resource()
{
  auto region =
    Vmm::Region::ss(Vmm::Guest_addr(exp_rom.map_addr), exp_rom.size,
                    Vmm::Region_type::Virtual, Vmm::Region_flags::Moveable);
  info().printf("Removing expansion ROM region: [0x%lx, 0x%lx]\n",
                region.start.get(), region.end.get());

  parent->_vmm->del_mmio_device(region);
}

void
Pci_host_bridge::Hw_pci_device::del_io_bar_resources(Pci_cfg_bar const &bar)
{
  auto region = Vmm::Io_region::ss(bar.map_addr, bar.size,
                                   Vmm::Region_type::Vbus);
  warn().printf("Unregister IO region: [0x%lx, 0x%lx]\n",
                region.start, region.end);
  parent->_vmm->del_io_device(region);
}

void
Pci_host_bridge::Hw_pci_device::del_mmio_bar_resources(Pci_cfg_bar const &bar)
{
  auto region = Vmm::Region::ss(Vmm::Guest_addr(bar.map_addr), bar.size,
                                Vmm::Region_type::Vbus);
  warn().printf("Unregister MMIO region: [0x%lx, 0x%lx]\n",
                region.start.get(), region.end.get());
  parent->_vmm->del_mmio_device(region);
}

void
Pci_host_bridge::Hw_pci_device::del_msix_bar_resources(Pci_cfg_bar const &bar)
{
  auto region = Region::ss(Vmm::Guest_addr(bar.map_addr), bar.size,
                           Vmm::Region_type::Vbus);
  warn().printf("Unregister MSI-X bar MMIO region: [0x%lx, 0x%lx]\n",
                region.start.get(), region.end.get());
  parent->_vmm->del_mmio_devices(region);
}

bool Pci_host_bridge::Hw_pci_device::msi_cap_read(unsigned reg,
                                                  l4_uint32_t *value,
                                                  Vmm::Mem_access::Width width)
{
  if (reg < msi_cap.offset || reg >= msi_cap.cap_end())
    return false;

  unsigned offset = reg - msi_cap.offset;
  trace().printf("msi_cap_read: devid = 0x%x offset = 0x%x width = %d\n",
                 dev_id, offset, width);

  // guard against multiple threads accessing the device
  std::lock_guard<std::mutex> lock(_mutex);

  bool sixtyfour = msi_cap.ctrl.sixtyfour();
  switch (offset)
    {
    case 0x0:
      if (width <= Vmm::Mem_access::Width::Wd16)
        // access only to non-emulated part, forward to hardware
        break;
      else
        {
          // read lower 16 bits from hardware
          l4_uint32_t val;
          L4Re::chksys(dev.cfg_read(reg, &val, mem_access_to_bits(width)),
                       "PCI MSI cap access: read");
          // and combine with emulated upper 16 bits.
          *value = (msi_cap.ctrl.raw << 16) | (val & 0xffff);
          return true;
        }
    case 0x2:
      *value = msi_cap.ctrl.raw;
      return true;

    case 0x4:
      *value = msi_cap.address;
      return true;

    case 0x8:
      if (sixtyfour)
        *value = msi_cap.upper_address;
      else
        *value = msi_cap.data;
      return true;

    case 0xc:
      if (sixtyfour)
        {
          *value = msi_cap.data;
          return true;
        }
      // mask bits or non-existent
      break;

    default:
      // Forward to hardware. No register that we emulate.
      break;
    }

  return false;
}

void
Pci_host_bridge::Hw_pci_device::msi_cap_write_ctrl(l4_uint16_t ctrl)
{
  bool was_enabled = msi_cap.ctrl.msi_enable();
  msi_cap.write_ctrl(ctrl);

  if (!was_enabled && msi_cap.ctrl.msi_enable())
    {
      if (parent->_msi_src_factory)
        {
          info().printf("MSI enabled: devid = 0x%x, ctrl = 0x%x\n", dev_id,
                        msi_cap.ctrl.raw);
          l4_icu_msi_info_t msiinfo;
          msi_src = parent->_msi_src_factory
            ->configure_msi_route(msi_cap, parent->msix_dest(dev_id),
                                  src_id(), &msiinfo);
          if (msi_src)
            cfg_space_write_msi_cap(&msiinfo);
        }
      else
        warn().printf("MSI enabled, but bridge lacks support: devid = 0x%x "
                      "ctrl = 0x%x.\n Your device will probably not work!\n",
                      dev_id, msi_cap.ctrl.raw);
    }
  else if (was_enabled && !msi_cap.ctrl.msi_enable())
    {
      if (parent->_msi_src_factory)
        cfg_space_write_msi_cap();
      msi_src = nullptr;

      trace().printf("MSI disabled: devid = 0x%x ctrl = 0x%x\n", dev_id,
                     msi_cap.ctrl.raw);
    }
}

bool Pci_host_bridge::Hw_pci_device::msi_cap_write(unsigned reg,
                                                   l4_uint32_t value,
                                                   Vmm::Mem_access::Width width)
{
  if (reg < msi_cap.offset || reg >= msi_cap.cap_end())
    return false;

  unsigned offset = reg - msi_cap.offset;
  trace().printf("msi_cap_write: devid = 0x%x offset = 0x%x width = %d value = 0x%x\n",
                 dev_id, offset, width, value);
  if (   (width == Vmm::Mem_access::Width::Wd8 && offset != 0)
      || (offset % (mem_access_to_bits(width) / 8) != 0))
    warn().printf("Unaligned or partial write to MSI cap fields not supported. "
                  "State might become inconsistent.\n");

  // guard against multiple threads accessing the device
  std::lock_guard<std::mutex> lock(_mutex);

  bool sixtyfour = msi_cap.ctrl.sixtyfour();
  bool per_vector_mask = msi_cap.ctrl.per_vector_masking();
  bool consume_write = true;
  switch (offset)
    {
    case 0x0:
      if (width <= Vmm::Mem_access::Width::Wd16)
        // access only to non-emulated part, forward to hardware
        consume_write = false;
      else
        {
          // write lower 16 bits to hardware
          L4Re::chksys(dev.cfg_write(reg, value & 0xffff, 16),
                       "PCI MSI cap access: write");

          msi_cap_write_ctrl(value >> 16);
        }
      break;

    case 0x2:
      {
        msi_cap_write_ctrl(value);
        break;
      }

    case 0x4: // message address
      msi_cap.address = value;
      break;

    case 0x8:
      if (sixtyfour)
        msi_cap.upper_address = value;
      else
        msi_cap.data = value;
      break;

    case 0xc:
      if (sixtyfour)
        msi_cap.data = value;
      else if (per_vector_mask)
        consume_write = false; // mask bits
      break;

    case 0x10:
      if (sixtyfour && per_vector_mask)
        consume_write = false; // mask bits
      else if (!sixtyfour && per_vector_mask)
        warn().printf("write to RO field: pending bits. Ignored\n");
      break;

    case 0x14:
      warn().printf("write to RO field: pending bits. Ignored\n");
      break;

    default:
      warn().printf("Write to unhandled MSI CAP register: devid = 0x%x offset "
                    "= 0x%x width = %d value = 0x%x\n",
                    dev_id, offset, width, value);
      break;
    }

  return consume_write;
}

void Pci_host_bridge::Hw_pci_device::cfg_space_write_msi_cap(
  l4_icu_msi_info_t *msiinfo)
{
  unsigned msi_cap_addr = msi_cap.offset;

  if (msiinfo)
    {
      trace().printf("msi address: 0x%llx, data 0x%x\n", msiinfo->msi_addr,
                     msiinfo->msi_data);

      // write MSI address
      L4Re::chksys(dev.cfg_write(msi_cap_addr + 0x4,
                                 static_cast<l4_uint32_t>(msiinfo->msi_addr),
                                 32),
                   "Write HW PCI device MSI cap message address");

      // write MSI data
      unsigned data_addr =
        msi_cap_addr + (msi_cap.ctrl.sixtyfour() ? 0xC : 0x8);
      L4Re::chksys(dev.cfg_write(data_addr, msiinfo->msi_data, 16),
                   "Write HW PCI device MSI cap message data");

      // write MSI upper address
      if (msi_cap.ctrl.sixtyfour())
        L4Re::chksys(dev.cfg_write(msi_cap_addr + 0x8,
                                   static_cast<l4_uint32_t>(msiinfo->msi_addr
                                                            >> 32),
                                   32),
                     "Write HW PCI device MSI cap upper message address");
    }

  // write MSI control
  L4Re::chksys(dev.cfg_write(msi_cap_addr + 0x2, msi_cap.ctrl.raw, 16),
               "Write HW PCI device MSI cap ctrl.");
}

void Pci_host_bridge::Hw_pci_device::setup_msix_table()
{
  if (!has_msix)
    return;

  unsigned bir = msix_cap.tbl.bir();
  if (bir < Pci_config_consts::Bar_num_max_type0)
    {
      Gic::Msix_dest _msix_dest = parent->msix_dest(dev_id);
      if (!_msix_dest.is_present())
        warn().printf(
          "No MSI-X controller available for MSI-X device %s (devid=%u).\n",
          dinfo.name, dev_id);

      unsigned max_msis = msix_cap.ctrl.max_msis() + 1;
      unsigned table_size = max_msis * Msix::Entry_size;

      // Cover MSI-X table with page granularity
      l4_addr_t io_table_addr =
        bars[bir].io_addr + msix_cap.tbl.offset();
      l4_addr_t io_table_ds_base = l4_trunc_page(io_table_addr);
      l4_addr_t io_table_ds_size =
        l4_round_page(io_table_addr + table_size) - io_table_ds_base;

      msix_table_page_mgr =
        cxx::make_ref_obj<Ds_access_mgr>(parent->_vbus->io_ds(),
                                         io_table_ds_base, io_table_ds_size);
      auto con =
        make_device<Mmio_ds_converter>(msix_table_page_mgr,
                                       io_table_addr - io_table_ds_base);

      msix_table = make_device<Msix::Virt_msix_table>(
        std::move(con), cxx::static_pointer_cast<Msi::Allocator>(parent->_vbus),
        parent->_vmm->registry(), src_id(), max_msis, _msix_dest);
    }
  else
    warn().printf("Device %s (devid=%u) has invalid MSI-X bar: %u\n",
                  dinfo.name, dev_id, bir);
}

bool Pci_host_bridge::Hw_pci_device::sriov_cap_read(unsigned reg,
                                                    l4_uint32_t *value,
                                                    Vmm::Mem_access::Width width)
{
  if (reg < sriov_cap.offset || reg >= sriov_cap.cap_end())
    return false;

  unsigned offset = reg - sriov_cap.offset;
  trace().printf("sriov_cap_read: devid = 0x%x offset = 0x%x width = %d\n",
                 dev_id, offset, width);

  switch (offset)
    {
    case 0x12: // Fcn Dep Link
      // If a PF is independent from other PFs of a Device, this field shall
      // contain its own Function Number. The function number on hardware
      // differs from the one we assigned to the device on our virtual PCI bus,
      // so we have to emulate the register.
      // We do not support device function, therefore the following shift
      // accounts for the 3 bits allocated for the function number.
      *value = dev_id << 3;
      return true;

    default:
      // Forward to hardware. No register that we emulate.
      break;
    }

  return false;
}

void Pci_host_bridge::Hw_pci_device::map_additional_iomem_resources(
  Vmm::Guest *vmm, L4::Cap<L4Re::Dataspace> io_ds)
{
  for (unsigned i = 0; i < dinfo.num_resources; ++i)
    {
      l4vbus_resource_t res;
      L4Re::chksys(dev.get_resource(i, &res), "Cannot get vbus resource.");

      // we only handle iomem resources
      if (res.type != L4VBUS_RESOURCE_MEM)
        continue;

      unsigned mmio_space_rw =
        L4VBUS_RESOURCE_F_MEM_MMIO_READ | L4VBUS_RESOURCE_F_MEM_MMIO_WRITE;
      bool is_mmio_space = res.flags & mmio_space_rw;

      // we only handle mmio resources (not spaces)
      if (is_mmio_space)
        continue;

      auto size = res.end - res.start + 1;
      // we only handle resources that are not handled via PCI BARs
      bool is_pci_bar = false;
      for (unsigned j = 0; j < Bar_num_max_type0; ++j)
        {
          if (bars[j].type == Pci_cfg_bar::Unused_empty
              || bars[j].type == Pci_cfg_bar::Reserved_mmio64_upper
              || bars[j].type == Pci_cfg_bar::IO)
            continue;
          if (res.start == bars[j].io_addr && size == bars[j].size)
            is_pci_bar = true;
        }
      if (is_pci_bar)
        continue;

      // ignore ROM resource. If supported the expansion ROM BAR is
      // already set up.
      if (res.id == 0x4d4f52) // "ROM"
        continue;

      // Default to 1:1 mapping of additional resources, e.g. for i915.
      l4_addr_t map_addr = res.start;

      info().printf("Additional MMIO resource %s.%.4s : "
                    "[0x%lx - 0x%lx] -> [0x%lx, 0x%lx] flags = 0x%x\n",
                    dinfo.name, reinterpret_cast<char const *>(&res.id),
                    res.start, res.end, map_addr, map_addr + size - 1,
                    res.flags);

      auto region = Vmm::Region::ss(Vmm::Guest_addr(map_addr), size,
                                    Vmm::Region_type::Vbus);
      l4_uint32_t rights = 0;
      if (res.flags & L4VBUS_RESOURCE_F_MEM_R)
        rights |= L4_FPAGE_RO;
      if (res.flags & L4VBUS_RESOURCE_F_MEM_W)
        rights |= L4_FPAGE_W;
      auto handler = Vdev::make_device<Ds_handler>(
        cxx::make_ref_obj<Vmm::Ds_manager>("Pci_host_bridge: additional IO mem",
                                           io_ds, res.start, size,
                                           L4Re::Rm::Region_flags(rights)),
        static_cast<L4_fpage_rights>(rights));
      vmm->add_mmio_device(region, handler);
    }
}
}} // namespace Vdev::Pci
