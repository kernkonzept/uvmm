/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
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

namespace Vdev { namespace Pci {

bool Pci_host_bridge::Hw_pci_device::msi_cap_read(unsigned reg,
                                                  l4_uint32_t *value,
                                                  Vmm::Mem_access::Width width)
{
  if (reg < msi_cap.offset || reg >= msi_cap.cap_end())
    return false;

  unsigned offset = reg - msi_cap.offset;
  trace().printf("read: devid = 0x%x offset = 0x%x width = %d\n",
                 dev_id, offset, width);

  // guard against multiple threads accessing the device
  std::lock_guard<std::mutex> lock(_mutex);

  bool sixtyfour = msi_cap.ctrl.sixtyfour();
  switch (offset)
    {
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

bool Pci_host_bridge::Hw_pci_device::msi_cap_write(unsigned reg,
                                                   l4_uint32_t value,
                                                   Vmm::Mem_access::Width width)
{
  if (reg < msi_cap.offset || reg >= msi_cap.cap_end())
    return false;

  unsigned offset = reg - msi_cap.offset;
  trace().printf("write: devid = 0x%x offset = 0x%x width = %d value = 0x%x\n",
                 dev_id, offset, width, value);

  // guard against multiple threads accessing the device
  std::lock_guard<std::mutex> lock(_mutex);

  bool sixtyfour = msi_cap.ctrl.sixtyfour();
  bool per_vector_mask = msi_cap.ctrl.per_vector_masking();
  bool consume_write = true;
  switch (offset)
    {
    case 0x2:
      {
        bool was_enabled = msi_cap.ctrl.msi_enable();
        msi_cap.ctrl.raw = value & 0xffff;
        msi_cap.ctrl.multiple_message_capable() = 0;
        if (!was_enabled && msi_cap.ctrl.msi_enable())
          {
            if (msi_src_factory)
              {
                info().printf("MSI enabled: devid = 0x%x, ctrl = 0x%x\n",
                              dev_id, msi_cap.ctrl.raw);
                l4_icu_msi_info_t msiinfo;
                msi_src =
                  msi_src_factory->configure_msi_route(msi_cap, src_id(),
                                                       &msiinfo);
                if (msi_src)
                  cfg_space_write_msi_cap(&msiinfo);
              }
            else
              warn().printf("MSI enabled but bridge lacks support: devid = "
                            "0x%x ctrl = 0x%x.\n"
                            " Your device will probably not work!\n",
                            dev_id, msi_cap.ctrl.raw);
          }
        else if (was_enabled && !msi_cap.ctrl.msi_enable())
          {
            if (msi_src_factory)
              {
                cfg_space_write_msi_cap();
                msi_src_factory->reset_msi_route(msi_src);
              }
            msi_src = nullptr;

            trace().printf("MSI disabled: devid = 0x%x ctrl = 0x%x\n",
                           dev_id, msi_cap.ctrl.raw);
          }
      }
      break;

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

    case 0x12:
      warn().printf("write to RO field: pending bits. Ignored\n");
      break;

    default: warn().printf("Unhandled MSI CAP register\n"); break;
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

void Pci_host_bridge::register_msix_table_page(
  Pci_host_bridge::Hw_pci_device *hwdev, unsigned bir,
  cxx::Ref_ptr<Gic::Msix_controller> const &msix_ctrl)
{
  assert(hwdev);
  assert(hwdev->has_msix);
  unsigned max_msis = hwdev->msix_cap.ctrl.max_msis() + 1;

  l4_addr_t table_addr =
    hwdev->bars[bir].map_addr + hwdev->msix_cap.tbl.offset().get();
  l4_addr_t table_end = table_addr + max_msis * Msix::Entry_size - 1;

  l4_addr_t table_page = l4_trunc_page(table_addr);

  auto mem_mgr =
    cxx::make_ref_obj<Ds_access_mgr>(_vbus->io_ds(), table_page, L4_PAGESIZE);

  l4_size_t pre_table_size = table_addr - table_page;
  if (pre_table_size > 0)
    {
      auto region = Vmm::Region::ss(Vmm::Guest_addr(table_page),
                                    pre_table_size, Vmm::Region_type::Vbus);
      auto con = make_device<Mmio_ds_converter>(mem_mgr, 0);
      _vmm->add_mmio_device(region, con);
      warn().printf("Register MMIO region before: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
    }

  l4_addr_t post_table = table_end + 1;
  l4_size_t post_table_size = table_page + L4_PAGESIZE - post_table;

  if (post_table_size > 0)
    {
      auto region = Vmm::Region::ss(Vmm::Guest_addr(post_table),
                                    post_table_size, Vmm::Region_type::Vbus);
      auto con =
        make_device<Mmio_ds_converter>(mem_mgr, post_table - table_page);
      _vmm->add_mmio_device(region, con);
      warn().printf("Register MMIO region after: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
    }

  auto con =
    make_device<Mmio_ds_converter>(mem_mgr, table_addr - table_page);

  auto region = Vmm::Region(Vmm::Guest_addr(table_addr),
                            Vmm::Guest_addr(table_end), Vmm::Region_type::Vbus);

  auto hdlr = make_device<Msix::Virt_msix_table>(
    std::move(con), cxx::static_pointer_cast<Msi::Allocator>(_vbus),
    _vmm->registry(), hwdev->src_id(), max_msis, msix_ctrl);

  warn().printf("Register MSI-X MMIO region: [0x%lx, 0x%lx]\n",
                region.start.get(), region.end.get());

  _vmm->add_mmio_device(region, hdlr);
}

void Pci_host_bridge::register_msix_bar(Pci_cfg_bar const *bar,
                                        l4_addr_t tbl_offset)
{
  l4_addr_t tbl_page_begin_rel = l4_trunc_page(tbl_offset);
  l4_addr_t tbl_page_size = L4_PAGESIZE;

  l4_addr_t before_area_begin = bar->map_addr;
  l4_addr_t before_area_size = tbl_page_begin_rel;

  l4_addr_t after_area_begin_rel = tbl_page_begin_rel + tbl_page_size;
  l4_addr_t after_area_begin = after_area_begin_rel + bar->map_addr;
  l4_addr_t after_area_size = bar->size - after_area_begin_rel;

  warn().printf("sizes before 0x%lx, after 0x%lx\n", before_area_size,
                after_area_size);

  cxx::Ref_ptr<Vmm::Ds_manager> m;

  if (before_area_size || after_area_size)
    m = cxx::make_ref_obj<Vmm::Ds_manager>(_vbus->io_ds(),
                                           bar->map_addr, bar->size);

  if (before_area_size > 0)
    {
      auto region = Vmm::Region::ss(Vmm::Guest_addr(before_area_begin),
                                    before_area_size, Vmm::Region_type::Vbus);

      warn().printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());

      _vmm->add_mmio_device(region, make_device<Ds_handler>(m, 0));
    }

  if (after_area_size > 0)
    {
      auto region = Vmm::Region::ss(Vmm::Guest_addr(after_area_begin),
                                    after_area_size, Vmm::Region_type::Vbus);

      warn().printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());

      _vmm->add_mmio_device(region,
                            make_device<Ds_handler>(m, after_area_begin_rel));
    }
}

unsigned Pci_host_bridge::setup_msix_memory(
  Hw_pci_device *hwdev, cxx::Ref_ptr<Gic::Msix_controller> const &msix_ctrl)
{
  if (!hwdev->has_msix)
    return Pci_config_consts::Bar_num_max_type0;

  unsigned bir = hwdev->msix_cap.tbl.bir();
  if (bir < Pci_config_consts::Bar_num_max_type0)
    {
      if (msix_ctrl)
        register_msix_table_page(hwdev, bir, msix_ctrl);
      else
        warn().printf(
          "No MSI controller assigned to MSI-X device %s (devid=%u).\n",
          hwdev->dinfo.name, hwdev->dev_id);

      register_msix_bar(&hwdev->bars[bir], hwdev->msix_cap.tbl.offset());
      return bir;
    }
  else
    {
      warn().printf("Device %s (devid=%u) has invalid MSI-X bar: %u\n",
                    hwdev->dinfo.name, hwdev->dev_id, bir);
      return Pci_config_consts::Bar_num_max_type0;
    }
}

}} // namespace Vdev::Pci
