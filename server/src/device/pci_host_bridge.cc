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
}} // namespace Vdev::Pci
