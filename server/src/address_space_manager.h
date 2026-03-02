/*
 * Copyright (C) 2021, 2023-2025 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/sys/task>
#include <l4/re/env>
#include <l4/re/dma_space>
#include <l4/cxx/bitfield>

#include "device.h"
#include "mem_types.h"
#include "virt_bus.h"
#include "debug.h"

namespace Vmm {

class Address_space_manager : public Vdev::Device
{
public:
  /**
   * Register a piece of RAM for DMA-mapping and get the DMA-capable
   * address and size.
   *
   * \param         ds        Dataspace of the backing memory.
   * \param         offset    Offset of the start address within the dataspace.
   * \param[in,out] dma_start corresponding DMA-capable address
   * \param         size      size of the corresponding DMA-capable region.
   * \param         dma_max   Highest guest physical address of the mapping.
   * \param         writable  Establish writable DMA mapping?
   */
  int add_ram(L4::Cap<L4Re::Dataspace> ds, L4Re::Dataspace::Offset offset,
              L4Re::Dma_space::Dma_addr *dma_start,
              L4Re::Dma_space::Dma_size *size,
              L4Re::Dma_space::Dma_addr dma_max,
              bool writable);

  /**
   * Delete a piece of RAM from the manager and the IO-MMU.
   *
   * \param dest      Start of the RAM region in VM memory.
   * \param size      Size of the RAM region.
   */
  void del_ram(Guest_addr dest, l4_size_t size);

  /**
   * Reserve RAM region.
   *
   * Makes sure that no DMA mappings can be created in the requested region by
   * any component in the system (e.g., io when mapping the MSI controller for
   * PCI devices). This is no-op of uvmm has no access to DMA capable devices.
   * In case the physical DMA address space is used (i.e., no IOMMU), the
   * function will fail with -L4_EPERM. A caller should be able to cope with
   * this error.
   *
   * \retval  >=0       Success
   * \retval  -L4_EPERM Identity mappings are needed. Reservations not allowed.
   * \retval  <0        Failure
   */
  int reserve(L4Re::Dma_space::Dma_addr start, L4Re::Dma_space::Dma_size size);

  /**
   * Place RAM into reserved region.
   *
   * Note that the call might return a different address if no IOMMU is
   * available.
   *
   * \param         ds     Dataspace of the backing memory.
   * \param         offset Offset of the start address within the dataspace.
   * \param[in,out] start  Base address of mapping
   * \param[in,out] size   Size of the mapping.
   */
  int place_ram(L4::Cap<L4Re::Dataspace> ds, L4Re::Dataspace::Offset offset,
                L4Re::Dma_space::Dma_addr *start,
                L4Re::Dma_space::Dma_size *size);

  /**
   * Detect system information.
   *
   * \param vbus                 The vbus containing hardware devices.
   */
  void detect_sys_info(Virt_bus *vbus);

private:
  static ::Dbg warn() { return {::Dbg::Mmio, ::Dbg::Warn, "ASM"}; }
  static ::Dbg info() { return {::Dbg::Mmio, ::Dbg::Info, "ASM"}; }
  static ::Dbg trace() { return {::Dbg::Mmio, ::Dbg::Trace, "ASM"}; }

  L4Re::Util::Unique_cap<L4Re::Dma_space> _dma_space;
}; // class Address_space_manager

} // namespace Vmm
