/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
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
  /// Operating modes
  enum class Mode { No_dma, Identity, Iommu, Dma_offset, Iommu_identity };

  /// Information collected to base the operating mode decision on.
  struct Info
  {
    unsigned raw;

    CXX_BITFIELD_MEMBER(0, 0, vbus_present, raw);
    CXX_BITFIELD_MEMBER(1, 1, vbus_has_dma_devs, raw);
    CXX_BITFIELD_MEMBER(2, 2, io_mmu, raw);
    CXX_BITFIELD_MEMBER(3, 3, force_identity, raw);
    CXX_BITFIELD_MEMBER(4, 4, dma_phys_addr, raw);
    CXX_BITFIELD_MEMBER(5, 5, dt_dma_ranges, raw);

    void dump() const
    {
      info().printf("Sys Info:\n"
                    "\tvBus:            %i\n"
                    "\tDMA devs:        %i\n"
                    "\tIO-MMU:          %i\n"
                    "\tIdentity forced: %i\n"
                    "\tDMA phys addr:   %i\n"
                    "\tDT dma-ranges:   %i\n",
                    vbus_present().get(), vbus_has_dma_devs().get(),
                    io_mmu().get(),
                    force_identity().get(),
                    dma_phys_addr().get(), dt_dma_ranges().get());
    }
  };

public:
  /**
   * Register a piece of RAM with the manager for use with an IO-MMU.
   *
   * \param vm_start  Start of the RAM region in VM memory.
   * \param start     Start of the local mapping of the RAM region.
   * \param size      Size of the RAM region.
   *
   * \return Error value.
   */
  void add_ram_iommu(Guest_addr vm_start, l4_addr_t start, l4_size_t size);

  /**
   * Register a piece of RAM for identity mapping and get the host physical
   * address and size.
   *
   * \param start       Start of the local mapping of the RAM region.
   * \param ds          Dataspace of the backing memory.
   * \param offset      Offset of the start address within the dataspace.
   * \param[out] start  corresponding host-physical address
   * \param[out] size   size of the corrsponding host-physical region.
   *
   * \return Error value of `dma_map()` operation.
   *
   * If identity mode was forced and an IO-MMU was detected, the KDMA space for
   * the IO-MMU is set up as well.
   */
  int get_phys_mapping(L4::Cap<L4Re::Dataspace> ds, l4_addr_t offset,
                       L4Re::Dma_space::Dma_addr *dma_start,
                       l4_size_t *size);

  /// Is the operating mode `Iommu`?
  bool is_iommu_mode() const { return _mode == Mode::Iommu; }
  /// Is the operating mode `Identity`?
  bool is_identity_mode() const { return _mode == Mode::Identity; }
  /// Is the operating mode `Dma_offset`?
  bool is_dma_offset_mode() const { return _mode == Mode::Dma_offset; }
  /// Is the operating mode `Iommu_identity`?
  bool is_iommu_identity_mode() const { return _mode == Mode::Iommu_identity; }
  /// Is the operating mode any of the indentity modes?
  bool is_any_identity_mode() const
  { return is_identity_mode() || is_iommu_identity_mode(); }

  /// Return the string representation of the current operating mode.
  char const *mode() const
  { return mode_to_str(_mode); }

  /**
   * Detect system information.
   *
   * \param vbus                 The vbus containing hardware devices.
   * \param force_identity_mode  true, if we must operate in identity mode.
   */
  void detect_sys_info(Virt_bus *vbus, bool force_identity_mode);

  /// True: the devie tree memory node has a 'dma-ranges' property.
  void info_add_dma_ranges() { _info.dt_dma_ranges() = 1; }

  /**
   * Start the mode selection based on the collected information.
   *
   * No DMA mode is selected, if the is no vBus or there are no DMA capable
   * devices on the vBus.
   *
   * DMA offset mode is used, if there is a DMA ranges property in the device
   * tree's memory node and DMA capable devices on the vBus. Forced identity
   * mappings supercede this mode.
   *
   * Identity mode is used if either forced or when there are DMA capable
   * devices and there is no DMA ranges property in the memory node of
   * the device tree.
   *
   * IO-MMU mode is selected, when there is an IO-MMU present in the system
   * and there are DMA capable devices on the vBus.
   * If this is the case and identity mappings are forced, the IO-MMU+Identity
   * mode is selected.
   *
   * \note The mode selection is just performed once. Subsequent calls do not
   *       change the selected mode.
   */
  void mode_selection();

private:
  static ::Dbg warn() { return {::Dbg::Mmio, ::Dbg::Warn, "ASM"}; }
  static ::Dbg info() { return {::Dbg::Mmio, ::Dbg::Info, "ASM"}; }
  static ::Dbg trace() { return {::Dbg::Mmio, ::Dbg::Trace, "ASM"}; }

  static char const *mode_to_str(Mode m)
  {
    switch(m)
      {
      case Mode::No_dma: return "No DMA";
      case Mode::Identity: return "Identity";
      case Mode::Iommu: return "IO-MMU";
      case Mode::Dma_offset: return "DMA-offset";
      case Mode::Iommu_identity: return "IO-MMU+identity";
      default: return "Invalid mode value";
      }
  }

  Info _info{0};
  bool _mode_selected = false;
  Mode _mode = Mode::No_dma;
  L4Re::Util::Unique_cap<L4::Task> _kdma_space;
  L4Re::Util::Unique_cap<L4Re::Dma_space> _dma_space;
}; // class Address_space_manager

} // namespace Vmm
