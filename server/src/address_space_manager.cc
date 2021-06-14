/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#include "address_space_manager.h"

namespace Vmm {

int Address_space_manager::get_phys_mapping(L4::Cap<L4Re::Dataspace> ds,
                                            l4_addr_t offset,
                                            L4Re::Dma_space::Dma_addr *dma_start,
                                            l4_size_t *size)
{
  assert(_dma_space);

  int err = _dma_space->map(L4::Ipc::make_cap(ds, L4_CAP_FPAGE_RW), offset,
                            size, L4Re::Dma_space::Attributes::None,
                            L4Re::Dma_space::Bidirectional, dma_start);

  return err;
}

void Address_space_manager::add_ram_iommu(Guest_addr vm_start, l4_addr_t start,
                                          l4_size_t size)
{
  l4_addr_t target_addr = vm_start.get();
  l4_addr_t end = start + size - 1;

  warn().printf("Add RAM Iommu: [0x%lx, 0x%lx] -> [0x%lx, 0x%lx]\n", start,
                end, target_addr, target_addr + size - 1);

  l4_addr_t addr = l4_trunc_page(start);
  unsigned char order =
    l4_fpage_max_order(L4_LOG2_PAGESIZE, start, addr, start + size);

  // map all pages of region into DMA space
  while (start < end)
    {
      L4Re::chksys(_kdma_space->map(L4Re::This_task,
                                    l4_fpage(start, order, L4_FPAGE_RWX),
                                    target_addr),
                   "Map guest RAM into KDMA space");
      start += 1UL << order;
      target_addr += 1UL << order;
    }
}

void Address_space_manager::detect_sys_info(Virt_bus *vbus,
                                            bool force_identity_mode)
{
  _info.force_identity() = force_identity_mode;
  if (force_identity_mode)
    {
      auto dma_space =
        L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dma_space>(),
                     "Allocate DMA space capability");
      L4Re::chksys(L4Re::Env::env()->user_factory()->create(dma_space.get()),
                   "Create DMA space.");

      if (dma_space->associate(L4::Ipc::Cap<L4::Task>(),
                               L4Re::Dma_space::Phys_space)
          >= 0)
        _info.dma_phys_addr() = 1;

      _dma_space = std::move(dma_space);
    }

  if (!vbus->available())
    {
      _info.dump();
      return;
    }

  _info.vbus_present() = 1;

  // We have a vBus, can we create the KDMA space and assign it to the vbus'
  // DMA domain?
  auto kdma = L4Re::chkcap(L4Re::Util::make_unique_cap<L4::Task>(),
                           "Allocate KDMA Task capability");

  // If we cannot create a KDMA space, we don't have an IO-MMU.
  int err = l4_error(
    L4Re::Env::env()->factory()->create(kdma.get(), L4_PROTO_DMA_SPACE));

  if (err >= L4_EOK)
    {
      _info.io_mmu() = 1;
      _kdma_space = std::move(kdma);

      // If we cannot assign DMA Domain ~0U, the vBus has no DMA capable devices.
      err = vbus->bus()->assign_dma_domain(~0U,
                                           L4VBUS_DMAD_BIND
                                             | L4VBUS_DMAD_KERNEL_DMA_SPACE,
                                           _kdma_space.get());
      if (err >= L4_EOK)
        _info.vbus_has_dma_devs() = 1;
      else
        info().printf("Can not assign KDMA space to vBus (%i). No DMA capable "
                      "devices configured.\n", err);
    }
  else
    {
      // if we already have a _dma_space due to the force flag, use it.
      if (!_info.force_identity())
        {
          auto dma_space =
            L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dma_space>(),
                         "Allocate DMA space capability");
          err =
            l4_error(L4Re::Env::env()->user_factory()->create(dma_space.get()));

          if (err >= L4_EOK)
            {
              if (dma_space->associate(L4::Ipc::Cap<L4::Task>(),
                                       L4Re::Dma_space::Phys_space)
                  >= 0)
                _info.dma_phys_addr() = 1;

              _dma_space = std::move(dma_space);
            }
          else
            info().printf("DMA space creation failed (%i).\n", err);
        }

      if (_dma_space)
        {
          // If we cannot assign DMA Domain ~0U, the vBus has no DMA capable
          // devices.
          err = vbus->bus()->assign_dma_domain(~0U,
                                               L4VBUS_DMAD_BIND
                                                 | L4VBUS_DMAD_L4RE_DMA_SPACE,
                                               _dma_space.get());

          if (err >= L4_EOK)
            _info.vbus_has_dma_devs() = 1;
          else
            info()
              .printf("Can not assign KDMA space to vBus (%i). No DMA capable "
                      "devices configured.\n", err);
        }
    }

  _info.dump();
}

void Address_space_manager::mode_selection()
{
  if (_mode_selected)
    return;

  _mode_selected = true;

  if (_info.force_identity() || _info.dma_phys_addr())
    {
      // The _dma_space is either Phys_space associated or Io associated it.
      // We need the Phys_space association.
      assert(_dma_space);
      L4Re::chksys(_dma_space->associate(L4::Ipc::Cap<L4::Task>(),
                                        L4Re::Dma_space::Phys_space),
                   "Access physical address space mappings.");
    }

  if (_info.force_identity())
    {
      _mode = _info.io_mmu() ? Mode::Iommu_identity : Mode::Identity;
      info().printf("Operating mode: %s (Identity forced)\n",
                    mode_to_str(_mode));
      return;
    }

  if (!_info.vbus_present())
    {
      _mode = Mode::No_dma;
      info().printf("Operating mode: %s\n", mode_to_str(_mode));
      return;
    }

  if (_info.io_mmu())
    {
      if (_info.vbus_has_dma_devs())
        _mode = Mode::Iommu;
      else
        _mode = Mode::No_dma;
    }
  else
    {
      if (_info.vbus_has_dma_devs())
        _mode = _info.dt_dma_ranges() ? Mode::Dma_offset : Mode::Identity;
      else
        _mode = Mode::No_dma;
    }

  info().printf("Operating mode: %s\n", mode_to_str(_mode));
}
} // namespace Vmm
