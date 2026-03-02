/*
 * Copyright (C) 2021-2022, 2024-2025 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include <l4/sys/cxx/consts>

#include "address_space_manager.h"
#include "consts.h"

namespace Vmm {

int Address_space_manager::add_ram(L4::Cap<L4Re::Dataspace>  ds,
                                   L4Re::Dataspace::Offset   offset,
                                   L4Re::Dma_space::Dma_addr *dma_start,
                                   L4Re::Dma_space::Dma_size *size,
                                   L4Re::Dma_space::Dma_addr dma_max)
{
  if (_dma_space)
    return _dma_space->map(L4::Ipc::make_cap(ds, L4_CAP_FPAGE_RW),
                           offset, size, dma_start, dma_max,
                           L4Re::Dma_space::Search_addr
                           | L4Re::Dma_space::Partial_map);
#ifndef CONFIG_MMU
  l4_addr_t ds_start;
  l4_addr_t ds_end;
  L4Re::chksys(ds->map_info(&ds_start, &ds_end), "get ram ds addr");
  l4_addr_t max_size = ds_end - ds_start + 1;
  if (offset >= max_size)
    return -L4_ERANGE;

  max_size -= offset;
  if (max_size < size)
    return -L4_ENOMEM;

  *dma_start = ds_start + offset;
#endif

  return 0;
}

void Address_space_manager::del_ram(Guest_addr dest, l4_size_t size)
{
  l4_addr_t dst_start = dest.get();
  l4_addr_t dst_end = dst_start + size - 1;

  // Must be page aligned
  assert(l4_trunc_page(dst_start) == dst_start);

  warn().printf("Remove RAM: [0x%lx, 0x%lx]\n", dst_start, dst_end);

  if (_dma_space)
    _dma_space->unmap(dst_start, size);
}

int Address_space_manager::reserve(L4Re::Dma_space::Dma_addr start,
                                   L4Re::Dma_space::Dma_size size)
{
#ifdef CONFIG_MMU
  if (_dma_space)
    return _dma_space->map(L4::Cap<L4Re::Dataspace>(), 0,
                           &size, &start, -1, L4Re::Dma_space::Reserve);

  return 0;
#else
  return -L4_EPERM;
#endif
}

int Address_space_manager::place_ram(L4::Cap<L4Re::Dataspace> ds,
                                     L4Re::Dataspace::Offset offset,
                                     L4Re::Dma_space::Dma_addr *start,
                                     L4Re::Dma_space::Dma_size *size)
{
#ifdef CONFIG_MMU
  if (_dma_space)
    return _dma_space->map(L4::Ipc::make_cap(ds, L4_CAP_FPAGE_RW), offset,
                           size, start, -1, L4Re::Dma_space::Replace);

  return 0;
#else
  return add_ram(ds, offset, start, *size);
#endif
}

void Address_space_manager::detect_sys_info(Virt_bus *vbus)
{
  if (!vbus->available())
    {
      info().printf("No vBus found. Running fully virtualized.\n");
      return;
    }

  auto dma_space =
    L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dma_space>(),
                 "Allocate DMA space capability");
  L4Re::chksys(L4Re::Env::env()->user_factory()->create(dma_space.get()),
               "Create DMA space.");

  // If we cannot assign DMA Domain ~0U, the vBus has no DMA capable devices.
  int err = vbus->bus()->assign_dma_domain(~0U, L4VBUS_DMAD_BIND,
                                           dma_space.get());

  if (err >= L4_EOK)
    {
      info().printf("Found vBus with DMA capable devices.\n");
      _dma_space = std::move(dma_space);
    }
  else if (err == -L4_ENOENT)
    info().printf("Found vBus w/o DMA capable devices.\n");
  else
    L4Re::throw_error(err, "Can not assign DMA space to vBus!");
}

} // namespace Vmm
