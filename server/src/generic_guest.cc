/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/sys/cache.h>
#include <l4/sys/debugger.h>

#include "generic_guest.h"
#include "binary_loader.h"

namespace Vmm {

Generic_guest::Generic_guest(L4::Cap<L4Re::Dataspace> ram,
                             l4_addr_t vm_base, l4_addr_t boot_offset)
: _registry(&_bm),
  _ram(ram, vm_base, boot_offset),
  _task(L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4::Task>())),
  _device_tree(L4virtio::Ptr<void>::Invalid)
{
  // attach RAM to VM
  _memmap[Region::ss(_ram.vm_start(), _ram.size())]
    = Vdev::make_device<Ds_handler>(_ram.ram(), _ram.local_start());

  // create the VM task
  auto *e = L4Re::Env::env();
  L4Re::chksys(e->factory()->create(_task.get(), L4_PROTO_VM),
               "allocate vm");
  l4_debugger_set_object_name(_task.get().cap(), "vm-task");
}

Cpu
Generic_guest::create_cpu()
{
  auto *e = L4Re::Env::env();
  l4_addr_t vcpu_addr = 0x10000000;

  L4Re::chksys(e->rm()->reserve_area(&vcpu_addr, L4_PAGESIZE,
                                     L4Re::Rm::Search_addr));
  L4Re::chksys(e->task()->add_ku_mem(l4_fpage(vcpu_addr, L4_PAGESHIFT,
                                              L4_FPAGE_RWX)),
               "kumem alloc");

  Cpu vcpu = Cpu((l4_vcpu_state_t *)vcpu_addr);
  vcpu.thread_attach();
  vcpu->user_task = _task.get().cap();

  return vcpu;
}

L4virtio::Ptr<void>
Generic_guest::load_device_tree_at(char const *name, L4virtio::Ptr<void> addr,
                                   l4_size_t padding)
{
  _device_tree = _ram.load_file(name, addr);

  auto dt = device_tree();
  dt.check_tree();
  // use 1.25 * size + padding for the time being
  dt.add_to_size(dt.size() / 4 + padding);
  Dbg().printf("Loaded device tree to %llx:%llx\n", _device_tree.get(),
               _device_tree.get() + dt.size());

  // Round to the next page to load anything else to a new page.
  return l4_round_size(L4virtio::Ptr<void>(addr.get() + dt.size()),
                       L4_PAGESHIFT);
}

void
Generic_guest::update_device_tree(char const *cmd_line)
{
  // We assume that "/choosen" and "/memory" are present
  auto dt = device_tree();
  if (cmd_line)
    {
      auto node = dt.path_offset("/chosen");
      node.setprop_string("bootargs", cmd_line);
    }
  auto mem_node = dt.path_offset("/memory");
  mem_node.set_reg_val(_ram.vm_start(), _ram.size());

  l4_addr_t dma_base;
  l4_size_t dma_size;
  _ram.dma_area(&dma_base, &dma_size);
  int addr_cells = mem_node.get_address_cells();
  mem_node.setprop("dma-ranges", dma_base, addr_cells);
  mem_node.appendprop("dma-ranges", _ram.vm_start(), addr_cells);
  mem_node.appendprop("dma-ranges", dma_size, mem_node.get_size_cells());
}

void
Generic_guest::set_ramdisk_params(L4virtio::Ptr<void> addr, l4_size_t size)
{
  if (!size)
    return;

  // We assume that "/choosen" is present
  auto dt = device_tree();

  auto node = dt.path_offset("/chosen");
  node.set_prop_address("linux,initrd-start", addr.get());
  node.set_prop_address("linux,initrd-end", addr.get() + size);

}

L4virtio::Ptr<void>
Generic_guest::load_ramdisk_at(char const *ram_disk, L4virtio::Ptr<void> addr,
                               l4_size_t *size)
{
  Dbg info(Dbg::Info);

  l4_size_t tmp;
  auto initrd = _ram.load_file(ram_disk, addr, &tmp);

  if (size)
    *size = tmp;

  // Round to the next page to load anything else to a new page.
  auto res = l4_round_size(L4virtio::Ptr<void>(initrd.get() + tmp),
                           L4_PAGESHIFT);
  info.printf("Loaded ramdisk image %s to [%llx:%llx] (%08zx)\n", ram_disk,
              initrd.get(), res.get() - 1, tmp);
  return res;
}

L4virtio::Ptr<void>
Generic_guest::load_binary_at(char const *kernel, l4_addr_t offset,
                              l4_addr_t *entry)
{
  L4virtio::Ptr<void> start, end;
  Boot::Binary_ds kbin(kernel);

  if (kbin.is_elf_binary())
    {
      *entry = kbin.load_as_elf(&_ram);

      l4_addr_t lstart, lend;
      kbin.elf_addr_bounds(&lstart, &lend);

      start = _ram.boot2guest_phys<void>(lstart);
      end = _ram.boot2guest_phys<void>(lend);
    }
  else
    {
      l4_size_t sz;
      start = _ram.load_file(kernel, offset, &sz);
      end = L4virtio::Ptr<void>(start.get() + sz);
    }

  l4_cache_coherent((unsigned long) _ram.access(start),
                    (unsigned long) _ram.access(end));

  return end;
}


void
Generic_guest::register_mmio_device(cxx::Ref_ptr<Vmm::Mmio_device> &&dev,
                                    Vdev::Dt_node const &node, int index)
{
  l4_uint64_t base, size;
  node.get_reg_val(index, &base, &size);

  auto region = Region::ss(base, size);

  if (_memmap.count(region) > 0)
    L4Re::chksys(-L4_ENOMEM, "overlapping MMIO regions");

  _memmap[region] = dev;
  Dbg().printf("New mmio mapping: @ %llx %llx\n", base, size);
}
} // namespace
