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

void
Generic_guest::load_device_tree_at(char const *name, l4_addr_t base,
                                 l4_size_t padding)
{
  _device_tree = _ram.load_file(name, base);

  auto dt = device_tree();
  dt.check_tree();
  dt.add_to_size(padding);
  Dbg().printf("Loaded device tree to %llx:%llx\n", _device_tree.get(),
               _device_tree.get() + dt.size());

  auto mem_node = dt.path_offset("/memory");
  mem_node.set_reg_val(_ram.vm_start(), _ram.size());
}

l4_size_t
Generic_guest::load_ramdisk_at(char const *ram_disk, l4_addr_t ramaddr)
{
  Dbg info(Dbg::Info);

  if (ramaddr < _ram.vm_start() || ramaddr >= _ram.vm_start() + _ram.size())
    L4Re::chksys(-L4_EINVAL, "Ramdisk begins outside physical RAM.");

  l4_addr_t offset = ramaddr - _ram.vm_start();
  l4_size_t size;
  auto initrd = _ram.load_file(ram_disk, offset, &size);
  info.printf("loaded ramdisk image %s to %llx:%llx\n", ram_disk,
              initrd.get(), initrd.get()+size);

  if (offset + size > _ram.size())
    L4Re::chksys(-L4_EINVAL, "Ramdisk does not fit into RAM.");

  if (overlaps_device_tree(initrd, L4virtio::Ptr<void>(initrd.get() + size)))
    L4Re::chksys(-L4_EINVAL, "Ramdisk overlaps with device tree.");

  if (has_device_tree())
    {
      auto node = device_tree().path_offset("/chosen");
      node.set_prop_address("linux,initrd-start", _ram.boot_addr(initrd));
      node.set_prop_address("linux,initrd-end", _ram.boot_addr(initrd) + size);
    }

  return size;
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

  if (overlaps_device_tree(start, end))
    L4Re::chksys(-L4_EINVAL, "Linux binary overlaps with device tree in RAM.");

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
  _memmap[Region::ss(base, size)] = dev;
  Dbg().printf("New mmio mapping: @ %llx %llx\n", base, size);
}
} // namespace
