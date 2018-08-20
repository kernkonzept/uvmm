/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/cxx/minmax>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/l4re_vfs/backend>

#include "debug.h"
#include "vm_memmap.h"
#include "vm_ram.h"

namespace {

class Auto_fd
{
public:
  explicit Auto_fd(int fd) : _fd(fd) {}
  Auto_fd(Auto_fd &&) = delete;
  Auto_fd(Auto_fd const &) = delete;

  ~Auto_fd()
  {
    if (_fd >= 0)
      close(_fd);
  }

  int get() const { return _fd; }

private:
  int _fd;
};

}

static Dbg warn(Dbg::Core, Dbg::Warn, "ram");
static Dbg info(Dbg::Core, Dbg::Info, "ram");
static Dbg trace(Dbg::Core, Dbg::Trace, "ram");

bool
Vmm::Ram_free_list::reserve_fixed(l4_addr_t start, l4_size_t size)
{
  for (auto it = _freelist.begin(); it != _freelist.end(); ++it)
    {
      if (!it->contains(Region::ss(start, size)))
        continue;

      if (start == it->start)
        *it = Region(start + size, it->end);
      else
        {
          auto oldend = it->end;
          *it = Region(it->start, start - 1);

          if (oldend >= start + size)
            _freelist.insert(it + 1, Region(start + size, oldend));
        }

      return true;
    }

  return false;
}

bool
Vmm::Ram_free_list::reserve_back(l4_size_t size, l4_addr_t *start,
                                 unsigned char page_shift)
{
  for (auto rit = _freelist.rbegin(); rit != _freelist.rend(); ++rit)
    {
      if (rit->end - rit->start + 1 < size)
        continue;

      *start = l4_trunc_size(rit->end - size + 1, page_shift);

      if (*start < rit->start)
        continue;

      return reserve_fixed(*start, size);
    }

  return false;
}

long
Vmm::Ram_free_list::load_file_to_back(Vm_ram *ram, char const *name,
                                      L4virtio::Ptr<void> *start, l4_size_t *size)
{
  Auto_fd fd(open(name, O_RDONLY));
  if (fd.get() < 0)
    {
      Err().printf("could not open file: %s\n", name);
      L4Re::chksys(-L4_EINVAL);
    }

  cxx::Ref_ptr<L4Re::Vfs::File> file = L4Re::Vfs::vfs_ops->get_file(fd.get());
  if (!file)
    {
      Err().printf("bad file descriptor: %s\n", name);
      L4Re::chksys(-L4_EINVAL);
    }

  L4::Cap<L4Re::Dataspace> f = file->data_space();
  if (!f)
    {
      Err().printf("could not get data space for %s\n", name);
      L4Re::chksys(-L4_EINVAL);
    }

  l4_addr_t addr;
  l4_size_t sz = f->size();

  if (!reserve_back(sz, &addr, L4_SUPERPAGESHIFT))
    return -L4_ENOMEM;

  info.printf("load: %s -> 0x%lx\n", name, addr);

  if (start)
    *start = L4virtio::Ptr<void>(addr);
  if (size)
    *size = sz;

  ram->load_file(f, L4virtio::Ptr<void>(addr), sz);

  return L4_EOK;
}

l4_size_t
Vmm::Vm_ram::add_memory_region(L4::Cap<L4Re::Dataspace> ds, l4_addr_t baseaddr,
                               l4_addr_t ds_offset, l4_size_t size, Vm_mem *memmap)
{
  Ram_ds r(ds, size, ds_offset);

  if (r.setup(baseaddr) < 0)
    return -1;

  auto dsdev = Vdev::make_device<Ds_handler>(ds, r.local_start(), r.size(),
                                             ds_offset);
  memmap->add_mmio_device(Region::ss(r.vm_start(), r.size()), std::move(dsdev));

  _regions.push_back(std::move(r));

  return _regions.size() - 1;
}


Vmm::Ram_free_list
Vmm::Vm_ram::setup_from_device_tree(Vdev::Host_dt const &dt, Vm_mem *memmap,
                                    l4_addr_t default_address)
{
  bool has_memory_nodes = false;

  if (dt.valid())
    {
      dt.get().scan(
        [this, &memmap, &has_memory_nodes](Vdev::Dt_node const &node, int)
          {
            char const *devtype = node.get_prop<char>("device_type", nullptr);

            if (!devtype || strcmp("memory", devtype) != 0)
              return true;

            if (add_from_dt_node(memmap, &has_memory_nodes, node) < 0)
              node.setprop_string("status", "disabled");

            // memory nodes should not have children, so no point in further
            // scanning
            return false;
          },
          [] (Vdev::Dt_node const &, unsigned) {});

      int err = dt.get().remove_nodes_by_property("device_type", "memory", true);
      if (err < 0)
        {
          Err().printf("Unable to remove disabled memory nodes: %s\n",
                       fdt_strerror(err));
          throw L4::Runtime_error(-L4_EINVAL);
        }
    }

  if (!has_memory_nodes)
    setup_default_region(dt, memmap, default_address);
  else if (_regions.empty())
    L4Re::chksys(-L4_ENOMEM, "Memory configuration in device tree provides no valid RAM");

  Ram_free_list list;
  L4::Cap<L4Re::Dataspace> main_ds = _regions[0].ds();

  for (auto const &r : _regions)
    {
      if (r.ds() != main_ds)
        break;

      list.add_free_region(r.vm_start(), r.size());
    }

  return list;
}


long
Vmm::Vm_ram::add_from_dt_node(Vm_mem *memmap, bool *found, Vdev::Dt_node const &node)
{
  int sz;
  char const *dscap = node.get_prop<char>("l4vmm,dscap", &sz);

  if (!dscap)
    return -L4_ENOSYS;

  *found = true;
  auto ds = L4Re::Env::env()->get_cap<L4Re::Dataspace>(dscap);

  if (!ds.is_valid())
    return -L4_EINVAL;

  L4Re::Dataspace::Stats ds_stats;
  L4Re::chksys(ds->info(&ds_stats));

  l4_addr_t offset = 0;
  l4_uint64_t remain = ds_stats.size;

  int reg_idx = 0;

  // so we can iterate later over new regions
  l4_size_t first_region = _regions.size();
  // dma-ranges can only be set for all regions or none
  bool add_dma_ranges = node.has_prop("dma-ranges");

  if (node.has_prop("l4vmm,physmap"))
    {
      trace.printf("%s: trying identity mapping.\n", node.get_name());
      long ridx = add_memory_region(ds, Ram_ds::Ram_base_identity_mapped, 0,
                                    remain, memmap);

      if (ridx >= 0)
        remain = 0; // we are done
      else
        {
          warn.printf("Memory region '%s' cannot be identity mapped.\n",
                      node.get_name());
          if (!node.has_prop("reg"))
            L4Re::chksys(-L4_ENOMEM, "Setup of RAM memory region");
        }
    }

  while (remain > 0)
    {
      l4_uint64_t reg_addr, reg_size;
      int ret = node.get_reg_val(reg_idx++, &reg_addr, &reg_size);

      if (ret == -Vdev::Dt_node::ERR_BAD_INDEX)
        break;

      if (ret < 0)
        L4Re::chksys(-L4_EINVAL, "Reading reg values.");

      trace.printf("Adding region @0x%llx (size = 0x%llx remaining = 0x%llx)\n",
                   reg_addr, reg_size, remain);

      l4_uint64_t map_size = cxx::min(reg_size, remain);

      if (map_size & ~L4_PAGEMASK)
        L4Re::chksys(-L4_EINVAL, "Size must be rounded to page size");

      if (reg_addr & ~L4_PAGEMASK)
        L4Re::chksys(-L4_EINVAL, "Start address must be rounded to page size");

      long ridx = add_memory_region(ds, reg_addr, offset, map_size, memmap);
      if (ridx < 0)
        L4Re::chksys(-L4_ENOMEM, "Setting up RAM region.");

      remain -= map_size;
      offset += map_size;

      if (!_regions[ridx].has_phys_addr())
        add_dma_ranges = false;
    }

  if (first_region == _regions.size())
    return -L4_ENOMEM; // no regions found, disable

  // update the regs property
  bool append = false;
  for (l4_size_t i = first_region; i < _regions.size(); ++i)
    {
      node.set_reg_val(_regions[i].vm_start(), _regions[i].size(), append);
      append = true;

      if (add_dma_ranges)
        _regions[i].dt_append_dmaprop(node);
    }

  if (!add_dma_ranges)
    node.delprop("dma-ranges");

  return L4_EOK;
}

void
Vmm::Vm_ram::setup_default_region(Vdev::Host_dt const &dt, Vm_mem *memmap,
                                  l4_addr_t baseaddr)
{
  auto ds = L4Re::chkcap(L4Re::Env::env()->get_cap<L4Re::Dataspace>("ram"));
  long ridx = add_memory_region(ds, baseaddr, 0, ds->size(), memmap);

  if (ridx < 0)
    L4Re::chksys(-L4_ENOMEM, "Setting up RAM region.");

  if (dt.valid())
    {
      auto const &r = _regions[ridx];
      // "memory@" + 64bit hex address + '\0'
      char buf[7 + 16 + 1];
      std::snprintf(buf, sizeof(buf), "memory@%lx", r.vm_start());

      auto node = dt.get().first_node().add_subnode(buf);
      node.setprop_string("device_type", "memory");
      node.set_reg_val(r.vm_start(), r.size());

      if (r.has_phys_addr())
        r.dt_append_dmaprop(node);
    }
}
