/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/dataspace>
#include <l4/util/util.h>
#include <cstdio>

#include "mmio_device.h"
#include "vcpu_ptr.h"

class Ds_handler : public Vmm::Mmio_device
{
  L4::Cap<L4Re::Dataspace> _ds;
  l4_addr_t _offset;

  bool _mergable(cxx::Ref_ptr<Mmio_device> other,
                 l4_addr_t start_other, l4_addr_t start_this) override
  {
    // same device type and same underlying dataspace?
    auto dsh = dynamic_cast<Ds_handler *>(other.get());
    if (!dsh || (_ds != dsh->_ds))
      return false;

    // reference the same part of the data space?
    return (_offset + (start_other - start_this)) == dsh->_offset;
  }

  void map_eager(L4::Cap<L4::Task> vm_task, l4_addr_t start,
                 l4_addr_t end) override
  {
#ifndef MAP_OTHER
    map_guest_range(vm_task, start, local_start(), end - start + 1,
                    L4_FPAGE_RWX);
#endif
  }

  int access(l4_addr_t pfa, l4_addr_t offset, Vmm::Vcpu_ptr vcpu,
             L4::Cap<L4::Task> vm_task, l4_addr_t min, l4_addr_t max) override
  {
    long res;
#ifdef MAP_OTHER
    res = _ds->map(offset + _offset,
                   vcpu.pf_write() ? L4Re::Dataspace::Map_rw : 0,
                   pfa, min, max, vm_task);
#else
    // Make sure that the page is currently mapped.
    res = page_in(_local_start + offset, true);

    if (res >= 0)
      {
        // We assume that the region manager provided the largest possible
        // page size and try to map the largest possible page to the
        // client.
        unsigned char ps = get_page_shift(pfa, min, max, offset, _local_start);

        res = l4_error(
                vm_task->map(L4Re::This_task,
                             l4_fpage(l4_trunc_size(_local_start + offset, ps),
                                      ps, L4_FPAGE_RWX),
                             l4_trunc_size(pfa, ps)));
      }
#endif

    if (res < 0)
      {
        Err().printf("cannot handle VM memory access @ %lx ip=%lx r=%ld\n",
                     pfa, vcpu->r.ip, res);
        return res;
      }

    return Vmm::Retry;
  }

  char const *dev_info(char *buf, size_t size) const override
  {
#ifndef MAP_OTHER
    snprintf(buf, size, "mmio ds: [%lx - ?] -> [%lx:%lx - ?]",
             _local_start, _ds.cap(), _offset);
#else
    snprintf(buf, size, "mmio ds: [? - ?] -> [%lx:%lx - ?]",
             _ds.cap(), _offset);
#endif
    return buf;
  }

  l4_addr_t _local_start;

public:
  explicit Ds_handler(L4::Cap<L4Re::Dataspace> ds,
                      l4_addr_t local_start,
                      l4_size_t size,
                      l4_addr_t offset = 0)
    : _ds(ds), _offset(offset), _local_start(local_start)
  {
    assert(size);
#ifndef MAP_OTHER
    if (local_start == 0)
      {
        auto rm = L4Re::Env::env()->rm();
        L4Re::chksys(rm->attach(&_local_start, size,
                                L4Re::Rm::Search_addr | L4Re::Rm::Eager_map,
                                L4::Ipc::make_cap_rw(ds), offset,
                                L4_SUPERPAGESHIFT));
      }

    l4_addr_t page_offs = offset & ~L4_PAGEMASK;
    if (page_offs)
      {
        auto tmp = l4_trunc_page(_local_start) + page_offs;
        Dbg(Dbg::Mmio, Dbg::Warn)
          .printf("Region not page aligned, adjusting local_start: %lx -> %lx\n",
                  _local_start, tmp);
        _local_start = tmp;
      }
#endif
  }

  l4_addr_t local_start() const { return _local_start; }
};
