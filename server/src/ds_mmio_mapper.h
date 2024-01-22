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
#include "ds_manager.h"

#ifndef MAP_OTHER
/**
 * Ds_handler represents a dataspace-backed region in the VMs memory
 * map.
 *
 * This version uses VMM local mappings for the dataspace and forwards
 * pages to the VM using L4::Task::map.
 *
 * The dataspace and the VMM local mapping is managed by the associated
 * Ds_manager. The VMM local mapping is created lazily, either on first
 * access() or map_eager() calls.
 */
class Ds_handler : public Vmm::Mmio_device
{
public:
  enum Flags
  {
    None = 0x0,
    Map_eager = 0x1
  };

  explicit Ds_handler(cxx::Ref_ptr<Vmm::Ds_manager> ds,
                      L4_fpage_rights rights = L4_FPAGE_RW,
                      l4_addr_t offset = 0, Flags flags = Map_eager)
  : _ds(ds), _rights(rights), _offset(offset), _flags(flags)
  {
    l4_addr_t page_offs = offset & ~L4_PAGEMASK;
    if (page_offs)
      Dbg(Dbg::Mmio, Dbg::Warn)
        .printf("Region not page aligned\n");
  }

private:
  /// manager for a portion of a dataspace + local mapping
  cxx::Ref_ptr<Vmm::Ds_manager> _ds;

  /// Stores the rights for the mapping into the guest
  L4_fpage_rights _rights;

  /// Stores the offset relative to the offset in the Ds_manager
  l4_addr_t _offset;

  /// Special properties of the dataspace
  Flags _flags;

  /**
   * Get the full offset from the start of the dataspace.
   *
   * This is mainly useful for implementing _mergable().
   */
  l4_addr_t full_offset() const
  { return _offset + _ds->offset(); }

  /**
   * Get the VMM local address for this part of the dataspace
   * represented by this Ds_handler.
   *
   * NOTE: this function might create a VMM local mapping of the
   * dataspace part managed by the Ds_manager (_ds).
   */
  l4_addr_t local_start() const
  {
    return _ds->local_addr<l4_addr_t>() + _offset;
  }

  bool _mergable(cxx::Ref_ptr<Mmio_device> other,
                 Vmm::Guest_addr start_other, Vmm::Guest_addr start_this) override
  {
    // same device type and same underlying dataspace?
    auto dsh = dynamic_cast<Ds_handler *>(other.get());
    if (!dsh || (_ds->dataspace() != dsh->_ds->dataspace()))
      return false;

    // same rights?
    if (_rights != dsh->_rights)
      return false;

    // reference the same part of the data space?
    return (full_offset() + (start_other - start_this)) == dsh->full_offset();
  }

  /// map the memory into the guest. (this might establish a VMM local mapping)
  void map_eager(L4::Cap<L4::Vm> vm_task, Vmm::Guest_addr start,
                 Vmm::Guest_addr end) override
  {
    if (_flags & Map_eager)
      map_guest_range(vm_task, start, local_start(), end - start + 1, _rights);
  }

  /**
   * Map an MMIO region to the guest.
   *
   * \param pfa      Guest-physical page fault address.
   * \param offset   Offset of the page fault into the MMIO region.
   * \param vcpu     Virtual CPU from which the memory was accessed.
   * \param vm_task  VM task capability.
   * \param min      Guest-physical address of the MMIO region's first byte.
   * \param max      Guest-physical address of the MMIO region's last byte.
   */
  int access(l4_addr_t pfa, l4_addr_t offset, Vmm::Vcpu_ptr vcpu,
             L4::Cap<L4::Vm> vm_task, l4_addr_t min, l4_addr_t max) override
  {
    long res;
    l4_addr_t ls = local_start();
    // Make sure that the page is currently mapped.
    res = page_in(ls + offset, vcpu.pf_write());

    if (res >= 0)
      {
        // We assume that the region manager provided the largest possible
        // page size and try to map the largest possible page to the
        // client.
        unsigned char ps = get_page_shift(pfa, min, max, offset, ls);

        if (vcpu.pf_write() && !(_rights & L4_FPAGE_W))
          {
            Err().printf(
              "not handling VM write access @ %lx ip=%lx on read-only area\n",
               pfa, vcpu->r.ip);
            return -L4_EPERM;
          }

        res = l4_error(
                vm_task->map(L4Re::This_task,
                             l4_fpage(l4_trunc_size(ls + offset, ps),
                                      ps, _rights),
                             l4_trunc_size(pfa, ps)));
      }

    if (res < 0)
      {
        Err().printf("cannot handle VM memory access @ %lx ip=%lx r=%ld\n",
                     pfa, vcpu->r.ip, res);
        return res;
      }

    return Vmm::Retry;
  }

  char const *dev_name() const override { return _ds->dev_name(); }

  char const *dev_info(char *buf, size_t size) const override
  {
    snprintf(buf, size, "%s: DS local=%lx cap=%lx offset=%lx",
             dev_name(), _ds->local_addr<unsigned long>(),
             _ds->dataspace().cap(),
             static_cast<long>(_ds->offset()) + _offset);
    buf[size - 1] = '\0';
    return buf;
  }

};

#else /* MAP_OTHER */

/**
 * Ds_handler represents a dataspace-backed region in the VMs memory
 * map.
 *
 * This version maps the dataspace directly from the dataspace into the VM,
 * without creating VMM local mappings. If such mappings are needed the
 * Ds_manager interface must be used.
 */
class Ds_handler : public Vmm::Mmio_device
{
public:
  enum Flags
  {
    None = 0x0,
    Map_eager = 0x1
  };

  explicit Ds_handler(cxx::Ref_ptr<Vmm::Ds_manager> const &ds,
                      L4_fpage_rights rights = L4_FPAGE_RW,
                      l4_addr_t offset = 0, Flags flags = Map_eager)
  : _ds(ds->dataspace()), _rights(rights), _offset(ds->offset() + offset)
  {
    (void)flags;
  }

private:
  /// just keep the dataspace cap (no local region is needed)
  L4Re::Util::Ref_cap<L4Re::Dataspace>::Cap _ds;

  /// store the rights for the mapping into the guest
  L4_fpage_rights _rights;

  /// store the offset relative to the start of the dataspace.
  l4_addr_t _offset;

  bool _mergable(cxx::Ref_ptr<Mmio_device> other,
                 Vmm::Guest_addr start_other, Vmm::Guest_addr start_this) override
  {
    // same device type and same underlying dataspace?
    auto dsh = dynamic_cast<Ds_handler *>(other.get());
    if (!dsh || (_ds != dsh->_ds))
      return false;

    // same rights?
    if (_rights != dsh->_rights)
      return false;

    // reference the same part of the data space?
    return (_offset + (start_other - start_this)) == dsh->_offset;
  }

  void map_eager(L4::Cap<L4::Vm> /*vm_task*/, Vmm::Guest_addr /*start*/,
                 Vmm::Guest_addr /*end*/) override
  {
    // eager mapping not yet supported
  }

  int access(l4_addr_t pfa, l4_addr_t offset, Vmm::Vcpu_ptr vcpu,
             L4::Cap<L4::Vm> vm_task, l4_addr_t min, l4_addr_t max) override
  {
    if (vcpu.pf_write() && !(_rights & L4_FPAGE_W))
      {
        Err().printf(
          "not handling VM write access @ %lx ip=%lx on read-only area\n",
           pfa, vcpu->r.ip);
        return -L4_EPERM;
      }

    long res = _ds->map(offset + _offset, L4Re::Dataspace::Flags(_rights),
                        pfa, min, max, vm_task);

    if (res < 0)
      {
        Err().printf("cannot handle VM memory access @ %lx ip=%lx r=%ld\n",
                     pfa, vcpu->r.ip, res);
        return res;
      }

    return Vmm::Retry;
  }

  char const *dev_name() const override { return _ds->dev_name(); }

  char const *dev_info(char *buf, size_t size) const override
  {
    snprintf(buf, size, "%s: DS cap=%lx offset=%lx",
             dev_name(), _ds.cap(), _offset);
    buf[size - 1] = '\0';
    return buf;
  }

};
#endif /* MAP_OTHER */
