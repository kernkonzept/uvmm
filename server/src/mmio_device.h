/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once
#include <typeinfo>

#include <l4/cxx/ref_ptr>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/unique_cap>
#include <l4/sys/task>
#include <l4/sys/l4int.h>
#include <l4/sys/types.h>
#include <l4/util/util.h>

#include "device.h"
#include "vcpu_ptr.h"
#include "mem_access.h"
#include "consts.h"

namespace Vmm {

/**
 * Interface for any device that processes access to special guest-physical
 * memory regions.
 */
struct Mmio_device : public virtual Vdev::Dev_ref
{
  virtual ~Mmio_device() = 0;

  bool mergable(cxx::Ref_ptr<Mmio_device> other,
                l4_addr_t start_other, l4_addr_t start_this)
  {
    if (typeid (*this) != typeid (*other.get()))
      return false;
    return _mergable(other, start_other, start_this);
  };

  /**
   * Check whether a superpage containing address is inside a region
   *
   * \param addr     address to check
   * \param start    start of region.
   * \param end      end of region; do not check end of region if end is zero.
   * \return true if there is a superpage containing the address
   *                 inside the region
   */
  inline bool sp_in_range(l4_addr_t addr, l4_addr_t start, l4_addr_t end)

  {
    auto superpage = l4_trunc_size(addr, L4_SUPERPAGESHIFT);
    return    (start <= superpage)
           && (!end || ((superpage + L4_SUPERPAGESIZE - 1) <= end));
  }

  /**
   * Calculate log_2(pagesize) for a location in a region
   *
   * \param addr     Guest-physical address where the access occurred.
   * \param start    Guest-physical address of start of memory region.
   * \param end      Guest-physical address of end of memory region.
   * \param offset   Accessed address relative to the beginning of the region.
   * \param l_start  Local address of start of memory region.
   * \param l_end    Local address of end of memory region, default 0.
   * \return largest possible pageshift (currently either L4_PAGESHIFT
   *                 or L4_SUPERPAGESHIFT)
   */
  inline char get_page_shift(l4_addr_t addr, l4_addr_t start, l4_addr_t end,
                                 l4_addr_t offset, l4_addr_t l_start,
                                 l4_addr_t l_end = 0)
  {
    // Check whether a superpage is inside the regions
    if (   !sp_in_range(addr, start, end)
        || !sp_in_range(l_start + offset, l_start, l_end))
      return L4_PAGESHIFT;

    // Check whether both regions have a compatible alignment
    if ((start & (L4_SUPERPAGESIZE - 1)) != (l_start & (L4_SUPERPAGESIZE - 1)))
      return L4_PAGESHIFT;

    return L4_SUPERPAGESHIFT;
  }

  /**
   * Callback on memory access.
   *
   * \param pfa      Guest-physical address where the access occurred.
   * \param offset   Accessed address relative to the beginning of the
   *                 device's memory region.
   * \param vcpu     Virtual CPU from which the memory was accessed.
   * \param vm_task  Capability to the guest memory.
   * \param s        Guest-physical address of start of device memory region.
   * \param e        Guest-physical address of end of device memory region.
   *
   * \retval < 0         if memory access was faulty, the error code.
   * \retval Retry       if memory was mapped and access can be retried.
   * \retval Jump_instr  if memory access could be handled.
   * \
   */
  virtual int access(l4_addr_t pfa, l4_addr_t offset, Vcpu_ptr vcpu,
                     L4::Cap<L4::Task> vm_task, l4_addr_t s, l4_addr_t e) = 0;
  virtual char const *dev_info(char *buf, size_t size)
  {
    if (size > 0)
      {
        strncpy(buf, typeid(*this).name(), size);
        buf[size - 1] = '\0';
      }
    return buf;
  };

private:
  virtual bool _mergable(cxx::Ref_ptr<Mmio_device> /* other */,
                         l4_addr_t /* start_other */,
                         l4_addr_t /* start_this */)
  { return false; }
};

/**
 * Mixin for devices that trap read and write access to physical guest memory.
 *
 * The base class DEV needs to provide two functions read() and write() that
 * implement the actual functionality behind the memory access. Those
 * functions must be defined as follows:
 *
 *     l4_umword_t read(unsigned reg, char size, unsigned cpu_id);
 *
 *     void write(unsigned reg, char size, l4_umword_t value, unsigned cpu_id);
 *
 * `reg` is the address offset into the devices memory region. `size`
 * describes the width of the access (see Vmm::Mem_access::Width) and
 * `cpu_id` the accessing CPU (currently unused).
 */
template<typename DEV>
struct Mmio_device_t : Mmio_device
{
  int access(l4_addr_t pfa, l4_addr_t offset, Vcpu_ptr vcpu,
             L4::Cap<L4::Task>, l4_addr_t, l4_addr_t)
  {
    auto insn = vcpu.decode_mmio();

    if (insn.access == Vmm::Mem_access::Other)
      {
        Dbg(Dbg::Mmio, Dbg::Warn, "mmio")
          .printf("MMIO access @ 0x%lx: unknown instruction. Ignored.\n",
                  pfa);
        return -L4_ENXIO;
      }

    Dbg(Dbg::Mmio, Dbg::Trace, "mmio")
      .printf("MMIO access @ 0x%lx (0x%lx) %s, width: %u\n",
              pfa, offset,
              insn.access == Vmm::Mem_access::Load ? "LOAD" : "STORE",
              (unsigned) insn.width);

    if (insn.access == Vmm::Mem_access::Store)
      dev()->write(offset, insn.width, insn.value, vcpu.get_vcpu_id());
    else
      {
        insn.value = dev()->read(offset, insn.width, vcpu.get_vcpu_id());
        vcpu.writeback_mmio(insn);
      }

    return Jump_instr;
  }

private:
  DEV *dev()
  { return static_cast<DEV *>(this); }
};

/**
 * Mixin for virtual memory-mapped device that allows direct read access to
 * its memory region.
 *
 * \tparam BASE  Type of the device the mixin is used for.
 *
 * The device manages a dataspace of its memory region that is directly
 * mapped into the guest memory for reading. The device needs to take care
 * to keep the region up-to-date. Write access to the region still traps
 * into the VMM and needs to be handled programmatically.
 */
template<typename BASE>
struct Ro_ds_mapper_t : Mmio_device
{
  int access(l4_addr_t pfa, l4_addr_t offset, Vcpu_ptr vcpu,
             L4::Cap<L4::Task> vm_task, l4_addr_t min, l4_addr_t max)
  {
    auto insn = vcpu.decode_mmio();

    if (insn.access == Vmm::Mem_access::Other)
      {
        Dbg(Dbg::Mmio, Dbg::Warn, "mmio")
          .printf("MMIO access @ 0x%lx: unknown instruction. Ignored.\n",
                  pfa);
        return -L4_ENXIO;
      }

    Dbg(Dbg::Mmio, Dbg::Trace, "mmio")
      .printf("MMIO access @ 0x%lx (0x%lx) %s, width: %u\n",
              pfa, offset,
              insn.access == Vmm::Mem_access::Load ? "LOAD" : "STORE",
              (unsigned) insn.width);

    if (insn.access == Vmm::Mem_access::Store)
      dev()->write(offset, insn.width, insn.value, vcpu.get_vcpu_id());
    else
      {
        if (offset < dev()->mapped_mmio_size())
          map_mmio(pfa, offset, vm_task, min, max);

        insn.value = dev()->read(offset, insn.width, vcpu.get_vcpu_id());
        vcpu.writeback_mmio(insn);
      }

    return Jump_instr;
  }

  /**
   * Emulate a read access by accessing the dataspace backing the
   * MMIO region.
   * \param offset   The offset (in bytes) inside the MMIO region
   *                 (and inside the dataspace as the dataspace
   *                 starts at offset 0 in the MMIO region).
   * \param width   The width (in log2 bytes) of the memory access.
   * \param cpuid   The CPU that did the access (has to be ignored).
   *
   * \pre `offset + (1UL << width) <= mapped_mmio_size()`
   * \pre `offset <= 2GB`
   */
  l4_uint64_t read(unsigned offset, char width, unsigned cpuid)
  {
    (void) cpuid; // must be ignored by this implementation because
                  // we have no CPU-local mappings of our dataspace.
    if (0)
      printf("MMIO/RO/DS read: offset=%x (%u) [0x%lx] = %x\n", offset,
             (unsigned)width, local_addr() + offset,
             *((l4_uint32_t*)(local_addr() + offset)));

    // limit MMIO regions to 2GB
    assert (offset <= 0x80000000);
    assert (offset + (1UL << width) <= dev()->mapped_mmio_size());

    return Mem_access::read_width(local_addr() + offset, width);
  }

  void map_mmio(l4_addr_t pfa, l4_addr_t offset, L4::Cap<L4::Task> vm_task,
                l4_addr_t min, l4_addr_t max)
  {
#ifdef MAP_OTHER
    auto res = dev()->mmio_ds()->map(offset, 0, pfa, min, max, vm_task);
#else
    auto local_start = local_addr();
    unsigned char ps = get_page_shift(pfa, min, max, offset, local_start,
                                      local_start + dev()->mapped_mmio_size());

    // XXX make sure that the page is currently mapped
    l4_addr_t base = l4_trunc_size(local_start + offset, ps);
    l4_touch_ro((void *)base, 1 << ps);

    auto res = l4_error(vm_task->map(L4Re::This_task,
                                     l4_fpage(base, ps, L4_FPAGE_RX),
                                     l4_trunc_size(pfa, ps)));
#endif

    if (res < 0)
      Err().printf("Could not map to mmio address %lx. Ignored.\n", pfa);
  }

private:
  BASE *dev()
  { return static_cast<BASE *>(this); }

  BASE const *dev() const
  { return static_cast<BASE const *>(this); }

  l4_addr_t local_addr() const
  { return reinterpret_cast<l4_addr_t>(dev()->mmio_local_addr()); }
};

/**
 * Mixin for virtual memory-mapped device that allows direct read access to
 * its memory region.
 *
 * \tparam BASE  Type of the device the mixin is used for.
 * \tparam T     Data type for the device memory region.
 *
 * The device manages a dataspace of its memory region that is directly
 * mapped into the guest memory for reading. The device needs to take care
 * to keep the region up-to-date. Write access to the region still traps
 * into the VMM and needs to be handled programmatically.
 */
template<typename BASE, typename T>
struct Read_mapped_mmio_device_t : Ro_ds_mapper_t<BASE>
{
  /**
   * Construct a partially mapped MMIO region.
   *
   * \param size      Size of the region that is mapped read-only
   *                  to the guest.
   * \param rm_flags  Additional properties to set for RM.
   *                  Default is that the dataspace is mapped uncached
   *                  into VMM and guest dataspace because operating
   *                  systems normally expect device memory to be uncached.
   *
   * Allocates a new dataspace of the given size and makes it available
   * for the VMM for reading/writing.
   *
   * \note The device may cover an area that is larger than the area covered
   *       by the dataspace mapped into the guest. Any read access outside
   *       the area then needs to be emulated as in the standard MMIO device.
   */
  explicit Read_mapped_mmio_device_t(l4_size_t size,
                                     unsigned rm_flags = L4Re::Rm::Cache_uncached)
  : _mapped_size(size)
  {
    auto *e = L4Re::Env::env();
    auto ds = L4Re::chkcap(L4Re::Util::make_unique_del_cap<L4Re::Dataspace>());
    L4Re::chksys(e->mem_alloc()->alloc(size, ds.get()));

    L4Re::Rm::Unique_region<T *> mem;
    L4Re::chksys(e->rm()->attach(&mem, size,
                                 L4Re::Rm::Search_addr | rm_flags,
                                 L4::Ipc::make_cap_rw(ds.get())));

    _mmio_region = cxx::move(mem);
    _ds = cxx::move(ds);
  }

  l4_size_t mapped_mmio_size() const
  { return _mapped_size; }

  L4::Cap<L4Re::Dataspace> mmio_ds() const
  { return _ds.get(); }

  T *mmio_local_addr() const
  { return _mmio_region.get(); }

private:
  L4Re::Util::Unique_del_cap<L4Re::Dataspace> _ds;

protected:
  L4Re::Rm::Unique_region<T *> _mmio_region;
  l4_size_t _mapped_size;
};

inline Mmio_device::~Mmio_device() = default;

} // namespace
