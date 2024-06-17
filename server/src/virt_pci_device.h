/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/sys/types.h>

#include "device_tree.h"
#include "mem_access.h"
#include "pci_device.h"
#include "mmio_device.h"
#include "io_device.h"
#include "device/pci_bridge_windows.h"

namespace Vdev { namespace Pci {

class Virt_pci_device:
  public Pci_device
{
public:
  Virt_pci_device()
  {
    memset(&_hdr, 0, sizeof(_hdr));
    _last_caps_next_ptr = &get_header<Pci_header::Type0>()->cap_ptr;
    _next_free_idx = 0x40; // first byte after the PCI header;
  }

  /**
   * Construct virtual PCI device from device tree node.
   *
   * This implies a type0 device.
   */
  Virt_pci_device(Vdev::Dt_node const &node, Pci_bridge_windows *wnds);

  /**
   * Read from the PCI header config.
   *
   * \param      reg    The config space register to read from.
   * \param[out] value  The value returned by the read. -1 if failed.
   * \param      width  The width of the register access.
   */
  void cfg_read_raw(unsigned reg, l4_uint32_t *value,
                    Vmm::Mem_access::Width width) override
  {
    using Vmm::Mem_access;

    *value = -1;

    if (!check_cfg_range(reg, width))
      return;

    reg >>= width;
    switch (width)
      {
      case Mem_access::Wd8: *value  = _hdr.byte[reg]; break;
      case Mem_access::Wd16: *value = _hdr.word[reg]; break;
      case Mem_access::Wd32: *value = _hdr.dword[reg]; break;
      case Mem_access::Wd64: *value = _hdr.qword[reg]; break;
      }

    trace().printf("read config 0x%x(%d) = 0x%x\n", reg, width,
                   static_cast<unsigned>(*value));
  }

  /**
   * Write to the PCI header config.
   *
   * \param reg    Register number to write to.
   * \param value  Value to write to `reg`.
   * \param width  Width of the memory access.
   */
  void cfg_write_raw(unsigned reg, l4_uint32_t value,
                     Vmm::Mem_access::Width width) override
  {
    using Vmm::Mem_access;

    if (!check_cfg_range(reg, width))
      return;

    if (   reg == Pci_hdr_status_offset
        && ((8U << width)) == Pci_hdr_status_length)
      return;

    reg >>= width;
    switch (width)
      {
      case Mem_access::Wd8:  _hdr.byte[reg] = value; break;
      case Mem_access::Wd16: _hdr.word[reg] = value; break;
      case Mem_access::Wd32: _hdr.dword[reg] = value; break;
      case Mem_access::Wd64: _hdr.qword[reg] = value; break;
      }

    trace().printf("write config 0x%x(%d) = 0x%x\n", reg, width, value);
  }

  /**
   * Create a PCI capability of type `T` in the device's capability table.
   *
   * \tparam T  Type of the capability to create. The type must have a Cap_id
   *            member defining the PCI capability ID.
   *
   * Allocate a new PCI capability in the PCI header config space and enqueue
   * it in the cap list.
   *
   * \return  Pointer to the new typed capability.
   */
  template <typename T>
  T *create_pci_cap()
  {
    // _next_free_idx: next location for a capability
    assert(_next_free_idx < sizeof(_hdr));
    assert(_last_caps_next_ptr < (l4_uint8_t *)(&_hdr + 1));

    l4_uint8_t cap_offset = align_min_dword<T>(_next_free_idx);

    // guard against wrap around of uint8
    assert(cap_offset >= 0x40);
    assert((unsigned)cap_offset + sizeof(T) < 0x100);

    T *ret = new (&_hdr.byte[cap_offset]) T();
    trace().printf("cap offset 0x%x, cap size 0x%zx\n", cap_offset,
                   sizeof(*ret));

    *_last_caps_next_ptr = cap_offset;
    _last_caps_next_ptr = &ret->cap_next;

    _next_free_idx = cap_offset + sizeof(*ret);

    trace().printf("indexes: cap's next ptr %p, next free byte 0x%x\n",
                   &_last_caps_next_ptr, _next_free_idx);

    ret->cap_next = 0;
    assert(ret->cap_type == T::Cap_id);
    return ret;
  }

  void add_decoder_resources(Vmm::Guest *vmm, l4_uint32_t access) override;
  void del_decoder_resources(Vmm::Guest *vmm, l4_uint32_t access) override;

  void add_exp_rom_resource() override {};
  void del_exp_rom_resource() override {};

private:
  template <typename TYPE>
  static void assert_header_type()
  {
    static_assert(    (std::is_same<Pci_header::Type0, TYPE>::value)
                   || (std::is_same<Pci_header::Type1, TYPE>::value),
                  "Invalid PCI header type requested.");
  }

  template <typename TYPE>
  static void assert_bar_type_size(unsigned bar)
  {
    static_cast<void>(bar);
    if (std::is_same<Pci_header::Type0, TYPE>::value)
      assert(bar < Bar_num_max_type0);
    else if (std::is_same<Pci_header::Type1, TYPE>::value)
      assert(bar < Bar_num_max_type1);
  }

  /**
   * Test if the requested access references a location inside the PCI
   * configuration.
   *
   * \param reg    Location inside the PCI header to be accessed.
   * \param width  Access width.
   *
   * \retval True  If the access falls inside the PCI configuration area.
   * \retval False Otherwise.
   */
  bool check_cfg_range(unsigned reg, Vmm::Mem_access::Width width) const
  {
    if (width == Vmm::Mem_access::Wd64)
      return false;

    unsigned w = 1U << width;
    bool ret = (reg + w) <= Pci_header_size;
    if (!ret)
      trace().printf("config access 0x%x(%d): out of range\n", reg, width);

    return ret;
  }

  inline void
  check_power_of_2(l4_uint64_t size, char const *err)
  {
    if (size & (size - 1))
      L4Re::chksys(-L4_EINVAL, err);
  }

protected:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "Virt PCI dev"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "Virt PCI dev"); }
  static Dbg dbg() { return Dbg(Dbg::Dev, Dbg::Warn, "Virt PCI dev"); }

  virtual cxx::Ref_ptr<Vmm::Mmio_device> get_mmio_bar_handler(unsigned bar) = 0;
  virtual cxx::Ref_ptr<Vmm::Io_device> get_io_bar_handler(unsigned bar) = 0;

  /**
   * Get a pointer to the header memory of type `TYPE`.
   *
   * \tparam TYPE  PCI header type 0 or 1.
   */
  template <typename TYPE>
  TYPE *get_header()
  {
    assert_header_type<TYPE>();

    return reinterpret_cast<TYPE *>(&_hdr);
  }

  template <typename TYPE>
  TYPE const *get_header() const
  {
    assert_header_type<TYPE>();

    return reinterpret_cast<TYPE const *>(&_hdr);
  }

  void dump_header() const
  {
    for (unsigned i = 0; i < Pci_header_size; i += 4)
      info().printf("0x%x:: 0x%x 0x%x \t 0x%x 0x%x\n", i, _hdr.byte[i],
                     _hdr.byte[i + 1], _hdr.byte[i + 2], _hdr.byte[i + 3]);
  }

  /// Align cap address at least to DWORD or to `CAP` requirement.
  template <typename CAP>
  l4_uint8_t align_min_dword(l4_uint8_t addr)
  {
    l4_uint8_t align = alignof(CAP) < 4 ? 4 : alignof(CAP);
    return (addr + align - 1) & ~(align - 1);
  }

  /**
   * Configure a BAR address as IO BAR address.
   *
   * \param bar   BAR number
   * \param addr  Address to write to BAR.
   * \param size  Size of the memory referenced by `addr`.
   */
  template <typename TYPE>
  void set_io_space(unsigned bar, l4_uint32_t addr, l4_size_t size)
  {
    assert_bar_type_size<TYPE>(bar);

    bars[bar].map_addr = addr & ~Bar_io_attr_mask;
    bars[bar].type = Pci_cfg_bar::Type::IO;
    set_bar_size(bar, size);
  }

  /**
   * Configure a BAR address as 32-bit memory BAR address.
   *
   * \param bar   BAR number
   * \param addr  Address to write to BAR.
   * \param size  Size of the memory referenced by `addr`.
   */
  template <typename TYPE>
  void set_mem_space(unsigned bar, l4_uint32_t addr, l4_uint32_t size)
  {
    assert_bar_type_size<TYPE>(bar);

    bars[bar].map_addr = addr & ~Bar_mem_attr_mask;
    bars[bar].type = Pci_cfg_bar::Type::MMIO32;
    set_bar_size(bar, size);
  }

  /**
   * Configure a BAR address as 64-bit memory BAR address.
   *
   * Attention: this will occupy *two* BAR registers!
   *
   * \param bar   BAR number
   * \param addr  Address to write to BAR.
   * \param size  Size of the memory referenced by `addr`.
   */
  template <typename TYPE>
  void set_mem64_space(unsigned bar, l4_uint64_t addr, l4_uint64_t size)
  {
    assert_bar_type_size<TYPE>(bar);

    bars[bar + 0].map_addr = addr & ~Bar_mem_attr_mask;
    bars[bar + 0].type = Pci_cfg_bar::Type::MMIO64;
    bars[bar + 1].type = Pci_cfg_bar::Type::Reserved_mmio64_upper;
    set_bar_size(bar, size);
  }

  /**
   * Set the size of a BAR. According to the PCI spec, this value is rounded up
   * to the nearest power of two >= 16.
   *
   * \param bar   BAR number.
   * \param size  BAR size.
   */
  void set_bar_size(unsigned bar, l4_uint64_t size)
  {
    // Keep in mind that __builtin_clzl(0) is undefined.
    if (size < 16)
      size = 16;
    else
      size = 1ULL << (8 * sizeof(unsigned long long) - __builtin_clzll(size - 1U));
    bars[bar].size = size;
  }

  Pci_header _hdr;
  /// Index into _hdr.byte array
  l4_uint8_t _next_free_idx;
  /// Index into _hdr.byte array
  l4_uint8_t *_last_caps_next_ptr;
};

} } // namespace Vdev::Pci
