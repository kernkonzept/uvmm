/*
 * Copyright (C) 2018-2019 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/l4int.h>
#include <l4/sys/types.h>
#include <l4/cxx/static_vector>
#include <l4/cxx/bitfield>
#include <l4/re/error_helper>

#include "mem_access.h"
#include "device.h"
#include "msi.h"

#include <type_traits>

namespace Vdev { namespace Pci {

enum Pci_status_register
{
  // see PCI Local Bus Specification V.3 (2004) Section 6.2.3 Device Status
  Interrupt_status_bit = 1U << 3,
  Capability_list_bit  = 1U << 4,
};

enum Pci_command_register : l4_uint16_t
{
  Io_space_bit = 1U,
  Memory_space_bit = 1U << 1,
  Access_mask = Io_space_bit | Memory_space_bit,
  Bus_master_bit = 1U << 2,
  Interrupt_disable_bit = 1U << 10,
};

enum Pci_header_type_register
{
  Multi_func_bit = (1U << 7),
};

enum Pci_config_consts
{
  Pci_header_size = 0x100,
  // see PCI Local Bus Specification V.3 (2004) Section 6
  Bar_type_mask = 0x1,
  Bar_io_space_bit = 0x1,
  Bar_io_attr_mask = 0x3,
  Bar_mem_type_mask = 0x7,
  Bar_mem_type_32bit = 0x0,      /// type bits[2:1] 00 = 32bit
  Bar_mem_type_64bit = 0x1 << 2, /// type bits[2:1] 10 = 64bit
  Bar_mem_attr_mask = 0xf,
  Bar_mem_prefetch_bit = 0x8,
  Bar_num_max_type0 = 6,
  Bar_num_max_type1 = 2,
};

enum Cap_ident : l4_uint8_t
{
  // see PCI Local Bus Specification V.3 (2004) Appendix H.
  Power_management = 0x1,
  Msi = 0x5,
  Vendor_specific = 0x9,
  Pcie = 0x10,
  Msi_x = 0x11,
};

enum Pci_cap_mask : l4_uint8_t
{
  Next_cap = 0xfc, // Lowest two bits of the pointer to the
                   // next capability are reserved
  Cap_id   = 0xff, // Capability ID
};

enum
{
  // see PCI Local Bus Specification V.3 (2004) Section 6.1
  Pci_hdr_vendor_id_offset = 0x0,
  Pci_hdr_device_id_offset = 0x2,
  Pci_hdr_command_offset = 0x4,
  Pci_hdr_status_offset = 0x6,
  Pci_hdr_status_length = 0x10,
  Pci_hdr_revision_id_offset = 0x8,
  Pci_hdr_classcode_offset = 0x9,
  Pci_hdr_cacheline_size_offset = 0xc,
  Pci_hdr_latency_timer_offset = 0xd,
  Pci_hdr_type_offset = 0xe,
  Pci_hdr_bist_offset = 0xf,
  Pci_hdr_base_addr0_offset = 0x10,
  Pci_hdr_base_addr1_offset = 0x14,
  Pci_hdr_base_addr2_offset = 0x18,
  Pci_hdr_base_addr3_offset = 0x1c,
  Pci_hdr_base_addr4_offset = 0x20,
  Pci_hdr_base_addr5_offset = 0x24,
  Pci_hdr_card_bus_offset = 0x28,
  Pci_hdr_subsystem_vendor_id_offset = 0x2c,
  Pci_hdr_subsystem_id_offset = 0x2e,
  Pci_hdr_expansion_rom_offset = 0x30,
  Pci_hdr_capability_offset = 0x34,
  Pci_hdr_interrupt_line_offset = 0x3c,
  Pci_hdr_interrupt_pin_offset = 0x3d,
  Pci_hdr_interrupt_pin_max = 0x4,
  Pci_hdr_min_time_offset = 0x3e,
  Pci_hdr_max_latency_offset = 0x3f,
};

enum : l4_uint8_t
{
  Pci_class_code_bridge_device = 0x06,
  Pci_subclass_code_host = 0x00,
};

enum : l4_uint16_t
{
  Pci_invalid_vendor_id = 0xffff,
};

enum
{
  Pci_header_status_capability_bit = (1UL << 4),
};

enum Virtual_pci_device_msix_consts
{
  Msix_mem_need = 2 * L4_PAGESIZE, // ideally Table and PBA on different pages
};

/// Base class of a PCI capability.
struct Pci_cap
{
  explicit Pci_cap(l4_uint8_t type) : cap_type(type) {}

  /**
   * Perform a cast if the input cap `c` is of the expected type `T`.
   *
   * \tparam T  The expected PCI capability type.
   * \param  c  The capability to cast.
   *
   * \returns A valid capability pointer if the type is correct; nullptr
   *          otherwise.
   */
  template <typename T>
  static T *
  cast_type(Pci_cap *c)
  {
    return c->cap_type == T::Cap_id ? static_cast<T *>(c) : nullptr;
  }

  // see PCI Local Bus Specification V.3 (2010) 6.8.2.
  l4_uint8_t const cap_type;
  l4_uint8_t cap_next;
};

/// Class for all vendor specific PCI capabilities.
struct Vendor_specific_cap : Pci_cap
{
  enum : l4_uint8_t { Cap_id = Cap_ident::Vendor_specific };

  explicit Vendor_specific_cap(l4_uint8_t len)
  : Pci_cap(Cap_id), cap_len(len)
  {}

  l4_uint8_t cap_len;
};
static_assert(sizeof(Vendor_specific_cap) == 3,
              "Vendor_specific_cap size conforms to specification.");

/// MSI-X capability for the PCI config space.
struct Pci_msix_cap : Pci_cap
{
  enum : l4_uint8_t { Cap_id = Cap_ident::Msi_x };

  Pci_msix_cap() : Pci_cap(Cap_id) {}

  struct
  {
    l4_uint16_t raw;
    CXX_BITFIELD_MEMBER(15, 15, enabled, raw);
    CXX_BITFIELD_MEMBER(14, 14, masked, raw);
    CXX_BITFIELD_MEMBER(0, 10, max_msis, raw);
  } ctrl;

  struct Offset_bir
  {
    l4_uint32_t raw;
    CXX_BITFIELD_MEMBER(3, 31, offset, raw);
    CXX_BITFIELD_MEMBER(0, 2, bir, raw);
  };
  Offset_bir tbl;
  Offset_bir pba;
};
static_assert(sizeof(Pci_msix_cap) == 12,
              "Pci_msix_cap size conforms to specification.");

union alignas(l4_addr_t) Pci_header
{
  l4_uint8_t byte[Pci_header_size];
  l4_uint16_t word[Pci_header_size / 2];
  l4_uint32_t dword[Pci_header_size / 4];
  l4_uint64_t qword[Pci_header_size / 8];

  struct Type0
  {
    l4_uint16_t vendor_id;
    l4_uint16_t device_id;
    l4_uint16_t command;
    l4_uint16_t status;
    l4_uint8_t revision_id;
    l4_uint8_t classcode[3];
    l4_uint8_t cachline_size;
    l4_uint8_t latency_timer;
    l4_uint8_t header_type;
    l4_uint8_t bist;
    l4_uint32_t base_addr_regs[Bar_num_max_type0];
    l4_uint32_t cardbus_ptr;
    l4_uint16_t subsystem_vendor;
    l4_uint16_t subsystem_id;
    l4_uint32_t expansion_rom_base;
    l4_uint8_t cap_ptr;
    l4_uint8_t _reserved0[3];
    l4_uint32_t _reserved1;
    l4_uint8_t int_line;
    l4_uint8_t int_pin;
    l4_uint8_t min_gnt;
    l4_uint8_t max_lat;
    unsigned char cfg_space[192]; // (0x100 - 0x40)
  };

  struct Type1
  {
    l4_uint16_t vendor_id;
    l4_uint16_t device_id;
    l4_uint16_t command;
    l4_uint16_t status;
    l4_uint8_t revision_id;
    l4_uint8_t classcode[3];
    l4_uint8_t cachline_size;
    l4_uint8_t latency_timer;
    l4_uint8_t header_type;
    l4_uint8_t bist;
    l4_uint32_t base_addr_regs[Bar_num_max_type1];
    l4_uint8_t primary_bus_num;
    l4_uint8_t secondary_bus_num;
    l4_uint8_t subordinate_bus_num;
    l4_uint8_t secondary_latency_timer;
    l4_uint8_t io_base;
    l4_uint8_t io_limit;
    l4_uint16_t secondary_status;
    l4_uint16_t mem_base;
    l4_uint16_t mem_limit;
    l4_uint16_t prefetch_mem_base;
    l4_uint16_t prefetch_mem_limit;
    l4_uint32_t prefetch_mem_base_upper32;
    l4_uint32_t prefetch_mem_limit_upper32;
    l4_uint16_t io_base_upper16;
    l4_uint16_t io_limit_upper16;
    l4_uint8_t cap_ptr;
    l4_uint8_t _reserved[3];
    l4_uint32_t exp_rom_base_addr;
    l4_uint8_t int_line;
    l4_uint8_t int_pin;
    l4_uint16_t bridge_ctrl;
    unsigned char cfg_space[192]; // (0x100 - 0x40)
  };
};

static_assert(   sizeof(Pci_header::Type0) == sizeof(Pci_header)
              && sizeof(Pci_header::Type1) == sizeof(Pci_header),
              "Pci_header and Pci_header::Type sizes differ.");


struct Pci_device : public virtual Vdev::Dev_ref
{
  virtual ~Pci_device() = default;

  virtual void cfg_write(unsigned reg,
                         l4_uint32_t value, Vmm::Mem_access::Width width) = 0;
  virtual void cfg_read(unsigned reg,
                        l4_uint32_t *value, Vmm::Mem_access::Width width) = 0;

  bool is_multi_function_device()
  {
    l4_uint32_t val = 0;
    cfg_read(Pci_hdr_type_offset, &val, Vmm::Mem_access::Wd8);
    return val & Multi_func_bit;
  }

  /**
   * Get PCI flags value of a register in the DT-PCI node.
   *
   * \param node     DT node to get the register flags of.
   * \param reg_num  Index of the 'reg' entry.
   *
   * \return PCI flags specified in the DT for the specified reg entry.
   */
  static l4_uint32_t dt_get_reg_flags(Vdev::Dt_node const &node, int reg_num)
  {
    auto parent = node.parent_node();
    size_t addr_cells = node.get_address_cells(parent);
    size_t size_cells = node.get_size_cells(parent);

    if (addr_cells != 3 || size_cells != 2)
      L4Re::chksys(-L4_EINVAL,
                   "PCI device register lengths are three (address) "
                   "and two (size).");

    int const reg_len = addr_cells + size_cells;
    int dt_regs_size = 0;
    auto dt_regs = node.get_prop<fdt32_t>("reg", &dt_regs_size);
    assert(reg_num < (dt_regs_size / reg_len));

    for (int i = 0; i < 2; ++i)
      Dbg().printf("dt_regs[%i]: 0x%x\n", i, fdt32_to_cpu(dt_regs[i * reg_len]));

    return fdt32_to_cpu(dt_regs[reg_num * reg_len]);
  }

  /**
   * Get IO-Reg values of the PCI-DT node, without translation through the
   * parent.
   *
   * The IO regs entry defines absolute reset values for the IO area of the
   * device, which are not translated through the PCI host bridge ranges
   * property. Attempts to do so result in a translation error.
   *
   * It is slightly modified copy of Dtb::Node::get_reg_val().
   *
   * \see Dtb::Node::get_reg_val()
   */
  static int dt_get_untranslated_reg_val(Vdev::Dt_node node, int index,
                                         l4_uint64_t *address,
                                         l4_uint64_t *size)
  {
    auto parent = node.parent_node();
    size_t addr_cells = node.get_address_cells(parent);
    size_t size_cells = node.get_size_cells(parent);
    int rsize = addr_cells + size_cells;

    int prop_size;
    auto *prop = node.get_prop<fdt32_t>("reg", &prop_size);
    if (!prop && prop_size < 0)
      return prop_size;

    if (!prop)
      return FDT_ERR_INTERNAL;

    if (prop_size < rsize * (index + 1))
      return Dt_node::ERR_BAD_INDEX;

    prop += rsize * index;

    // ignore flags
    prop += 1;
    addr_cells -= 1;
    Dtb::Reg reg{Dtb::Cell{prop, addr_cells},
                 Dtb::Cell(prop + addr_cells, size_cells)};

    if (address)
      *address = reg.address.get_uint64();
    if(size)
      *size = reg.size.get_uint64();

    return 0;
  }
};

class Pci_dev : public Pci_device
{
public:
  Pci_dev()
  {
    for (auto &b : _bar_size)
      b = 1; // Default to an IO-space BAR.

    memset(&_hdr, 0, sizeof(_hdr));
    _last_caps_next_ptr = &get_header<Pci_header::Type0>()->cap_ptr;
    _next_free_idx = 0x40; // first byte after the PCI header;
  }

  /**
   * Read from the PCI header config.
   *
   * \param      reg    The config space register to read from.
   * \param[out] value  The value returned by the read. -1 if failed.
   * \param      width  The width of the register access.
   */
  void cfg_read(unsigned reg, l4_uint32_t *value,
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
                   (unsigned)*value);
  }

  /**
   * Write to the PCI header config.
   *
   * \param reg    Register number to write to.
   * \param value  Value to write to `reg`.
   * \param width  Width of the memory access.
   */
  void cfg_write(unsigned reg, l4_uint32_t value,
                 Vmm::Mem_access::Width width) override
  {
    using Vmm::Mem_access;

    if (!check_cfg_range(reg, width))
      return;

    if (   reg == Pci_hdr_status_offset
        && ((8U << width)) == Pci_hdr_status_length)
      return;

    // If the BAR is sized, write the size value to the cfg space. The driver
    // will write the old value back afterwards.
    if (value == 0xFFFFFFFF && reg >= 0x10 && reg <= 0x24)
      value = _bar_size[(reg - 0x10) / 0x4];

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
   * Search for the PCI capability of type `CAP`.
   *
   * \tparam CAP  Capability type structure.
   *
   * \return Pointer to the capability in this PCI devices config space.
   */
  template <typename CAP>
  CAP *get_cap()
  {
    // cap_ptr is the same for both header types.
    l4_uint8_t nxt = get_header<Pci_header::Type0>()->cap_ptr;
    while (nxt != 0)
      {
        auto *pci_cap = reinterpret_cast<CAP *>(&_hdr.byte[nxt]);
        auto *c = CAP::template cast_type<CAP>(pci_cap);

        if (c)
          return c;

        nxt = pci_cap->cap_next;
      }

    return nullptr;
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
    info().printf("cap offset 0x%x, cap size 0x%zx\n", cap_offset, sizeof(*ret));

    *_last_caps_next_ptr = cap_offset;
    _last_caps_next_ptr = &ret->cap_next;

    _next_free_idx = cap_offset + sizeof(*ret);

    info().printf("indexes: cap's next ptr %p, next free byte 0x%x\n",
                  &_last_caps_next_ptr, _next_free_idx);

    ret->cap_next = 0;
    assert(ret->cap_type == T::Cap_id);
    return ret;
  }

private:
  Pci_header _hdr;
  /// Index into _hdr.byte array
  l4_uint8_t _next_free_idx;
  /// Index into _hdr.byte array
  l4_uint8_t *_last_caps_next_ptr;
  l4_uint32_t _bar_size[Bar_num_max_type0];

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

protected:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI dev"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI dev"); }
  static Dbg dbg() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI dev"); }

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

  void dump_header() const
  {
    for (unsigned i = 0; i < Pci_header_size; i += 4)
      trace().printf("0x%x:: 0x%x 0x%x \t 0x%x 0x%x\n", i, _hdr.byte[i],
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

    get_header<TYPE>()->base_addr_regs[bar] =
      ((addr & ~Bar_io_attr_mask) | Bar_io_space_bit);
    _bar_size[bar] = size;
  }

  /**
   * Configure a BAR address as memory BAR address.
   *
   * \param bar   BAR number
   * \param addr  Address to write to BAR.
   * \param size  Size of the memory referenced by `addr`.
   */
  template <typename TYPE>
  void set_mem_space(unsigned bar, l4_uint32_t addr, l4_size_t size)
  {
    assert_bar_type_size<TYPE>(bar);

    // memory space: [0] mem space indicator := 0;
    // [2:1] type: 00 = 32bit, 10 = 64bit;
    // [3] prefetch;
    get_header<TYPE>()->base_addr_regs[bar] = (addr & ~Bar_mem_attr_mask);
    _bar_size[bar] = size;
  }
};

enum
{
  Dt_pci_flags_io = 1 << 24,
  Dt_pci_flags_mmio32 = 1 << 25,
  Dt_pci_flags_mmio64 = 3 << 25,
  Dt_pci_flags_prefetch = 1 << 30,
};

struct Device_register_entry
{
  l4_uint64_t base;
  l4_uint64_t size;
  l4_uint32_t flags;

  void print() const
  {
    Dbg().printf("base 0x%llx, size 0x%llx, flags 0x%x\n", base, size, flags);
  }
};

} } // namespace Vdev::Pci
