/*
 * Copyright (C) 2018 Kernkonzept GmbH.
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

#include "mem_access.h"
#include "device.h"

#include <type_traits>

namespace Vdev {

enum Pci_status_register
{
  // see PCI Local Bus Specification V.3 (2004) Section 6.2.3 Device Status
  Interrupt_status_bit = 1U << 3,
  Capability_list_bit  = 1U << 4,
};

enum Pci_command_register : l4_uint16_t
{
  Io_space_bit = 1U,
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
  Bar_mem_io_space_bit = 0x1,
  Bar_mem_io_attr_mask = 0x3,
  Bar_mem_attr_mask = 0xf,
  Bar_mem_type_64bit = 0x1 << 2, /// type bits[2:1] 10 = 64bit
  Bar_mem_prefetch_bit = 0x8,
  Bar_num_max_type0 = 6,
  Bar_num_max_type1 = 2,
};

enum
{
  Pci_hdr_vendor_id_offset = 0,
  Pci_hdr_device_id_offset = 2,
  Pci_hdr_command_offset = 4,
  Pci_hdr_status_offset = 6,
  Pci_hdr_status_length = 16,
  Pci_hdr_revision_id_offset = 8,
  Pci_hdr_classcode_offset = 9,
  Pci_hdr_cacheline_size_offset = 12,
  Pci_hdr_type_offset = 14,
  // see PCI Local Bus Specification V.3 (2004) Section 6.1
};

enum Pci_msix_consts
{
  // see PCI Local Bus Specification V.3 (2004) Appendix H.
  Pci_cfg_msix_cap_id = 0x11,
  Msix_table_entry_size = 16,      // entry size in bytes: 4 DWORDs.
  Msix_mem_need = 2 * L4_PAGESIZE, // ideally Table and PBA on different pages
};

struct Pci_cap_ident
{
  l4_uint8_t cap_type;
  l4_uint8_t cap_next;
} __attribute__((__packed__));

struct Pci_msix_cap
{
  // see PCI Local Bus Specification V.3 (2010) 6.8.2.
  Pci_cap_ident id;

  l4_uint16_t msg_ctrl = 0;
  CXX_BITFIELD_MEMBER(15, 15, msix_enable, msg_ctrl);
  CXX_BITFIELD_MEMBER(14, 14, fn_mask, msg_ctrl);
  CXX_BITFIELD_MEMBER(0, 10, tbl_size, msg_ctrl);

  l4_uint32_t table = 0;
  CXX_BITFIELD_MEMBER(3, 31, tbl_offset, table);
  CXX_BITFIELD_MEMBER(0, 2, tbl_bir, table);

  l4_uint32_t pba = 0;
  CXX_BITFIELD_MEMBER(3, 31, pba_offset, pba);
  CXX_BITFIELD_MEMBER(0, 2, pba_bir, pba);
};

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
    if ((node.get_address_cells() != 3) && (node.get_size_cells() != 2))
      L4Re::chksys(-L4_EINVAL,
                   "PCI device register lengths are three (address) "
                   "and two (size).");

    int const reg_len = node.get_address_cells() + node.get_size_cells();
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
    size_t addr_cells = node.get_address_cells();
    size_t size_cells = node.get_size_cells();
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
    _last_cap_ptr_idx = 0x34; // cap_ptr offset in byte;
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

private:
  Pci_header _hdr;
  /// Index into _hdr.byte array
  l4_uint8_t _next_free_idx;
  /// Index into _hdr.byte array
  l4_uint8_t _last_cap_ptr_idx;
  l4_uint32_t _bar_size[Bar_num_max_type0];

  template <typename TYPE> constexpr
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

  /**
   * Allocate a new PCI capability in the PCI header config space and enqueue
   * it in the cap list.
   *
   * \tparam CAP  Capability type to allocate.
   */
  template <typename CAP>
  CAP *allocate_pci_cap()
  {
    assert(_next_free_idx < sizeof(_hdr));
    assert(_last_cap_ptr_idx < sizeof(_hdr));

    CAP *ret = reinterpret_cast<CAP *>(&(_hdr.qword[_next_free_idx / 8]));
    l4_uint8_t cap_offset = _next_free_idx;
    dbg().printf("cap offset 0x%x, cap size 0x%lx\n", cap_offset, sizeof(*ret));

    _hdr.byte[_last_cap_ptr_idx] = _next_free_idx;
    _last_cap_ptr_idx =  cap_offset + 1; // next ptr is at 2nd byte into cap
    _next_free_idx = l4_round_size(cap_offset + sizeof(*ret), 3);

    dbg().printf("indexes: last 0x%x, next 0x%x\n", _last_cap_ptr_idx,
                 _next_free_idx);

    ret->id.cap_next = 0;
    return ret;
  }

  void dump_header() const
  {
    for (unsigned i = 0; i < Pci_header_size; i += 4)
      trace().printf("0x%x:: 0x%x 0x%x \t 0x%x 0x%x\n", i, _hdr.byte[i],
                     _hdr.byte[i + 1], _hdr.byte[i + 2], _hdr.byte[i + 3]);
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
      ((addr & ~Bar_mem_io_attr_mask) | Bar_mem_io_space_bit);
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

class Pci_device_msix : public Pci_dev
{
public:
  Pci_device_msix() : Pci_dev(), _cap(nullptr) {}

  /**
   * Allocate an entrie in the PCI capability list of the PCI configuration
   * header and fill it with the MSI-X capability.
   *
   * \param max_msix_entries  Maximum number of MSI-X entries of this device.
   * \param BAR index         BAR index[0,5] of the MSI-X memory BAR.
   */
  void create_msix_cap(unsigned max_msix_entries, unsigned bar_index)
  {
    assert(bar_index < 6);

    Pci_msix_cap *cap = allocate_pci_cap<Pci_msix_cap>();
    cap->id.cap_type = Pci_cfg_msix_cap_id;
    cap->msix_enable() = 1;
    cap->tbl_size() = max_msix_entries - 1;
    cap->tbl_bir() = bar_index;
    cap->pba_offset() = L4_PAGESIZE;
    cap->pba_bir() = bar_index;

    trace().printf("msi.msg_ctrl 0x%x\n", cap->msg_ctrl);
    trace().printf("msi.table 0x%x\n", cap->table);
    trace().printf("msi.pba 0x%x\n", cap->pba);

    _cap = cap;
  }

  bool msix_enabled() const { return _cap->msix_enable(); }
  bool msix_func_enabled() const { return !_cap->fn_mask(); }

private:
  Pci_msix_cap *_cap;
};

struct Msi_msg
{
  l4_uint64_t addr;
  l4_uint32_t data;

  // Attribute packed is necessary to fit into a 128bit MSI-X table entry
  // together with 'vector_ctrl' in 'struct Msix_table_entry' below.
} __attribute__((__packed__));


struct Msix_table_entry
{
  /* The structure defined in the PCI spec V.3.0 is as follows:
   * Each table entry consists of four DWORDs (32 bits), overall 128 bits.
   * [    127:96     |     95:64    |        63:32      |       31:0      ]
   * [Vector control | Message Data | Message Addr high | Message Addr low]
   */
  Msi_msg msg;
  l4_uint32_t vector_ctrl;

  enum Msix_table_entry_const
  {
    Vector_ctrl_mask_bit = 0x1,
    Msix_vector_mask = 0xff,
  };

  Msix_table_entry() : vector_ctrl(Vector_ctrl_mask_bit) {}

  /// True if the entry is disabled.
  bool disabled() const { return vector_ctrl & Vector_ctrl_mask_bit; }

  /// Print entry
  void dump() const
  {
    Dbg().printf("Addr 0x%llx, Data 0x%x, ctrl 0x%x\n", msg.addr, msg.data,
                 vector_ctrl);
  }
} __attribute__((__packed__));

/**
 * Device local MSI-X table structure.
 */
class Msix_table
{
public:
  /**
   * \param memory           Backing memory allocated by device.
   * \param max_num_entires  As encoded in MSI-X message control plus one.
   */
  Msix_table(l4_addr_t memory, unsigned const max_num_entries)
  : _table(reinterpret_cast<Msix_table_entry *>(memory), max_num_entries)
  {}

  /// Read the table entry at `idx`
  Msix_table_entry const &entry(unsigned idx) const
  {
    assert(idx < _table.size());
    return _table[idx];
  }

  /// Print all table entries.
  void dump() const
  {
    for (Msix_table_entry const &e : _table)
      e.dump();
  }

private:
  cxx::static_vector<Msix_table_entry> const _table;
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

} // namespace Vdev

