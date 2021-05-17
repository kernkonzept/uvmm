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

enum Pci_header_type
{
  Type0 = 0,
  Type1 = 1,
  Type2 = 2
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

/**
 * PCI BAR configuration.
 *
 * Internal representation of a PCI base address register (BAR) configuration.
 */
struct Pci_cfg_bar
{
  enum Type
  {
    Unused, /// Not used
    MMIO32, /// 32bit MMIO
    MMIO64, /// 64bit MMIO
    IO      /// IO space
  };

  l4_uint64_t io_addr = 0;  /// Address used by IO
  l4_uint64_t map_addr = 0; /// Address to use for the guest mapping
  l4_uint64_t size = 0;       /// Size of the region
  Type type = Unused;       /// Type of the BAR

  static const char *to_string(Type t)
  {
    switch(t)
    {
      case IO: return "io";
      case MMIO32: return "mmio32";
      case MMIO64: return "mmio64";
      default: return "unused";
    }
  }
  // for user: get address type dependent
  // auto addr =
  //  (type == MMIO64) ? addr : (l4_uint32_t)(addr && 0xffffffff);
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


  /*
   * Get source ID.
   *
   * Return a source_id compatible with IO.
   */
  virtual l4_uint64_t src_id() const
  { return 0U; }

  /*
   * Enable access to the PCI device.
   *
   * \param access  The MMIO/IO space configuration bits to enable
   */
  void enable_access(l4_uint32_t access)
  {
    l4_uint32_t cmd_reg = 0;
    cfg_read(Pci_hdr_command_offset, &cmd_reg, Vmm::Mem_access::Wd16);
    // Reenable bar access
    cfg_write(Pci_hdr_command_offset, cmd_reg | (access & Access_mask),
              Vmm::Mem_access::Wd16);
  }

  /*
   * Disable access to the PCI device.
   *
   * The current configuration will be returned and has to be passed to the
   * enabled_access function to restore the correct configuration when
   * enabling the device again.
   *
   * \return The current MMIO/IO space configuration bits
   */
  l4_uint32_t disable_access()
  {
    // Disable any bar access
    l4_uint32_t cmd_reg = 0;
    cfg_read(Pci_hdr_command_offset, &cmd_reg, Vmm::Mem_access::Wd16);
    cfg_write(Pci_hdr_command_offset, cmd_reg & ~Access_mask,
              Vmm::Mem_access::Wd16);

    return cmd_reg & Access_mask;
  }

  /**
   * Queries the size of a bar.
   */
  unsigned read_bar_size(unsigned bar_offs, l4_uint32_t bar,
                         l4_uint32_t *bar_size)
  {
    cfg_write(bar_offs, 0xffffffffUL, Vmm::Mem_access::Wd32);
    cfg_read(bar_offs, bar_size, Vmm::Mem_access::Wd32);
    cfg_write(bar_offs, bar, Vmm::Mem_access::Wd32);
    return bar_offs + 4;
  }

  /**
   * Parses one bar configuration for a specific device.
   *
   * \pre  Because this modifies the base address register the PCI device
   *       access must be disabled before calling this method.
   *
   * \post This may advance the bar offset in case of an 64 bit mmio bar. 64
   *       bit addresses take up two bars.
   */
  unsigned read_bar(unsigned bar_offs,
                    l4_uint64_t *addr, l4_uint64_t *size,
                    Pci_cfg_bar::Type *type)
  {
    // Read the base address reg
    l4_uint32_t bar = 0;
    l4_uint32_t bar_size = 0;
    cfg_read(bar_offs, &bar, Vmm::Mem_access::Wd32);
    if ((bar & Bar_type_mask) == Bar_io_space_bit) // IO bar
      {
        bar_offs = read_bar_size(bar_offs, bar, &bar_size);
        if (bar_size == ~0U)
          return bar_offs;

        bar_size &= ~Bar_io_attr_mask; // clear decoding

        *type = Pci_cfg_bar::IO;
        *addr = bar & ~Bar_io_attr_mask;
        *size = (~bar_size & 0xffff) + 1;
      }
    else if ((bar & Bar_mem_type_mask) == Bar_mem_type_32bit) // 32Bit MMIO bar
      {
        bar_offs = read_bar_size(bar_offs, bar, &bar_size);
        if (bar_size == 0)
          return bar_offs;

        bar_size &= ~Bar_mem_attr_mask; // clear decoding

        *type = Pci_cfg_bar::MMIO32;
        *addr = bar & ~Bar_mem_attr_mask;
        *size = ~bar_size + 1;
      }
    else if ((bar & Bar_mem_type_mask) == Bar_mem_type_64bit) // 64Bit MMIO bar
      {
        // Process the first 32bit
        l4_uint64_t addr64 = bar & ~Bar_mem_attr_mask;
        l4_uint64_t size64 = 0;
        bar_offs = read_bar_size(bar_offs, bar, &bar_size);
        if (bar_size == 0)
          return bar_offs;

        size64 = bar_size;

        // Process the second 32bit
        cfg_read(bar_offs, &bar, Vmm::Mem_access::Wd32);
        addr64 |= (l4_uint64_t)bar << 32; // shift to upper part
        bar_offs = read_bar_size(bar_offs, bar, &bar_size);

        size64 |= (l4_uint64_t)bar_size << 32; // shift to upper part
        size64 &= ~Bar_mem_attr_mask; // clear decoding

        *type = Pci_cfg_bar::MMIO64;
        *addr = addr64;
        *size = ~size64 + 1;
      }

    return bar_offs;
  }

  //
  // *** PCI cap ************************************************************
  //

  void parse_msix_cap()
  {
    unsigned msix_cap_addr = get_capability(Cap_ident::Msi_x);
    if (!msix_cap_addr)
      return;

    l4_uint32_t ctrl = 0;
    cfg_read(msix_cap_addr + 2, &ctrl, Vmm::Mem_access::Wd16);
    msix_cap.ctrl.raw = (l4_uint16_t)ctrl;
    cfg_read(msix_cap_addr + 4, &msix_cap.tbl.raw, Vmm::Mem_access::Wd32);
    cfg_read(msix_cap_addr + 8, &msix_cap.pba.raw, Vmm::Mem_access::Wd32);

    has_msix = true;
  }

  /*
   * Walk capabilities list and return the first capability of cap_type (see
   * PCI Spec. Version 3, Chapter 6.7). If none is found return 0.
   *
   * \param devfn     Device function to query
   * \param cap_type  Capability type to retrieve
   *
   * \returns 0       If no capability was found.
   *          >0      Pointer to the capability.
   */
  unsigned get_capability(l4_uint8_t cap_type)
  {
    l4_uint32_t val = 0;
    cfg_read(Pci_hdr_status_offset, &val, Vmm::Mem_access::Wd16);
    if (!(val & Pci_header_status_capability_bit))
      {
        trace().printf("Pci_header_status_capability_bit is not set.\n");
        return 0;
      }

    cfg_read(Pci_hdr_capability_offset, &val, Vmm::Mem_access::Wd8);

    l4_uint8_t next_cap = val & Pci_cap_mask::Next_cap;

    if (next_cap == 0)
      {
        trace().printf("get_capability: Capability pointer is zero.\n");
        return 0;
      }

    while (true)
      {
        cfg_read(next_cap, &val, Vmm::Mem_access::Wd16);
        l4_uint8_t cap_id = val & Pci_cap_mask::Cap_id;
        trace().printf("get_capability: found cap id 0x%x (cap addr 0x%x)\n",
                       cap_id, next_cap);

        if (cap_id == cap_type)
          return next_cap;

        next_cap = (val >> 8) & Pci_cap_mask::Next_cap;
        if (!next_cap) // next pointer is zero -> end of list
          break;
      }

    trace().printf("get_capability: Did not find capability of type 0x%x\n",
                   cap_type);

    return 0;
  }

  /**
   * Parses all bars for a specific device.
   */
  void parse_device_bars()
  {
    unsigned const max_bar_offset =
      get_header_type() == Pci_header_type::Type0
        ? Pci_hdr_base_addr5_offset
        : Pci_hdr_base_addr1_offset;

    // Disable any bar access
    l4_uint32_t access = disable_access();

    for (unsigned bar_offs = Pci_hdr_base_addr0_offset, i = 0;
         bar_offs <= max_bar_offset; ++i)
      {
        Pci_cfg_bar &bar = bars[i];

        // Read one bar configuration
        bar_offs = read_bar(bar_offs, &bar.io_addr, &bar.size, &bar.type);

        if (bar.type == Pci_cfg_bar::Unused)
          continue;

        // Initial map address is equal to io address
        bar.map_addr = bar.io_addr;


        info().printf("  bar[%u] addr=0x%llx size=0x%llx type=%s\n", i,
                      bar.io_addr, bar.size, Pci_cfg_bar::to_string(bar.type));
      }

    // Reenable bar access
    enable_access(access);
  }

  /**
   * Get the type of the device's PCI header.
   *
   * We are not supporting PCI-to-Cardbus bridges (Type2). If such a bridge is
   * encountered or any other invalid header type, this function throws.
   *
   * \retval Pci_header_type::Type0, for normal PCI devices
   *         Pci_header_type::Type1, for PCI-to-PCI bridge devices.
   */
  Pci_header_type get_header_type()
  {
    enum { Type_mask = 0x7f };
    l4_uint8_t type = get_header_field() & Type_mask;

    // Not supporting Cardbus bridges and reserved header type values.
    if (type >= Pci_header_type::Type2)
      L4Re::throw_error(-L4_EINVAL, "Device has unsupported PCI header type.");

    return Pci_header_type(type);
  }

  /// True, iff this device supports multiple functions.
  bool is_multi_function_device()
  {
    return get_header_field() & Multi_func_bit;
  }

  /// Get the raw value of the header type field in the config space.
  l4_uint8_t get_header_field()
  {
    l4_uint32_t header_type = 0U;
    cfg_read(Pci_hdr_type_offset, &header_type, Vmm::Mem_access::Wd8);
    return header_type & 0xff;
  }

  // These registers keep track of the BARs that are actually mapped.
  // We expect the guest to reprogram PCI BARs. These writes will modify the
  // in-memory header BARs, but only when the IO/MMIO decode bits are set in
  // the control register, we actually commit the configuration (program the
  // mappings and save the configuration into the shadow registers).
  Pci_cfg_bar bars[Bar_num_max_type0];
  Pci_msix_cap msix_cap;               /// MSI-X capability
  bool has_msix = false;               /// indicates MSI-X support

private:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI dev"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI dev"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI dev"); }
};

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

    if (reg >= 0x10 && reg <= 0x24) // PCI BAR
      {
        // According to PCI Spec. 3.0, Chapter 3.2.2.3..2
        // A bridge must implement configuration access only via full dword.
        if (width != Mem_access::Wd32)
          {
            dbg().printf("BAR[%u] write width = %d, value = %08x. Ignoring.\n",
                         (reg - 0x10) / 4, width, value);
            return;
          }

        // The BAR size (power of 2!) defines which bits are writable.
        l4_uint32_t size = bars[(reg - 0x10) / 4].size;
        l4_uint32_t bar  = _hdr.dword[reg / 4];
        l4_uint32_t mask = ~size + 1;

        // TODO: Needs adaption for 64-bit BARs!
        value &= mask;
        bar   &= ~mask;
        value |= bar;
      }

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
    info().printf("cap offset 0x%x, cap size 0x%zx\n", cap_offset,
                  sizeof(*ret));

    *_last_caps_next_ptr = cap_offset;
    _last_caps_next_ptr = &ret->cap_next;

    _next_free_idx = cap_offset + sizeof(*ret);

    info().printf("indexes: cap's next ptr %p, next free byte 0x%x\n",
                  &_last_caps_next_ptr, _next_free_idx);

    ret->cap_next = 0;
    assert(ret->cap_type == T::Cap_id);
    return ret;
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
      Dbg().printf("dt_regs[%i]: 0x%x\n", i, fdt32_to_cpu(dt_regs[i*reg_len]));

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
private:
  Pci_header _hdr;
  /// Index into _hdr.byte array
  l4_uint8_t _next_free_idx;
  /// Index into _hdr.byte array
  l4_uint8_t *_last_caps_next_ptr;

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

    bars[bar].map_addr = addr & ~Bar_io_attr_mask;
    bars[bar].type = Pci_cfg_bar::Type::IO;
    get_header<TYPE>()->base_addr_regs[bar] =
      bars[bar].map_addr | Bar_io_space_bit;
    set_bar_size(bar, size);
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
    bars[bar].map_addr = addr & ~Bar_mem_attr_mask;
    bars[bar].type = Pci_cfg_bar::Type::MMIO32;
    // TODO support mmio64 as well
    get_header<TYPE>()->base_addr_regs[bar] = (addr & ~Bar_mem_attr_mask);
    set_bar_size(bar, size);
  }

  /**
   * Set the size of a BAR. According to the PCI spec, this value is rounded up
   * to the nearest power of two >= 16.
   *
   * \param bar   BAR number.
   * \param size  BAR size.
   */
  void set_bar_size(unsigned bar, l4_size_t size)
  {
    // Keep in mind that __builtin_clzl(0) is undefined.
    if (size < 16)
      size = 16;
    else
      size = 1UL << (8 * sizeof(unsigned long) - __builtin_clzl(size - 1));
    bars[bar].size = size;
  }
};

} } // namespace Vdev::Pci
