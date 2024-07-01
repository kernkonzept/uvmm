/*
 * Copyright (C) 2018-2022 Kernkonzept GmbH.
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
#include "msix.h"
#include "mmio_device.h"
#include "io_device.h"

#include <type_traits>

namespace Vmm {
  class Guest;
}

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
  Bar_mem_non_prefetch_bit = 0x0,
  Bar_num_max_type0 = 6,
  Bar_num_max_type1 = 2,
};

/**
 * PCI BAR configuration.
 *
 * Internal representation of a PCI base address register (BAR) configuration.
 * For 64 bit BARs the lower structure holds the full address and the upper
 * structure is reserved.
 */
struct Pci_cfg_bar
{
  enum Type
  {
    Unused_empty, /// Not used
    Reserved_mmio64_upper,  /// Reserved for upper word of previous MMIO64
    MMIO32, /// 32bit MMIO
    MMIO64, /// 64bit MMIO
    IO      /// IO space
  };

  l4_uint64_t io_addr = 0;  /// Address used by IO
  l4_uint64_t map_addr = 0; /// Address to use for the guest mapping
  l4_uint64_t size = 0;       /// Size of the region
  Type type = Unused_empty;       /// Type of the BAR
  bool prefetchable = false;  /// Prefetchable MMIO region?

  char const *to_string() const
  {
    switch(type)
    {
      case IO: return "io";
      case MMIO32: return prefetchable ? "mmio32 (prefetchable)"
                                       : "mmio32 (non-prefetchable)";
      case MMIO64: return prefetchable ? "mmio64 (prefetchable)"
                                       : "mmio64 (non-prefetchable)";
      default: return "unused";
    }
  }
  // for user: get address type dependent
  // auto addr =
  //  (type == MMIO64) ? addr : (l4_uint32_t)(addr && 0xffffffff);
};

/**
 * PCI expansion ROM Bar description.
 */
struct Pci_expansion_rom_bar
{
  l4_uint64_t io_addr = 0;
  l4_uint64_t size = 0;
  l4_uint64_t map_addr = 0;
  bool hw_enabled = false;
  bool virt_enabled = false;

  enum { Enable_bit = 1 };
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

enum Ext_cap_ident : l4_uint16_t
{
  Sr_iov = 0x0010,
};

enum Pci_cap_mask : l4_uint8_t
{
  Next_cap = 0xfc, // Lowest two bits of the pointer to the
                   // next capability are reserved
  Cap_id   = 0xff, // Capability ID
};

enum
{
  // see PCI Local Bus Specification V.3 (2004) Section 6.1 and PCI-to-PCI
  // Bridge Architecture Specification Revision 1.1 Section 3.2
  Pci_hdr_vendor_id_offset = 0x0,
  Pci_hdr_device_id_offset = 0x2,
  Pci_hdr_command_offset = 0x4,
  Pci_hdr_command_length = 0x10,
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
  Pci_hdr_capability_offset = 0x34,
  Pci_hdr_interrupt_line_offset = 0x3c,
  Pci_hdr_interrupt_pin_offset = 0x3d,
  Pci_hdr_interrupt_pin_max = 0x4,

  Pci_hdr_type0_base_addr0_offset = Pci_hdr_base_addr0_offset,
  Pci_hdr_type0_base_addr1_offset = Pci_hdr_base_addr1_offset,
  Pci_hdr_type0_base_addr2_offset = 0x18,
  Pci_hdr_type0_base_addr3_offset = 0x1c,
  Pci_hdr_type0_base_addr4_offset = 0x20,
  Pci_hdr_type0_base_addr5_offset = 0x24,
  Pci_hdr_type0_card_bus_offset = 0x28,
  Pci_hdr_type0_subsystem_vendor_id_offset = 0x2c,
  Pci_hdr_type0_subsystem_id_offset = 0x2e,
  Pci_hdr_type0_expansion_rom_offset = 0x30,
  Pci_hdr_type0_capability_offset = Pci_hdr_capability_offset,
  Pci_hdr_type0_interrupt_line_offset = Pci_hdr_interrupt_line_offset,
  Pci_hdr_type0_interrupt_pin_offset = Pci_hdr_interrupt_pin_offset,
  Pci_hdr_type0_interrupt_pin_max = Pci_hdr_interrupt_pin_max,
  Pci_hdr_type0_min_time_offset = 0x3e,
  Pci_hdr_type0_max_latency_offset = 0x3f,

  Pci_hdr_type1_base_addr0_offset = Pci_hdr_base_addr0_offset,
  Pci_hdr_type1_base_addr1_offset = Pci_hdr_base_addr1_offset,
  Pci_hdr_type1_primary_bus_offset = 0x18,
  Pci_hdr_type1_secondary_bus_offset = 0x19,
  Pci_hdr_type1_subordinate_bus_offset = 0x1a,
  Pci_hdr_type1_secondary_latency_offset = 0x1b,
  Pci_hdr_type1_io_base_offset = 0x1c,
  Pci_hdr_type1_io_limit_offset = 0x1d,
  Pci_hdr_type1_secondary_status_offset = 0x1e,
  Pci_hdr_type1_memory_base_offset = 0x20,
  Pci_hdr_type1_memory_limit_offset = 0x22,
  Pci_hdr_type1_prefetchable_memory_base_offset = 0x24,
  Pci_hdr_type1_prefetchable_memory_limit_offset = 0x26,
  Pci_hdr_type1_prefetchable_base_upper_offset = 0x28,
  Pci_hdr_type1_prefetchable_limit_upper_offset = 0x2c,
  Pci_hdr_type1_io_base_upper_offset = 0x30,
  Pci_hdr_type1_io_limit_upper_offset = 0x32,
  Pci_hdr_type1_capabilities_offset = Pci_hdr_capability_offset,
  Pci_hdr_type1_expansion_rom_offset = 0x38,
  Pci_hdr_type1_interrupt_line_offset = Pci_hdr_interrupt_line_offset,
  Pci_hdr_type1_interrupt_pin_offset = Pci_hdr_interrupt_pin_offset,
  Pci_hdr_type1_interrupt_pin_max = Pci_hdr_interrupt_pin_max,
  Pci_hdr_type1_bridge_control_offset = 0x3e,
};

enum : l4_uint8_t
{
  Pci_class_code_mass_storage_device = 0x01,
  Pci_class_code_network_device = 0x02,
  Pci_class_code_display_device = 0x03,
  Pci_class_code_multimedia_device = 0x04,
  Pci_class_code_memory_device = 0x05,
  Pci_class_code_bridge_device = 0x06,
  Pci_class_code_communication_device = 0x07,
  Pci_class_code_system_peripheralls_device = 0x08,
  Pci_class_code_input_device = 0x09,
  Pci_class_code_docking_station_device = 0x0a,
  Pci_class_code_processors_device = 0x0b,
  Pci_class_code_serial_bus_device = 0x0c,
  Pci_class_code_wireless_device = 0x0d,
  Pci_class_code_io_device = 0x0e,
  Pci_class_code_satellite_device = 0x0f,
  Pci_class_code_crypt_device = 0x10,
  Pci_class_code_signal_device = 0x11,
  Pci_class_code_accelerator_device = 0x12,
  Pci_class_code_instrument_device = 0x13,
  Pci_class_code_other_device = 0x80,
  Pci_class_code_unknown_device = 0xff,
};

enum : l4_uint8_t
{
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
  l4_uint8_t cap_next = 0;
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
    CXX_BITFIELD_MEMBER_UNSHIFTED(3, 31, offset, raw);
    CXX_BITFIELD_MEMBER(0, 2, bir, raw);
  };
  Offset_bir tbl;
  Offset_bir pba;
};
static_assert(sizeof(Pci_msix_cap) == 12,
              "Pci_msix_cap size conforms to specification.");

/// MSI capability for PCI
struct Pci_msi_cap : Pci_cap
{
  enum : l4_uint8_t { Cap_id = Cap_ident::Msi };

  Pci_msi_cap() : Pci_cap(Cap_id) {}

  struct
  {
    l4_uint16_t raw;
    CXX_BITFIELD_MEMBER(8, 8, per_vector_masking, raw);
    CXX_BITFIELD_MEMBER(7, 7, sixtyfour, raw);
    CXX_BITFIELD_MEMBER(4, 6, multiple_message_enable, raw);
    CXX_BITFIELD_MEMBER(1, 3, multiple_message_capable, raw);
    CXX_BITFIELD_MEMBER(0, 0, msi_enable, raw);
  } ctrl;

  l4_uint32_t address = 0;
  l4_uint16_t data = 0;
  // optional, depends on ctrl.sixtyfour()
  l4_uint32_t upper_address = 0;
  unsigned offset = 0; // the offset into the devices config space

  void write_ctrl(l4_uint16_t val)
  {
    static l4_uint16_t const ro_mask = 0xff8e;
    static l4_uint16_t const wr_mask = 0x0071;

    ctrl.raw = (ctrl.raw & ro_mask) | (val & wr_mask);
  };

  l4_uint64_t addr() const
  {
    l4_uint64_t addr = address;
    if (ctrl.sixtyfour())
      addr |= static_cast<l4_uint64_t>(upper_address) << 32;
    return addr;
  }

  unsigned cap_end() const
  {
    if (ctrl.sixtyfour() && ctrl.per_vector_masking())
      return offset + 0x18;
    if (ctrl.sixtyfour())
      return offset + 0xe;
    if (ctrl.per_vector_masking())
      return offset + 0x14;
    return offset + 0xa;
  }
};

struct Pcie_cap_header
{
  enum : l4_uint32_t
  {
    Next_cap_mask = 0xffc, // Lowest two bits of the pointer to the
                           // next capability are reserved
  };

  l4_uint32_t raw;
  CXX_BITFIELD_MEMBER(20, 31, next_cap, raw);
  CXX_BITFIELD_MEMBER(15, 19, version, raw);
  CXX_BITFIELD_MEMBER(0, 15, id, raw);
};

/// SR-IOV capability for PCIe
struct Pcie_sriov_cap
{
  unsigned offset = 0; // the offset into the device's config space

  unsigned cap_end() const
  { return offset + 0x40; }
};

union alignas(sizeof(l4_uint64_t)) Pci_header
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

  virtual void cfg_write_raw(unsigned reg, l4_uint32_t value,
                             Vmm::Mem_access::Width width) = 0;
  virtual void cfg_read_raw(unsigned reg, l4_uint32_t *value,
                            Vmm::Mem_access::Width width) = 0;

  /**
   * Go through all resources of the PCI device and register them with the
   * memmap or iomap.
   *
   * \param vmm The guest where the device is mapped
   * \param access Resources to be added (Io_space_bit | Memory_space_bit)
   */
  virtual void add_decoder_resources(Vmm::Guest *vmm, l4_uint32_t access) = 0;

  /**
   * Go through all resources of the PCI device and remove them from the memmap
   * or iomap.
   *
   * \param vmm The guest where the device is mapped
   * \param access Resources to be removed (Io_space_bit | Memory_space_bit)
   */
  virtual void del_decoder_resources(Vmm::Guest *vmm, l4_uint32_t access) = 0;

  virtual void add_exp_rom_resource() = 0;
  virtual void del_exp_rom_resource() = 0;

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
    cfg_read_raw(Pci_hdr_command_offset, &cmd_reg, Vmm::Mem_access::Wd16);
    // Reenable bar access
    cfg_write_raw(Pci_hdr_command_offset, cmd_reg | (access & Access_mask),
                  Vmm::Mem_access::Wd16);
  }

  /*
   * Disable access to the PCI device.
   *
   * The current configuration will be returned and has to be passed to the
   * enabled_access function to restore the correct configuration when
   * enabling the device again.
   *
   * \param access  The MMIO/IO space configuration bits to disable
   *
   * \return The current MMIO/IO space configuration bits
   */
  l4_uint32_t disable_access(l4_uint32_t access)
  {
    // Disable any bar access
    l4_uint32_t cmd_reg = 0;
    cfg_read_raw(Pci_hdr_command_offset, &cmd_reg, Vmm::Mem_access::Wd16);
    cfg_write_raw(Pci_hdr_command_offset, cmd_reg & ~(access & Access_mask),
                  Vmm::Mem_access::Wd16);

    return cmd_reg & Access_mask;
  }

  /**
   * Update the guest resource registration.
   *
   * \param  Lower byte of the command register of the PCI config space.
   *
   * Will add or remove the resources for the enabled/disabled address space.
   */
  void update_decoders(Vmm::Guest *vmm, l4_uint8_t value)
  {
    l4_uint32_t diff = (enabled_decoders ^ value) & Access_mask;

    if (enabled_decoders & diff)
      del_decoder_resources(vmm, enabled_decoders & diff);
    if (value & diff)
      add_decoder_resources(vmm, value & diff);

    enabled_decoders = value & Access_mask;
  }

  /**
   * Queries the size of a bar.
   */
  unsigned read_bar_size(unsigned bar_offs, l4_uint32_t bar,
                         l4_uint32_t *bar_size)
  {
    cfg_write_raw(bar_offs, 0xffffffffUL, Vmm::Mem_access::Wd32);
    cfg_read_raw(bar_offs, bar_size, Vmm::Mem_access::Wd32);
    cfg_write_raw(bar_offs, bar, Vmm::Mem_access::Wd32);
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
  unsigned read_bar(unsigned bar_offs, unsigned max_bar_offs,
                    Pci_cfg_bar *res)
  {
    // Read the base address reg
    l4_uint32_t bar = 0;
    l4_uint32_t bar_size = 0;
    cfg_read_raw(bar_offs, &bar, Vmm::Mem_access::Wd32);
    if ((bar & Bar_type_mask) == Bar_io_space_bit) // IO bar
      {
        bar_offs = read_bar_size(bar_offs, bar, &bar_size);
        if (bar_size == ~0U)
          return bar_offs;

        bar_size &= ~Bar_io_attr_mask; // clear decoding

        res->type = Pci_cfg_bar::IO;
        res->io_addr = bar & ~Bar_io_attr_mask;
        res->size = (~bar_size & 0xffff) + 1;
      }
    else if ((bar & Bar_mem_type_mask) == Bar_mem_type_32bit) // 32Bit MMIO bar
      {
        bar_offs = read_bar_size(bar_offs, bar, &bar_size);
        if (bar_size == 0)
          return bar_offs;

        bar_size &= ~Bar_mem_attr_mask; // clear decoding

        res->type = Pci_cfg_bar::MMIO32;
        res->io_addr = bar & ~Bar_mem_attr_mask;
        res->size = ~bar_size + 1;
        res->prefetchable = (bar & Bar_mem_prefetch_bit) != 0;
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
        if (bar_offs > max_bar_offs) // max_bar_offset is an inclusive end.
          L4Re::throw_error(-L4_ERANGE,
                            "PCI device implements 64-bit MMIO in last BAR.");

        res->prefetchable = (bar & Bar_mem_prefetch_bit) != 0;

        cfg_read_raw(bar_offs, &bar, Vmm::Mem_access::Wd32);
        addr64 |= static_cast<l4_uint64_t>(bar) << 32; // shift to upper part
        bar_offs = read_bar_size(bar_offs, bar, &bar_size);

        size64 |= static_cast<l4_uint64_t>(bar_size) << 32; // shift to upper part
        size64 &= ~static_cast<l4_uint64_t>(Bar_mem_attr_mask); // clear decoding

        res->type = Pci_cfg_bar::MMIO64;
        res->io_addr = addr64;
        res->size = ~size64 + 1;
      }

    return bar_offs;
  }

  static unsigned expansion_rom_reg(bool type0)
  {
    return type0 ? Pci_hdr_type0_expansion_rom_offset
                 : Pci_hdr_type1_expansion_rom_offset;
  }

  static bool is_bar_reg(bool type0, unsigned reg)
  {
    unsigned max_bar_offset = type0 ? Pci_hdr_type0_base_addr5_offset + 3
                                    : Pci_hdr_type1_base_addr1_offset + 3;
    unsigned expansion_rom = expansion_rom_reg(type0);

    return (reg >= Pci_hdr_base_addr0_offset && reg <= max_bar_offset) ||
           (reg >= expansion_rom             && reg <= expansion_rom + 3);
  }

  /**
   * Read BAR register value.
   *
   * \return True if this was a BAR register, otherwise false.
   */
  bool cfg_read_bar(unsigned reg, l4_uint32_t *value,
                    Vmm::Mem_access::Width width);

  /**
   * Get BAR register value from shadow copy.
   */
  l4_uint32_t get_bar_regval(unsigned bar) const;

  void write_exp_rom_regval(l4_uint32_t value);

  /**
   * Write BAR register value.
   *
   * \return True if this was a BAR register, otherwise false.
   */
  bool cfg_write_bar(unsigned reg, l4_uint32_t value,
                    Vmm::Mem_access::Width width);

  /**
   * Update BAR values from register value.
   *
   * Applies the required masking. BAR updates are only permissible if the
   * respective address space decoder is disabled. Otherwise we loose track
   * of where the current mapping in the guest physical address space is.
   */
  void update_bar(unsigned bar, l4_uint32_t value);

  /**
   * Read from config page.
   *
   * The BAR register content is kept in a shadow copy in the `bars` array.
   * Access to these registers are diverted there. Anything else goes to the
   * underlying HW or virtual device.
   */
  void cfg_read(unsigned reg, l4_uint32_t *value, Vmm::Mem_access::Width width)
  {
    if (!cfg_read_bar(reg, value, width))
      cfg_read_raw(reg, value, width);
  }

  /**
   * Write to config page.
   *
   * If the command register is updated the respective decoder resources will
   * be added or removed from the guest address space. Updates of the BAR
   * registers are diverted to the internal `bars` shadow array. Anything else
   * goes to the underlying HW or virtual device.
   */
  void cfg_write(Vmm::Guest *vmm, unsigned reg, l4_uint32_t value,
                 Vmm::Mem_access::Width width)
  {
    if (reg == Pci_hdr_command_offset)
      update_decoders(vmm, value & 0xffU); // mask value to byte size.

    if (!cfg_write_bar(reg, value, width))
      cfg_write_raw(reg, value, width);
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
    cfg_read_raw(msix_cap_addr + 2, &ctrl, Vmm::Mem_access::Wd16);
    msix_cap.ctrl.raw = static_cast<l4_uint16_t>(ctrl);
    cfg_read_raw(msix_cap_addr + 4, &msix_cap.tbl.raw, Vmm::Mem_access::Wd32);
    cfg_read_raw(msix_cap_addr + 8, &msix_cap.pba.raw, Vmm::Mem_access::Wd32);

    has_msix = true;
  }

  void parse_msi_cap()
  {
    unsigned msi_cap_addr = get_capability(Cap_ident::Msi);
    if (!msi_cap_addr)
      return;

    msi_cap.offset = msi_cap_addr;

    l4_uint32_t ctrl = 0;
    cfg_read_raw(msi_cap_addr + 2, &ctrl, Vmm::Mem_access::Wd16);
    msi_cap.ctrl.raw = static_cast<l4_uint16_t>(ctrl);

    // Disable multi MSI, as we don't support it, yet.
    msi_cap.ctrl.multiple_message_capable() = 0;

    has_msi = true;
  }

  void parse_sriov_cap()
  {
    unsigned sriov_cap_addr = get_ext_capability(Ext_cap_ident::Sr_iov);
    if (!sriov_cap_addr)
      return;

    sriov_cap.offset = sriov_cap_addr;
    has_sriov = true;
  }

  /**
   * Walk capabilities list and return the first capability of `cap_type` (see
   * PCI Spec. Version 3, Chapter 6.7). If none is found return 0.
   *
   * \param cap_type  Capability type to retrieve
   *
   * \returns 0       If no capability was found.
   *          >0      Pointer to the capability.
   */
  unsigned get_capability(l4_uint8_t cap_type)
  {
    l4_uint32_t val = 0;
    cfg_read_raw(Pci_hdr_status_offset, &val, Vmm::Mem_access::Wd16);
    if (!(val & Pci_header_status_capability_bit))
      {
        trace().printf("Pci_header_status_capability_bit is not set.\n");
        return 0;
      }

    cfg_read_raw(Pci_hdr_capability_offset, &val, Vmm::Mem_access::Wd8);

    l4_uint8_t next_cap = val & Pci_cap_mask::Next_cap;

    if (next_cap == 0)
      {
        trace().printf("get_capability: Capability pointer is zero.\n");
        return 0;
      }

    // Capability list is terminated by zero next pointer.
    while (next_cap)
      {
        cfg_read_raw(next_cap, &val, Vmm::Mem_access::Wd16);
        l4_uint8_t cap_id = val & Pci_cap_mask::Cap_id;
        trace().printf("get_capability: found cap id 0x%x (cap addr 0x%x)\n",
                       cap_id, next_cap);

        if (cap_id == cap_type)
          return next_cap;

        next_cap = (val >> 8) & Pci_cap_mask::Next_cap;
      }

    trace().printf("get_capability: Did not find capability of type 0x%x\n",
                   cap_type);

    return 0;
  }

  /**
   * Walk PCIe extended capabilities list and return the first capability of
   * `cap_type` (see PCI Express Spec. Version 5, Chapter 7.6). If none is found
   * return 0.
   *
   * \param cap_type     Capability type to retrieve
   * \param min_version  Minimum required version of the capability
   *
   * \returns 0          If no capability was found.
   *          >0         Pointer to the capability.
   */
  unsigned get_ext_capability(Ext_cap_ident cap_type, l4_uint8_t min_version = 0)
  {
    if (!get_capability(Cap_ident::Pcie))
      // Not a PCIe device.
      return 0;

    l4_uint16_t next_cap = 0x100;
    // Extended capability list is terminated by zero next pointer.
    while (next_cap)
      {
        l4_uint32_t val = 0;
        cfg_read_raw(next_cap, &val, Vmm::Mem_access::Wd32);

        Pcie_cap_header cap{val};
        if (cap.id() == cap_type && cap.version() >= min_version)
          // Found matching capability.
          return next_cap;

        next_cap = cap.next_cap() & Pcie_cap_header::Next_cap_mask;
      }

    // No matching capability found.
    return 0;
  }

  /**
   * Parses all bars for a specific device.
   *
   * Only used for Hw_pci_device devices to sync the BAR shadow copy with the
   * actual state on the vbus. Guest writes are only working on the shadow copy
   * afterwards.
   */
  void parse_device_bars()
  {
    unsigned const max_bar_offset =
      get_header_type() == Pci_header_type::Type0
        ? Pci_hdr_type0_base_addr5_offset
        : Pci_hdr_type1_base_addr1_offset;

    // Disable all access because read_bar() actually modifies the BARs to
    // detect the size.
    l4_uint32_t access = disable_access(Access_mask);

    unsigned bar_offs = Pci_hdr_base_addr0_offset;
    while (bar_offs <= max_bar_offset)
      {
        unsigned i = (bar_offs - Pci_hdr_base_addr0_offset) / 4U;
        Pci_cfg_bar &bar = bars[i];

        // Read one bar configuration
        bar_offs = read_bar(bar_offs, max_bar_offset, &bar);

        if (bar.type == Pci_cfg_bar::MMIO64)
          bars[i + 1].type = Pci_cfg_bar::Reserved_mmio64_upper;
        else if (bar.type == Pci_cfg_bar::Unused_empty)
          continue;

        info().printf("  bar[%u] addr=0x%llx size=0x%llx type=%s\n", i,
                      bar.io_addr, bar.size, bar.to_string());
      }

    // Reenable bar access
    enable_access(access);
  }

  /**
   * Only use for Hw_pci_device.
   */
  void parse_device_exp_rom()
  {
    Pci_header_type hdr_type = get_header_type();
    unsigned rom_reg = expansion_rom_reg(hdr_type == Pci_header_type(0));

    trace().printf("Parsing expansion ROM reg 0x%x of type %i header\n",
                   rom_reg, hdr_type);
    l4_uint32_t access = disable_access(Access_mask);

    l4_uint32_t val = 0;
    cfg_read_raw(rom_reg, &val, Vmm::Mem_access::Wd32);

    enum : l4_uint32_t
    {
      Expansion_rom_address_shift = 11,
      Expansion_rom_address_mask = -1U << Expansion_rom_address_shift
    };

    l4_uint32_t size = 0;
    cfg_write_raw(rom_reg, Expansion_rom_address_mask, Vmm::Mem_access::Wd32);
    cfg_read_raw(rom_reg, &size, Vmm::Mem_access::Wd32);
    cfg_write_raw(rom_reg, val, Vmm::Mem_access::Wd32);

    enable_access(access);

    exp_rom.io_addr = val & size;
    exp_rom.hw_enabled = val & Pci_expansion_rom_bar::Enable_bit;
    exp_rom.size = ~size + 1;

    info().printf("Expansion ROM addr reg(0x%x) as read from hardware: 0x%x, "
                  "size 0x%llx (from hardware: 0x%x)\n",
                  rom_reg, val, exp_rom.size, size);

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
    cfg_read_raw(Pci_hdr_type_offset, &header_type, Vmm::Mem_access::Wd8);
    return header_type & 0xff;
  }

  // These registers keep track of the BARs that are actually mapped.
  // We expect the guest to reprogram PCI BARs. These writes will modify the
  // in-memory header BARs, but only when the IO/MMIO decode bits are set in
  // the control register, we actually commit the configuration (program the
  // mappings and save the configuration into the shadow registers).
  Pci_cfg_bar bars[Bar_num_max_type0];
  Pci_expansion_rom_bar exp_rom;
  Pci_msix_cap msix_cap;               /// MSI-X capability
  Pci_msi_cap msi_cap;                 /// MSI capability
  Pcie_sriov_cap sriov_cap;            /// SR-IOV capability
  l4_uint8_t enabled_decoders = 0;     /// Currently registered resources
  bool has_msix = false;               /// indicates MSI-X support
  bool has_msi = false;                /// indicates MSI support
  bool has_sriov = false;              /// indicates SR-IOV support

private:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI dev"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI dev"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI dev"); }
};

} } // namespace Vdev::Pci
