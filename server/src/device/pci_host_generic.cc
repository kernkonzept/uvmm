/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <l4/vbus/vbus>
#include <l4/re/error_helper>

#include "acpi.h"
#include "debug.h"
#include "device.h"
#include "pci_bus_cfg_ecam.h"
#include "pci_host_bridge.h"
#include "device_factory.h"
#include "guest.h"
#include "ds_mmio_mapper.h"
#include "io_port_handler.h"

namespace Vdev { namespace Pci {

/**
 * PCI bus emulation.
 *
 * The emulated host bridge handles the PCI bus transaction initialized by the
 * guest OS. Linux detects the virtual host bridge and queries the root bus for
 * devices present.
 * If hardware devices are supplied via Vbus, the virtio devices are merged
 * into Vbus' PCI root bus.
 */
class Pci_host_generic:
  public Pci_host_bridge,
  public Device,
  public Acpi::Acpi_device
{
  Pci_header::Type1 *header()
  { return get_header<Pci_header::Type1>(); }

  Pci_header::Type1 const *header() const
  { return get_header<Pci_header::Type1>(); }

  void init_bus_range(Dt_node const &node);
  void init_bridge_window(Dt_node const &node);

public:
  explicit Pci_host_generic(Device_lookup *devs, Dt_node const &node,
                            cxx::Ref_ptr<Gic::Msix_controller> msix_ctrl)
  : Pci_host_bridge(devs, msix_ctrl)
  {
    init_bus_range(node);
    init_bridge_window(node);

    // Linux' x86 PCI_direct code sanity checks for a device with class code
    // PCI_CLASS_DISPLAY_VGA(0x0300) or PCI_CLASS_BRIDGE_HOST(0x00) or for a
    // device of vendor INTEL or COMPAQ.
    // see linux/arch/x86/pci/direct.c
    header()->classcode[2] = Pci_class_code_bridge_device;
    header()->classcode[1] = Pci_subclass_code_host;
    header()->header_type = 1; // PCI_TO_PCI_BRIDGE
    header()->command |= Bus_master_bit;

    setup_devices();
  }

  void init_dev_resources(Hw_pci_device *) override;

  bool has_ecam() const
  { return _ecam_mcfg_size != 0; }

  /**
   * Add a MCFG allocation for the ECAM MCFG window of the PCI host bridge.
   */
  l4_size_t amend_mcfg(ACPI_MCFG_ALLOCATION *alloc, l4_size_t max_size) const override
  {
    if (!has_ecam())
      return 0;

    if (max_size < sizeof(ACPI_MCFG_ALLOCATION))
      L4Re::throw_error(-L4_ENOMEM,
        "Not enough space in ACPI MCFG table for PCI host bridge.");

    alloc->Address = _ecam_mcfg_base;
    alloc->PciSegment = 0;
    alloc->StartBusNumber = header()->secondary_bus_num;
    alloc->EndBusNumber = header()->subordinate_bus_num;
    alloc->Reserved = 0;

    return sizeof(ACPI_MCFG_ALLOCATION);
  };

  /**
   * Add a minimal DSDT system bus so that the PCI bridge is discoverable via
   * ACPI. Generated from the following ASL:
   *
   * DefinitionBlock ("Dsdt.aml", "DSDT", 1, "UVMM  ", "KERNKONZ", 4) {
   *   //
   *   //  System Bus
   *   //
   *   Scope (\_SB) {
   *     //
   *     // PCI Root Bridge
   *     //
   *     Device (PCI0) {
   *       Name (_HID, EISAID ("PNP0A08")) // PCI Express Root Bridge
   *       Name (_CID, EISAID ("PNP0A03")) // Compatible PCI Root Bridge
   *       Name (_ADR, 0x00000000)
   *       Name (_BBN, 0x00)
   *       Name (_UID, 0x00)
   *
   *       //
   *       // BUS, I/O, and MMIO resources
   *       //
   *       Name (_CRS, ResourceTemplate () {
   *         WORDBusNumber (          // Bus number resource (0); the bridge produces bus numbers for its subsequent buses
   *           ResourceProducer,      // bit 0 of general flags is 1
   *           MinFixed,              // Range is fixed
   *           MaxFixed,              // Range is fixed
   *           PosDecode,             // PosDecode
   *           0x0000,                // Granularity
   *           0xAAAA,                // Min
   *           0xBBBB,                // Max
   *           0x0000,                // Translation
   *           0x1112                 // Range Length = Max-Min+1
   *           )
   *
   *         IO (Decode16, 0xCF8, 0xCF8, 0x01, 0x08)       //Consumed resource (0xCF8-0xCFF)
   *
   *         WORDIO (                 // Consumed-and-produced resource (I/O window 0x8000 - 0xFFFF)
   *           ResourceProducer,      // bit 0 of general flags is 0
   *           MinFixed,              // Range is fixed
   *           MaxFixed,              // Range is fixed
   *           PosDecode,
   *           EntireRange,
   *           0x0000,                // Granularity
   *           0x8000,                // Min
   *           0xFFFF,                // Max
   *           0x0000,                // Translation
   *           0x8000                 // Range Length
   *           )
   *
   *         DWORDMEMORY (            // Descriptor for 32-bit MMIO
   *           ResourceProducer,      // bit 0 of general flags is 0
   *           PosDecode,
   *           MinFixed,              // Range is fixed
   *           MaxFixed,              // Range is Fixed
   *           NonCacheable,
   *           ReadWrite,
   *           0x00000000,            // Granularity
   *           0xAAAAAAAA,            // Min
   *           0xBBBBBBBB,            // Max
   *           0x00000000,            // Translation
   *           0x11111112,            // Range Length
   *           )
   *       })
   *     }
   *   }
   * }
   *
   * Conversion (save above as Dsdt.asl):
   *   $ iasl Dsdt.asl
   *   $ xxd -i -s 0x24 -c 8 Dsdt.aml
   */
  l4_size_t amend_dsdt(void *buf, l4_size_t max_size) const override
  {
    unsigned char dsdt_pci[] = {
      /* 0x00 */ 0x10, 0x42, 0x08, 0x5f, 0x53, 0x42, 0x5f, 0x5b,
      /* 0x08 */ 0x82, 0x4a, 0x07, 0x50, 0x43, 0x49, 0x30, 0x08,
      /* 0x10 */ 0x5f, 0x48, 0x49, 0x44, 0x0c, 0x41, 0xd0, 0x0a,
      /* 0x18 */ 0x08, 0x08, 0x5f, 0x43, 0x49, 0x44, 0x0c, 0x41,
      /* 0x20 */ 0xd0, 0x0a, 0x03, 0x08, 0x5f, 0x41, 0x44, 0x52,
      /* 0x28 */ 0x00, 0x08, 0x5f, 0x42, 0x42, 0x4e, 0x00, 0x08,
      /* 0x30 */ 0x5f, 0x55, 0x49, 0x44, 0x00, 0x08, 0x5f, 0x43,
      /* 0x38 */ 0x52, 0x53, 0x11, 0x48, 0x04, 0x0a, 0x44, 0x88,
      /* 0x40 */ 0x0d, 0x00, 0x02, 0x0c, 0x00, 0x00, 0x00,

      // bus range
      /* 0x47 */0xaa, 0xaa, // Min
      /* 0x49 */0xbb, 0xbb, // Max
      /* 0x4b */0x00, 0x00, // Translation
      /* 0x4d */0x12, 0x11, // Range Length

      /* 0x4f */ 0x47,
      /* 0x50 */ 0x01, 0xf8, 0x0c, 0xf8, 0x0c, 0x01, 0x08, 0x88,
      /* 0x58 */ 0x0d, 0x00, 0x01, 0x0c, 0x03, 0x00, 0x00,

      // I/O window
      /* 0x5f */ 0x00, 0x80, // Min
      /* 0x61 */ 0xff, 0xff, // Max
      /* 0x63 */ 0x00, 0x00, // Translation
      /* 0x65 */ 0x00, 0x80, // Range Length

      /* 0x67 */ 0x87,
      /* 0x68 */ 0x17, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x00,
      /* 0x70 */ 0x00,

      // MMIO window
      /* 0x71 */ 0xaa, 0xaa, 0xaa, 0xaa, // Min
      /* 0x75 */ 0xbb, 0xbb, 0xbb, 0xbb, // Max
      /* 0x79 */ 0x00, 0x00, 0x00, 0x00, // Translation
      /* 0x7d */ 0x12, 0x11, 0x11, 0x11, // Range Length

      /* 0x81 */ 0x79, 0x00
    };

    // Update "bus range" with actual values from device tree
    auto const *hdr = header();
    *reinterpret_cast<l4_uint16_t*>(&dsdt_pci[0x47]) = hdr->secondary_bus_num;
    *reinterpret_cast<l4_uint16_t*>(&dsdt_pci[0x49]) = hdr->subordinate_bus_num;
    *reinterpret_cast<l4_uint16_t*>(&dsdt_pci[0x4d]) =
      hdr->subordinate_bus_num - hdr->secondary_bus_num + 1U;

    // Update "I/O window" with actual values from device tree
    *reinterpret_cast<l4_uint16_t*>(&dsdt_pci[0x5f]) = _io_base;
    *reinterpret_cast<l4_uint16_t*>(&dsdt_pci[0x61]) = _io_base + _io_size - 1U;
    *reinterpret_cast<l4_uint16_t*>(&dsdt_pci[0x65]) = _io_size;

    // Update "MMIO window" with actual values from device tree
    *reinterpret_cast<l4_uint32_t*>(&dsdt_pci[0x71]) = _mmio_base;
    *reinterpret_cast<l4_uint32_t*>(&dsdt_pci[0x75]) = _mmio_base + _mmio_size - 1U;
    *reinterpret_cast<l4_uint32_t*>(&dsdt_pci[0x7d]) = _mmio_size;

    l4_size_t size = sizeof(dsdt_pci);
    if (max_size < size)
      L4Re::throw_error(-L4_ENOMEM,
        "Not enough space in DSDT ACPI table for PCI host bridge.");
    std::memcpy(buf, &dsdt_pci, size);

    if (has_ecam())
      size += amend_dsdt_with_mcfg(static_cast<l4_uint8_t *>(buf) + size,
                                   max_size - size);
    return size;
  }

  /**
   * Reserve ECAM MCFG window. Generated from the following ASL:
   *
   * DefinitionBlock ("Dsdt.aml", "DSDT", 1, "UVMM  ", "KERNKONZ", 4) {
   *   //
   *   //  System Bus
   *   //
   *   Scope (\_SB) {
   *     //
   *     // Reserved resources
   *     //
   *     Device (RES0) {
   *       Name (_HID, EISAID ("PNP0C02")) // ID used for reserving resources
   *       Name (_UID, 0x00)
   *
   *       //
   *       // Reserved MMIO resources
   *       //
   *       Name (_CRS, ResourceTemplate () {
   *         QWordMemory (            // Descriptor for ECAM MCFG
   *            ResourceConsumer,     // The value of this should not matter for the reservation,
   *                                  // but conceptully the PCI root bridge consumes memory access
   *                                  // converting them into a PCI configuration space access.
   *            PosDecode,
   *            MinFixed,             // Range is fixed
   *            MaxFixed,             // Range is fixed
   *            NonCacheable,
   *            ReadWrite,
   *            0x0000000000000000,   // Granularity
   *            0xAAAAAAAAAAAAAAAA,   // Min
   *            0xBBBBBBBBBBBBBBBB,   // Max
   *            0x0000000000000000,   // Translation
   *            0x1111111111111112,   // Range Length
   *            )
   *        })
   *      }
   *   }
   * }
   *
   * Conversion (save above as Dsdt.asl):
   *   $ iasl Dsdt.asl
   *   $ xxd -i -s 0x24 -c 8 Dsdt.aml
   */
  l4_size_t amend_dsdt_with_mcfg(void *buf, l4_size_t max_size) const
  {
    unsigned char dsdt_pci_mcfg[] = {
      /* 0x00 */ 0x10, 0x47, 0x05, 0x5f, 0x53, 0x42, 0x5f, 0x5b,
      /* 0x08 */ 0x82, 0x4f, 0x04, 0x52, 0x45, 0x53, 0x30, 0x08,
      /* 0x10 */ 0x5f, 0x48, 0x49, 0x44, 0x0c, 0x41, 0xd0, 0x0c,
      /* 0x18 */ 0x02, 0x08, 0x5f, 0x55, 0x49, 0x44, 0x00, 0x08,
      /* 0x20 */ 0x5f, 0x43, 0x52, 0x53, 0x11, 0x33, 0x0a, 0x30,
      /* 0x28 */ 0x8a, 0x2b, 0x00, 0x00, 0x0d, 0x01, 0x00, 0x00,
      /* 0x30 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

      // ECAM MCFG window
      /* 0x36 */ 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // Min
      /* 0x3e */ 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, // Max
      /* 0x46 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Translation
      /* 0x4e */ 0x12, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // Range Length

      /* 0x56 */ 0x79, 0x00
    };

    // Update "ECAM MCFG window" with actual values from device tree
    *reinterpret_cast<l4_uint64_t*>(&dsdt_pci_mcfg[0x36]) = _ecam_mcfg_base;
    auto ecam_mcfg_max = _ecam_mcfg_base + _ecam_mcfg_size - 1U;
    *reinterpret_cast<l4_uint64_t*>(&dsdt_pci_mcfg[0x3e]) = ecam_mcfg_max;
    *reinterpret_cast<l4_uint64_t*>(&dsdt_pci_mcfg[0x4e]) = _ecam_mcfg_size;

    l4_size_t size = sizeof(dsdt_pci_mcfg);
    if (max_size < size)
      L4Re::throw_error(-L4_ENOMEM,
        "Not enough space in DSDT ACPI for PCI host bridge MCFG reservation.");
    std::memcpy(buf, &dsdt_pci_mcfg, size);
    return size;
  }

protected:
  cxx::Ref_ptr<Vmm::Mmio_device> get_mmio_bar_handler(unsigned) override
  {
    assert(false); // Must not be called. No BARs set up.
    return nullptr;
  }

  cxx::Ref_ptr<Vmm::Io_device> get_io_bar_handler(unsigned) override
  {
    assert(false); // Must not be called. No BARs set up.
    return nullptr;
  }

private:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI bus"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI bus"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI bus"); }

  l4_uint64_t _mmio_base = 0;
  l4_uint64_t _mmio_size = 0;
  l4_uint16_t _io_base = 0xffff;
  l4_uint16_t _io_size = 0;
  l4_uint64_t _ecam_mcfg_base = 0;
  l4_uint64_t _ecam_mcfg_size = 0;
}; // class Pci_host_generic

/**
 * Interface to handle IO port access to the PCI configuration space and
 * translate it to an internal protocol.
 */
class Pci_bus_cfg_io : public Vmm::Io_device
{
  struct Config_address
  {
    l4_uint32_t raw = 0;
    CXX_BITFIELD_MEMBER(31, 31, enabled, raw);
    CXX_BITFIELD_MEMBER(24, 27, reghi, raw);
    CXX_BITFIELD_MEMBER(16, 23, bus, raw);
    CXX_BITFIELD_MEMBER(11, 15, dev, raw);
    CXX_BITFIELD_MEMBER( 8, 10, func, raw);
    CXX_BITFIELD_MEMBER( 2,  7, reglo, raw);
    CXX_BITFIELD_MEMBER( 0,  1, type, raw);

    unsigned reg() const
    {
      // the PCI standard requests the lowest two bits to be 0;
      return (static_cast<unsigned>(reghi()) << 8) | (reglo() << 2);
    }
  };
  Config_address _cfg_addr;
  cxx::Ref_ptr<Pci_host_generic> _bus;

  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI bus io"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI bus io"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI bus io"); }

  enum
  {
    Pci_bus_config_address    = 0,
    Pci_bus_fwd_register      = 2,
    Pci_bus_config_mechanism  = 3,
    Pci_bus_config_data       = 4,
    Pci_bus_config_data_15_8  = 5,
    Pci_bus_config_data_31_16 = 6,
    Pci_bus_config_data_31_24 = 7,
  };

public:
  Pci_bus_cfg_io(cxx::Ref_ptr<Pci_host_generic> const &pci_bus) : _bus(pci_bus) {}

  void io_out(unsigned port, Vmm::Mem_access::Width width,
              l4_uint32_t value) override
  {
    using Vmm::Mem_access;
    trace().printf("OUT access @0x%x/%d => 0x%x\n", port, width, value);

    switch (port)
      {
      case Pci_bus_config_mechanism:
        if (width == Mem_access::Wd8)
          {
            // if 1 -> PCI conf mechanism 1
            // if 0 -> PCI conf mechanism 2 (deprecated 1992)
            // PCI v.3 does not support mechanism 2, hence ignore and return.
            // XXX Probing can be suppressed by adding 'pci=conf1' to the
            // cmdline
            return;
          }
        break;
      case Pci_bus_fwd_register:
        // identifies 1 of 256 possible PCI busses
        // used in deprecated PCI conf mechansim 2; only byte width access
        break;

      case Pci_bus_config_address: // Configuration Space Enable - CSE
        if (width == Mem_access::Wd32)
          {
            _cfg_addr.raw = value;
            return;
          }
        // non 32bit width access is normal IO transaction.
        break;

      case Pci_bus_config_data_31_24:
        // Falls through.
      case Pci_bus_config_data_15_8:
        if (width != Mem_access::Wd8)
          break;
        // Else falls through.
      case Pci_bus_config_data_31_16:
        if (width == Mem_access::Wd32)
          break;
        // Else falls through.
      case Pci_bus_config_data:
        {
          if (!_cfg_addr.enabled())
            return;

          unsigned reg = _cfg_addr.reg() + (port - Pci_bus_config_data);
          if (_cfg_addr.bus() > 0 || _cfg_addr.func() > 0)
            return;
          _bus->cfg_space_write(_cfg_addr.dev().get(), reg, width, value);
          return;
        }
      }

    trace().printf("Unhandled OUT access @0x%x/%d => 0x%x\n", port,
                   width, value);
  }

  void io_in(unsigned port, Vmm::Mem_access::Width width,
             l4_uint32_t *value) override
  {
    using Vmm::Mem_access;
    trace().printf("IN access to @0x%x/%d\n", port, width);

    *value = -1;

    switch (port)
      {
      case Pci_bus_fwd_register: // identifies 1 of 256 possible PCI busses
        break;

      case Pci_bus_config_address:
        if (width == Mem_access::Wd32)
          {
            *value = _cfg_addr.raw;
            trace().printf("IN access to PCI config space @0x%x/%d => 0x%x\n",
                           port, width, *value);
            return;
          }
        break;
      case Pci_bus_config_data_31_24:
        // Falls through.
      case Pci_bus_config_data_15_8:
        if (width != Mem_access::Wd8)
          break;
        // Else falls through.
      case Pci_bus_config_data_31_16:
        if (width == Mem_access::Wd32)
          break;
        // Else falls through.
      case Pci_bus_config_data:
        {
          if (!_cfg_addr.enabled())
            return;

          unsigned reg = _cfg_addr.reg() + (port - Pci_bus_config_data);
          if (_cfg_addr.bus() > 0 || _cfg_addr.func() > 0)
            {
              *value = ~0;
              return;
            }
          trace().printf("io_in: dev = %d\n", _cfg_addr.dev().get());
          assert(_bus != nullptr);
          *value = _bus->cfg_space_read(_cfg_addr.dev().get(),
                                        reg, width);
          trace().printf("IN access @0x%x/%d reg: 0x%x --> 0x%x\n", port, width,
                         reg, *value);
          return;
        }
      }
    trace().printf("Unhandled IN access @0x%x/%d\n", port, width);
  }
}; // Pci_bus_cfg_io

void
Pci_host_generic::init_bus_range(Dt_node const &node)
{
  int sz;
  auto bus_range = node.get_prop<fdt32_t>("bus-range", &sz);
  if (sz != 2)
    {
      Err().printf("Bus range property of Pci_host_bridge has invalid size\n");
      return;
    }

  trace().printf("Init host bridge: Found 'bus-range' 0x%x - 0x%x\n",
                 fdt32_to_cpu(bus_range[0]), fdt32_to_cpu(bus_range[1]));

  auto *const hdr = header();
  hdr->secondary_bus_num = (l4_uint8_t)fdt32_to_cpu(bus_range[0]);
  hdr->subordinate_bus_num = (l4_uint8_t)fdt32_to_cpu(bus_range[1]);
}

/**
 * Retrieve bridge MMIO and I/O windows from ranges property, and the ECAM MCFG
 * window from the reg property.
 *
 * The actual values are irrelevant for uvmm. They are only gathered to be
 * forwarded to the guest via ACPI. See amend_dsdt() above.
 */
void
Pci_host_generic::init_bridge_window(Dt_node const &node)
{
  int prop_size;
  auto prop = node.get_prop<fdt32_t>("ranges", &prop_size);
  if (!prop)
    L4Re::throw_error(-L4_EINVAL, "missing ranges property");

  auto parent = node.parent_node();
  auto parent_addr_cells = node.get_address_cells(parent);
  size_t child_addr_cells = node.get_address_cells(node);
  size_t child_size_cells = node.get_size_cells(node);

  unsigned range_size = child_addr_cells + parent_addr_cells + child_size_cells;
  if (prop_size % range_size != 0)
    L4Re::throw_error(-L4_EINVAL, "invalid ranges property");

  for (auto end = prop + prop_size; prop < end; prop += range_size)
    {
      auto flags = Dtb::Reg_flags::pci(fdt32_to_cpu(*prop));
      Dtb::Cell parent_base(prop + child_addr_cells, parent_addr_cells);
      Dtb::Cell size(prop + child_addr_cells + parent_addr_cells,
                     child_size_cells);

      if (flags.is_mmio32())
        {
          _mmio_base = parent_base.get_uint64();
          _mmio_size = size.get_uint64();
        }
      else if (flags.is_ioport())
        {
          _io_base = parent_base.get_uint64();
          _io_size = size.get_uint64();
        }
    }

  int res = node.get_reg_val(0, &_ecam_mcfg_base, &_ecam_mcfg_size);
  if (res < 0)
    {
      _ecam_mcfg_size = 0;
      info().printf("No ECAM MCFG window provided via reg property, "
                    "thus ECAM is not going to be available to the guest.\n");
    }

  trace().printf("MMIO window at [0x%llx, 0x%llx]\n", _mmio_base,
                 _mmio_base + _mmio_size - 1U);
  trace().printf("I/O window at [0x%x, 0x%x]\n", _io_base,
                 _io_base + _io_size - 1U);
  if (has_ecam())
    {
      trace().printf("ECAM MCFG window at [0x%llx, 0x%llx]\n", _ecam_mcfg_base,
                     _ecam_mcfg_base + _ecam_mcfg_size - 1U);
      if (_ecam_mcfg_base >= 0x100000000ULL)
        // Linux does not accept MCFG addresses above 4GB unless a
        // BIOS year >= 2010 is provided via DMI (see acpi_mcfg_check_entry()).
        warn().printf(
          "Linux will ignore ECAM MCFG window because it is above 4GB.\n");
    }
}

void
Pci_host_generic::init_dev_resources(Hw_pci_device *)
{}

} } // namespace Vdev::Pci

namespace {

using namespace Vdev;
using namespace Vdev::Pci;

struct F : Factory
{
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI bus"); }

  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    info().printf("Creating host bridge\n");

    if (!node.has_prop("bus-range"))
      {
        info().printf(
          "Bus range not specified in device tree. Device not created.\n");
        return nullptr;
      }

    auto dev = make_device<Pci_host_generic>(devs, node,
                                             devs->get_or_create_mc_dev(node));

    auto io_cfg_connector = make_device<Pci_bus_cfg_io>(dev);
    auto region = Vmm::Io_region(0xcf8, 0xcff, Vmm::Region_type::Virtual);
    devs->vmm()->add_io_device(region, io_cfg_connector);

    if (dev->has_ecam())
      {
        auto ecam_cfg_connector = make_device<Pci_bus_cfg_ecam>(dev);
        devs->vmm()->register_mmio_device(ecam_cfg_connector,
                                          Vmm::Region_type::Virtual, node);
      }

    info().printf("Created & Registered the PCI host bridge\n");
    return dev;
  }
}; // struct F

static F f;
static Device_type t = {"virt-pci-bridge", nullptr, &f};

} // namespace
