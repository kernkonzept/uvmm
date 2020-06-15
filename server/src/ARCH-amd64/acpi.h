/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020 Kernkonzept GmbH.
 * Author(s): Benjamin Lamowski <benjamin.lamowski@kernkonzept.com>
 *
 */

/**
 * \file
 * Basic ACPI tables.
 *
 * Adapted from the ACPI Specification version 6.3.
 * Currently only implements the ACPI tables necessary to make Linux find local
 * APICs for SMP.
 */

#pragma once

#include <l4/cxx/utils>
#include <consts.h>
#include <vector>

#include "debug.h"
#include "guest.h"
#include "cpu_dev_array.h"
#include "cpu_dev.h"
#include "virt_lapic.h"

extern "C" {
#include "platform/acenv.h"
#include "actypes.h"
#include "actbl.h"
}

namespace Acpi
{
static Dbg info(Dbg::Dev, Dbg::Info, "ACPI");
static Dbg warn(Dbg::Dev, Dbg::Warn, "ACPI");
static Dbg trace(Dbg::Dev, Dbg::Trace, "ACPI");

class Tables;
class Acpi_device;
/**
 * Registry of devices that need to insert information into Acpi tables.
 *
 * Upon Uvmm startup devices will be created from the device tree. These can
 * register themselves here. The Acpi::Tables class will then call the
 * Acpi_device functions of these devices to fill the Acpi tables. It will
 * also delete the Acpi_device_hub after use.
 */
class Acpi_device_hub
{
  friend class Tables;
public:
  static void register_device(Acpi_device const *dev)
  { get()->_devices.push_back(dev); }

private:
  static Acpi_device_hub *get()
  {
    if (!_hub)
      _hub = new Acpi_device_hub();
    return _hub;
  }

  std::vector<Acpi_device const*> const &devices() const
  {
    return _devices;
  }

  static void destroy()
  {
    if (_hub)
      delete _hub;
    _hub = nullptr;
  }

  Acpi_device_hub() = default;
  ~Acpi_device_hub() = default;
  static Acpi_device_hub *_hub;
  std::vector<Acpi_device const*> _devices;
};

/**
 * Devices that must register with Acpi shall implement this interface.
 */
class Acpi_device
{
public:
  explicit Acpi_device()
  {
    Acpi_device_hub::register_device(this);
  }

  virtual void amend_fadt(ACPI_TABLE_FADT *) const {};
  virtual size_t amend_dsdt(void *, size_t) const { return 0; };
};

/**
 * ACPI control.
 *
 * Manage the creation of ACPI tables in guest memory.
 */
class Tables
{
  enum : l4_uint32_t
  {
    /**
     * Physical location of the RSDP according to section 5.2.5.1 of the ACPI
     * Specification.
     */
    Phys_start_addr = 0x0E0000
  };

  enum Table_sizes : size_t
  {
    Header_size = sizeof(ACPI_TABLE_HEADER),
    Rsdp_size = sizeof(ACPI_TABLE_RSDP),
    Rsdp_v1_size = 20,
    Rsdt_size = Header_size + 2 * sizeof(UINT32),
    Fadt_size = sizeof(ACPI_TABLE_FADT),
    Ioapic_size = sizeof(ACPI_MADT_IO_APIC),
    Lapic_size = sizeof(ACPI_MADT_LOCAL_APIC),
    Madt_basic_size = sizeof(ACPI_TABLE_MADT)
  };

public:
  /**
   * ACPI control structure.
   *
   * \param ram  Guest RAM.
   */
  Tables(cxx::Ref_ptr<Vmm::Vm_ram> ram)
  {
    info.printf("Initialize ACPI tables.\n");
    _dest_addr = ram->guest2host<l4_addr_t>(Vmm::Guest_addr(Phys_start_addr));
    _ram = ram;
  }

  ~Tables()
  {
    Acpi_device_hub::destroy();
  }

  /**
   * Calculate positions for each table and write them in place.
   */
  void write_to_guest(unsigned cpus)
  {
    auto madt_size = Madt_basic_size + Ioapic_size + cpus * Lapic_size;

    l4_addr_t const rsdp = _dest_addr;
    l4_addr_t const rsdt = l4_round_size(rsdp + Rsdp_size, 4);
    l4_addr_t const fadt = l4_round_size(rsdt + Rsdt_size, 4);
    l4_addr_t const madt = l4_round_size(fadt + Fadt_size, 4);
    l4_addr_t const dsdt = l4_round_size(madt + madt_size, 4);
    // we allow the dsdt to take up the rest of the page
    size_t dsdt_max = L4_PAGESIZE - (dsdt - rsdp);

    auto acpi_mem =
      Vmm::Region::ss(Vmm::Guest_addr(Phys_start_addr),
                      dsdt - _dest_addr + Header_size, Vmm::Region_type::Ram);
    // Throws an exception if the ACPI memory region isn't within guest RAM.
    _ram->guest2host<l4_addr_t>(acpi_mem);

    // Clear memory because we do not rely on the DS provider to do this for
    // us, and we must not have spurious values in Acpi tables.
    memset(reinterpret_cast<void *>(rsdp), 0, dsdt_max);

    write_rsdp(reinterpret_cast<ACPI_TABLE_RSDP *>(rsdp), rsdt);
    write_rsdt(reinterpret_cast<ACPI_TABLE_RSDT *>(rsdt), madt, fadt);
    write_fadt(reinterpret_cast<ACPI_TABLE_FADT *>(fadt), dsdt);
    write_madt(reinterpret_cast<ACPI_TABLE_MADT *>(madt), cpus);
    write_dsdt(reinterpret_cast<ACPI_TABLE_HEADER *>(dsdt), dsdt_max);
  }

private:
  /**
   * Compute guest-physical address of target table.
   *
   * \param virt_target_addr  Virtual address of the target table.
   *
   * \return 32-bit guest-physical address of the target table.
   */
  UINT32 acpi_phys_addr(l4_addr_t virt_target_addr) const
  {
    return Phys_start_addr + static_cast<UINT32>(virt_target_addr - _dest_addr);
  }

  /**
   * Compute table checksums.
   *
   * \param dest  Table address.
   * \param len   Length of the table.
   *
   * \return  Value so that the sum of all table values modulo 256 is zero.
   */
  static l4_uint8_t compute_checksum(void *dest, unsigned len)
  {
    auto table = reinterpret_cast<l4_uint8_t *>(dest);
    l4_uint8_t sum = 0;
    for (unsigned i = 0; i < len; i++)
      sum += table[i];

    return -sum;
  }

  /**
   * Compute a table's checksum field.
   *
   * \param h  Pointer to the table.
   */
  void compute_checksum(ACPI_TABLE_HEADER *h)
  {
    // In case the checksum is re-computated, the checksum field has to be
    // zeroed before computation.
    cxx::write_now<l4_uint8_t>(&(h->Checksum), 0U);
    h->Checksum = compute_checksum(h, h->Length);
  }

  /**
   * Write an identifier with correct padding.
   *
   * \param dest   Pointer to the memory destination.
   * \param value  String to write.
   * \param len    Length of the identifier field.
   */
  void write_identifier(char *dest, char const *value, size_t len)
  {
    auto value_length = strlen(value);

    assert(value_length <= len && "Supplied identifier fits into field.");

    memcpy(dest, value, value_length);
    memset(dest + value_length, ' ', len - value_length);
  }

  /**
   * Write a common header for ACPI tables as defined in section 5.2.6 of the
   * ACPI Specification.
   *
   * \param h    Destination pointer.
   * \param sig  Signature as described in Table 5-29.
   * \param len  Total length of the table.
   */
  void write_header(ACPI_TABLE_HEADER *h, char const *sig, l4_uint32_t len)
  {
    memcpy(h->Signature, sig, ACPI_NAMESEG_SIZE);
    h->Length = len;
    h->Revision = 0;
    write_identifier(h->OemId, "L4RE", ACPI_OEM_ID_SIZE);
    write_identifier(h->OemTableId, "UVMM", ACPI_OEM_TABLE_ID_SIZE);
    h->OemRevision = 1;
    memcpy(h->AslCompilerId, "UVMM", ACPI_NAMESEG_SIZE);
    h->AslCompilerRevision = 1;
  }

  /**
   * Write a Root System Description Pointer (RSDP).
   *
   * Base ACPI structure as defined in section 5.2.5 of the ACPI Specification.
   * This class includes the ACPI 2.0+ extensions.
   *
   * \param t     Pointer to the destination.
   * \param rsdt  Address of the RSDT.
   */
  void write_rsdp(ACPI_TABLE_RSDP *t, l4_addr_t rsdt_addr)
  {
    memcpy(t->Signature, ACPI_SIG_RSDP, sizeof(t->Signature));
    cxx::write_now<l4_uint8_t>(&(t->Checksum), 0U);
    write_identifier(t->OemId, "L4RE", ACPI_OEM_ID_SIZE);
    t->Revision = 2; // ACPI 2.0+
    t->RsdtPhysicalAddress = acpi_phys_addr(rsdt_addr);
    t->Checksum = compute_checksum(t, Rsdp_v1_size);
    t->Length = Rsdp_size;
    t->XsdtPhysicalAddress = 0; // For now we don't implement the XSDT.
    cxx::write_now<l4_uint8_t>(&(t->ExtendedChecksum), 0U);
    t->ExtendedChecksum = compute_checksum(t, Rsdp_size);
  }

  /**
   * Write a Root System Description Table (RSDT).
   *
   * Table holding pointers to other system description tables as defined in
   * section 5.2.7 of the ACPI Specification.
   *
   * \param t     Pointer to the destination.
   * \param madt  Address of the MADT.
   * \param fadt  Address of the FADT.
   */
  void write_rsdt(ACPI_TABLE_RSDT *t, l4_addr_t madt_addr, l4_addr_t fadt_addr)
  {
    auto header = &(t->Header);
    write_header(header, ACPI_SIG_RSDT, Rsdt_size);

    // The acpi_table_rsdt struct defines only one entry, but we simply use the
    // extra space allocated in the header.
    t->TableOffsetEntry[0] = acpi_phys_addr(madt_addr);
    t->TableOffsetEntry[1] = acpi_phys_addr(fadt_addr);

    compute_checksum(header);
  }

  /**
   * Write a Fixed ACPI Description Table (FADT).
   *
   * Table providing fixed hardware information as defined in section 5.2.8 of
   * the ACPI Specification.
   *
   * \param t     Pointer to the destination.
   * \param dsdt  Address of the DSDT.
   */
  void write_fadt(ACPI_TABLE_FADT *t, l4_addr_t dsdt_addr)
  {
    auto header = &(t->Header);
    write_header(header, ACPI_SIG_FADT, Fadt_size);

    // Emulate ACPI 6.3.
    t->Header.Revision = 6;
    t->MinorRevision = 3;

    // Switching on Hardware-Reduced ACPI has the positive effect of
    // eliminating a lot of legacy features we do not implement.
    // However, with that flag on Linux requires the DSDT to be properly set
    // up for finding PCI devices.
    // t->Flags = (1 << 20); // HW_REDUCED_ACPI

    t->Dsdt = acpi_phys_addr(dsdt_addr);
    t->XDsdt = 0; // For now we don't implement the extended DSDT.

    // How to pick the ID?
    t->HypervisorId = 0;

    std::vector<Acpi_device const*> const &devs = Acpi_device_hub::get()->devices();
    for (auto const &d: devs)
      d->amend_fadt(t);

    compute_checksum(header);
  }

  /**
   * Construct a Multiple APIC Description Table (MADT).
   *
   * The MADT lists Advanced Programmable Interrupt Controllers in the system
   * as defined in section 5.2.12 of the ACPI Specification.
   *
   * \param t     Pointer to the destination.
   * \param cpus  The number of enabled CPUs.
   */
  void write_madt(ACPI_TABLE_MADT *t, unsigned cpus)
  {
    auto madt_size = Madt_basic_size + Ioapic_size + cpus * Lapic_size;
    auto header = &(t->Header);

    write_header(header, ACPI_SIG_MADT, madt_size);

    t->Address = Gic::Lapic_access_handler::Mmio_addr;
    // ACPI 6.3 Specification, Table 5-44:
    // not a PC-AT-compatible dual-8259 setup
    t->Flags = 0;
    // I/O APIC Structure.
    // Provide information about the system's I/O APICs as defined in section
    // 5.2.12.3 of the ACPI Specification.
    auto ioapic = reinterpret_cast<ACPI_MADT_IO_APIC *>(
      reinterpret_cast<l4_addr_t>(t) + Madt_basic_size);
    ioapic->Header.Type = ACPI_MADT_TYPE_IO_APIC;
    ioapic->Header.Length = Ioapic_size;
    ioapic->Id = 0;
    ioapic->Reserved = 0;
    ioapic->Address = Gic::Io_apic::Mmio_addr;
    ioapic->GlobalIrqBase = 0;

    // Processor Local APIC Structure.
    // Structure to be appended to the MADT base table for each local APIC.
    // Defined in section 5.2.12.2 of the ACPI Specification.
    auto lapics = reinterpret_cast<ACPI_MADT_LOCAL_APIC *>(
      reinterpret_cast<l4_addr_t>(t) + Madt_basic_size + Ioapic_size);

    for (unsigned i = 0; i < cpus; ++i)
      {
        lapics[i].Header.Type = ACPI_MADT_TYPE_LOCAL_APIC;
        lapics[i].Header.Length = Lapic_size;
        lapics[i].ProcessorId = i;
        lapics[i].Id = i;
        lapics[i].LapicFlags = 1; // Enable CPU.
      }

    compute_checksum(header);
  }

  /**
   * Write Differentiated System Description Table (DSDT).
   *
   * \param t         Pointer to the destination.
   * \param max_size  Maximum size this table can use.
   *
   * XXX stub implementation, add actual device info.
   * Defined in section 5.2.11.1 of the ACPI Specification.
   */
  void write_dsdt(ACPI_TABLE_HEADER *t, size_t max_size)
  {
    size_t dsdt_size = Header_size;
    void *ptr = reinterpret_cast<void*>(reinterpret_cast<l4_addr_t>(t)
                                        + Header_size);
    std::vector<Acpi_device const*> const &devs = Acpi_device_hub::get()->devices();
    for (auto const &d: devs)
      {
        size_t s = d->amend_dsdt(ptr, max_size - dsdt_size);
        dsdt_size += s;
        ptr = reinterpret_cast<void *>(reinterpret_cast<l4_addr_t>(ptr) + s);
      }
    write_header(t, ACPI_SIG_DSDT, dsdt_size);
    compute_checksum(t);
  }

  l4_addr_t _dest_addr;
  cxx::Ref_ptr<Vmm::Vm_ram> _ram;
};

} // namespace Acpi
