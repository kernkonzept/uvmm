/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020, 2022-2023 Kernkonzept GmbH.
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
#include <array>
#include <vector>

#include "debug.h"
#include "guest.h"
#include "cpu_dev_array.h"
#include "cpu_dev.h"
#include "ioapic.h"
#include "virt_lapic.h"
#include "mem_types.h"

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
 * Registry of devices that need to insert information into ACPI tables.
 *
 * Upon Uvmm startup devices will be created from the device tree. These can
 * register themselves here. The Acpi::Tables class will then call the
 * Acpi_device functions of these devices to fill the ACPI tables. It will
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
 * Devices that must register with ACPI shall implement this interface.
 */
class Acpi_device
{
public:
  explicit Acpi_device()
  {
    Acpi_device_hub::register_device(this);
  }

  virtual void amend_fadt(ACPI_TABLE_FADT *) const {};
  virtual l4_size_t amend_mcfg(ACPI_MCFG_ALLOCATION *, l4_size_t) const { return 0; };
  virtual l4_size_t amend_dsdt(void *, l4_size_t) const { return 0; };
};

/**
 * Singleton for access to the FACS table.
 *
 * Used by ACPI platform to acquire the wakeup vector and zeropage to reserve
 * the FACS location in guest memory in the e820 map.
 */
class Facs_storage
{
public:
  static Facs_storage *get()
  {
    if (!_facs_storage)
      _facs_storage = new Facs_storage();
    return _facs_storage;
  }

  void set_addr(ACPI_TABLE_FACS *table) { _facs = table; }
  void set_gaddr(l4_addr_t gaddr) { _gfacs = Vmm::Guest_addr(gaddr); }
  l4_uint32_t waking_vector() const { return _facs->FirmwareWakingVector; }
  Vmm::Region mem_region() const
  {
    assert(_gfacs.get() != 0);

    return Vmm::Region::ss(_gfacs, sizeof(ACPI_TABLE_FACS),
                           Vmm::Region_type::Ram);
  }

private:
  Facs_storage() = default;
  ~Facs_storage() = default;

  static Facs_storage *_facs_storage;
  ACPI_TABLE_FACS *_facs;
  Vmm::Guest_addr _gfacs;
};

/**
 * ACPI control.
 *
 * Manage the creation of ACPI tables in guest memory.
 */
class Tables
{
public:
  ~Tables()
  {
    Acpi_device_hub::destroy();
  }

protected:
  enum Table_sizes : l4_size_t
  {
    Header_size = sizeof(ACPI_TABLE_HEADER),
    Rsdp_size = sizeof(ACPI_TABLE_RSDP),
    Rsdp_v1_size = sizeof(ACPI_RSDP_COMMON),
    Facs_size = sizeof(ACPI_TABLE_FACS)
  };

  enum class Table : unsigned
  {
    Rsdt,
    Fadt,
    Madt,
    Mcfg,
    Facs,
    Dsdt,
    Num_values,
  };

  /**
   * Helps with generating ACPI structures by providing abstractions for common
   * operations, table references and checksums.
   *
   * Table reference fields and checksum fields are not filled in immediately,
   * but instead a list of fixups is kept for them. Firstly, this simplifies the
   * creation of ACPI structures, since the size and layout of the tables no
   * longer have to be calculated in advance, which is particularly tricky for
   * dynamically-sized tables. Secondly, this allows a more flexible use of the
   * generated ACPI structures, since they can now be relocated to arbitrary
   * memory addresses thanks to the fixups.
   */
  class Writer
  {
  public:
    Writer(l4_addr_t buf_addr, unsigned buf_size)
    : _buf_addr(buf_addr), _buf_size(buf_size), _pos(0)
    {}

    /**
     * Return current write position.
     */
    unsigned pos() const
    { return _pos; }

    /**
     * Return number of unused bytes remaining in the write buffer.
     */
    unsigned remaining_size() const
    { return _buf_size - _pos; }

    /**
     * Register the given ACPI table to start at the current write position, if
     * necessary adjusted to the tables alignment requirements. Then reserve
     * memory for the ACPI table.
     *
     * \tparam T      Type of the table.
     * \param  table  Table
     * \param  len    Length of memory to reserve for the table.
     * \param  align  Alignment required by the table.
     */
    template<typename T>
    T *start_table(Table table, unsigned len = sizeof(T), unsigned align = 8)
    {
      if (_pos % align != 0)
        reserve<void>(align - (_pos % align));

      _tables[static_cast<unsigned>(table)] = _pos;
      return reserve<T>(len);
    }

    /**
     * Reserve memory.
     *
     * \tparam T    Type to reserve memory for.
     * \param  len  Length of the memory to reserve, defaults to size of T.
     */
    template<typename T = void>
    T *reserve(unsigned len = sizeof(T))
    {
      if (_pos + len > _buf_size)
        {
          Err().printf("ACPI table memory allocation exhausted. "
                       "Please configure less ACPI devices "
                       "or raise the ACPI table size limit.\n");
          L4Re::throw_error(-L4_ENOMEM, "ACPI table memory allocation exhausted.");
        }

      T *base = as_ptr<T>(_pos);
      _pos += len;
      return base;
    }

    /**
     * Write an identifier with correct padding.
     *
     * \param dest   Pointer to the memory destination.
     * \param value  String to write.
     * \param len    Length of the identifier field.
     */
    static void write_identifier(char *dest, char const *value, l4_size_t len)
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
     * \param h    Table header.
     * \param sig  Signature as described in Table 5-29.
     * \param rev  Revision of the table.
     * \param len  Total length of the table.
     */
    void write_header(ACPI_TABLE_HEADER *h, char const *sig, l4_uint8_t rev,
                      l4_uint32_t len)
    {
      memcpy(h->Signature, sig, ACPI_NAMESEG_SIZE);
      h->Length = len;
      h->Revision = rev;
      add_checksum(&h->Checksum, h, len);
      write_identifier(h->OemId, "L4RE", ACPI_OEM_ID_SIZE);
      write_identifier(h->OemTableId, "UVMM", ACPI_OEM_TABLE_ID_SIZE);
      h->OemRevision = 1;
      memcpy(h->AslCompilerId, "UVMM", ACPI_NAMESEG_SIZE);
      h->AslCompilerRevision = 1;
    }

    /**
     * Write header for a table and automatically determine size as delta
     * between start position of the table and the current position of the
     * writer.
     *
     * Useful for tables with dynamic size.
     *
     * \param h    Table header, must be at the very beginning of the table.
     * \param sig  Signature as described in Table 5-29.
     * \param rev  Revision of the table.
     */
    void end_table(ACPI_TABLE_HEADER *h, char const *sig, l4_uint8_t rev)
    {
      write_header(h, sig, rev, _pos - as_offset(h));
    }

    /**
     * Reserve an MADT subtable and write its header.
     *
     * \tparam T     Type of the MADT subtable.
     * \param  type  MADT subtable type.
     */
    template<typename T>
    T *reserve_madt_subtable(enum AcpiMadtType type)
    {
      T *subtable = reserve<T>();
      subtable->Header.Type = type;
      subtable->Header.Length = sizeof(T);
      return subtable;
    }

    /**
     * Add fixup for table reference field.
     *
     * \tparam T     Type of the table reference field.
     * \param  ref   Table reference field.
     * \param  table Table that is referenced.
     */
    template<typename T>
    void add_table_ref(T const *ref, Table table)
    {
      _table_refs.emplace_back(Table_ref{as_offset(ref), sizeof(T), table});
    }

    /**
     * Add fixup for checksum field.
     *
     * \param  checksum  Checksum field.
     * \param  base      Pointer to start of memory area to checksum.
     * \param  len       Length of the memory area to checksum.
     */
    void add_checksum(l4_uint8_t *checksum, void *base, unsigned len)
    {
      // Although we do not calculate the checksum here, ensure that the
      // checksum field is zeroed, which is required for checksum computation.
      *checksum = 0U;
      _checksums.emplace_back(Checksum{as_offset(checksum),
                                       as_offset(base), len});
    }

    /**
     * Table reference placeholder.
     */
    struct Table_ref
    {
      /// Offset of table reference field in write buffer.
      unsigned offset;
      /// Size of table reference field.
      unsigned size;
      /// Table that is referenced.
      Table table;
    };

    /**
     * Checksum placeholder.
     */
    struct Checksum
    {
      /// Offset of checksum field in write buffer.
      unsigned field_off;
      /// Offset of the memory area to checksum in write buffer.
      unsigned offset;
      /// Length of the memory area to checksum.
      unsigned len;
    };

    /// Return table reference placeholders.
    std::vector<Table_ref> const &table_refs() const { return _table_refs; }
    /// Return checksum placeholders.
    std::vector<Checksum> const &checksums() const { return _checksums; }

    /**
     * Return start offset of the given table.
     */
    unsigned table_offset(Table table) const
    { return _tables[static_cast<unsigned>(table)]; }

    /**
     * Convert offset into virtual address.
     */
    l4_addr_t as_addr(unsigned offset) const
    {
      assert(offset < _buf_size);
      return _buf_addr + offset;
    }

    /**
     * Convert offset into pointer.
     */
    template<typename T = void>
    T *as_ptr(unsigned offset) const
    { return reinterpret_cast<T *>(as_addr(offset)); }

  private:
    unsigned as_offset(void const *ptr) const
    {
      l4_addr_t addr = reinterpret_cast<l4_addr_t>(ptr);
      assert(addr >= _buf_addr);
      return addr - _buf_addr;
    }

    l4_addr_t _buf_addr;
    unsigned _buf_size;
    unsigned _pos;
    std::array<unsigned, static_cast<unsigned>(Table::Num_values)> _tables;
    std::vector<Table_ref> _table_refs;
    std::vector<Checksum> _checksums;
  }; // class Writer

  /**
   * Write a Root System Description Pointer (RSDP).
   *
   * Base ACPI structure as defined in section 5.2.5 of the ACPI Specification.
   * This class includes the ACPI 2.0+ extensions.
   */
  static void write_rsdp(Writer &wr)
  {
    auto *t = wr.reserve<ACPI_TABLE_RSDP>(Rsdp_size);
    memcpy(t->Signature, ACPI_SIG_RSDP, sizeof(t->Signature));
    wr.add_checksum(&t->Checksum, t, Rsdp_v1_size);
    wr.write_identifier(t->OemId, "L4RE", ACPI_OEM_ID_SIZE);
    t->Revision = 2; // ACPI 2.0+
    wr.add_table_ref(&t->RsdtPhysicalAddress, Table::Rsdt);
    t->Length = Rsdp_size;
    t->XsdtPhysicalAddress = 0; // For now we don't implement the XSDT.
    wr.add_checksum(&t->ExtendedChecksum, t, Rsdp_size);
  }

  /**
   * Writes all implemented ACPI tables.
   */
  static void write_all_tables(Writer &wr, Vdev::Device_lookup *devs)
  {
    write_rsdt(wr);
    write_fadt(wr);
    write_madt(wr, devs->cpus()->max_cpuid() + 1);
    write_mcfg(wr);
    write_facs(wr);
    write_dsdt(wr);
  }

  /**
   * Compute ACPI checksum for memory area.
   *
   * \param dest  Base address of the memory area.
   * \param len   Length of the memory area.
   *
   * \return Value so that the sum of all bytes in the memory area modulo 256
   *         is zero.
   */
  static l4_uint8_t compute_checksum(void *dest, unsigned len)
  {
    l4_uint8_t *bytes = reinterpret_cast<l4_uint8_t *>(dest);
    l4_uint8_t sum = 0;
    for (unsigned i = 0; i < len; i++)
      sum += bytes[i];

    return -sum;
  }

private:
  /**
   * Write a Root System Description Table (RSDT).
   *
   * Table holding pointers to other system description tables as defined in
   * section 5.2.7 of the ACPI Specification.
   */
  static void write_rsdt(Writer &wr)
  {
    // Tables that RSDT refers to.
    static constexpr std::array<Table, 3> ref_tables = {
      Table::Madt,
      Table::Fadt,
      Table::Mcfg,
    };

    // RSDT table header plus a 32-bit word per table pointer.
    auto rsdt_size = Header_size + ref_tables.size() * sizeof(l4_uint32_t);
    auto *t = wr.start_table<ACPI_TABLE_RSDT>(Table::Rsdt, rsdt_size);

    // The acpi_table_rsdt struct defines only one entry, but we simply use the
    // extra space allocated in the header. Do not forget to update
    // Num_table_refs when adding or removing a table reference here.
    for (l4_size_t i = 0; i < ref_tables.size(); i++)
      wr.add_table_ref(&t->TableOffsetEntry[i], ref_tables[i]);

    wr.end_table(&t->Header, ACPI_SIG_RSDT, 1);
  }

  /**
   * Write a Fixed ACPI Description Table (FADT).
   *
   * Table providing fixed hardware information as defined in section 5.2.8 of
   * the ACPI Specification.
   */
  static void write_fadt(Writer &wr)
  {
    auto *t = wr.start_table<ACPI_TABLE_FADT>(Table::Fadt);

    // Switching on Hardware-Reduced ACPI has the positive effect of
    // eliminating a lot of legacy features we do not implement.
    // However, with that flag on Linux requires the DSDT to be properly set
    // up for finding PCI devices.
    // t->Flags = (1 << 20); // HW_REDUCED_ACPI

    wr.add_table_ref(&t->Dsdt, Table::Dsdt);
    t->XDsdt = 0; // For now we don't implement the extended DSDT.
    wr.add_table_ref(&t->Facs, Table::Facs);
    t->XFacs = 0;

    // How to pick the ID?
    t->HypervisorId = 0;

    for (auto const &d : Acpi_device_hub::get()->devices())
      d->amend_fadt(t);

    // Emulate ACPI 6.3.
    wr.end_table(&t->Header, ACPI_SIG_FADT, 6);
    t->MinorRevision = 3;
  }

  /**
   * Construct a Multiple APIC Description Table (MADT).
   *
   * The MADT lists Advanced Programmable Interrupt Controllers in the system
   * as defined in section 5.2.12 of the ACPI Specification.
   *
   * \param cpus  The number of enabled CPUs.
   */
  static void write_madt(Writer &wr, unsigned cpus)
  {
    auto *t = wr.start_table<ACPI_TABLE_MADT>(Table::Madt);

    t->Address = Gic::Lapic_access_handler::Mmio_addr;
    // ACPI 6.3 Specification, Table 5-44:
    // not a PC-AT-compatible dual-8259 setup
    t->Flags = 0;

    // I/O APIC Structure.
    // Provide information about the system's I/O APICs as defined in section
    // 5.2.12.3 of the ACPI Specification.
    auto *ioapic = wr.reserve_madt_subtable<ACPI_MADT_IO_APIC>(
      ACPI_MADT_TYPE_IO_APIC);
    ioapic->Reserved = 0;
    ioapic->Id = 0;
    ioapic->Address = Gic::Io_apic::Mmio_addr;
    ioapic->GlobalIrqBase = 0;

    // Processor Local APIC Structure.
    // Structure to be appended to the MADT base table for each local APIC.
    // Defined in section 5.2.12.2 of the ACPI Specification.
    for (unsigned i = 0; i < cpus; ++i)
      {
        auto *lapic = wr.reserve_madt_subtable<ACPI_MADT_LOCAL_APIC>(
          ACPI_MADT_TYPE_LOCAL_APIC);
        lapic->ProcessorId = i;
        lapic->Id = i;
        lapic->LapicFlags = 1; // Enable CPU.
      }

    // Finally fill the table header.
    wr.end_table(&t->Header, ACPI_SIG_MADT, 5);
  }

  /**
   * Write PCI Express memory mapped configuration space base address
   * Description Table (MCFG).
   */
  static void write_mcfg(Writer &wr)
  {
    auto *t = wr.start_table<ACPI_TABLE_MCFG>(Table::Mcfg);

    for (auto const &d : Acpi_device_hub::get()->devices())
      {
        auto *ptr = wr.as_ptr<ACPI_MCFG_ALLOCATION>(wr.pos());
        auto amend_size = d->amend_mcfg(ptr, wr.remaining_size());
        wr.reserve(amend_size);
      }

    wr.end_table(&t->Header, ACPI_SIG_MCFG, 1);
  }

  /**
   * Write a Firmware ACPI Control Structure (FACS).
   */
  static void write_facs(Writer &wr)
  {
    auto *t = wr.start_table<ACPI_TABLE_FACS>(Table::Facs, Facs_size, 64);
    memcpy(t->Signature, ACPI_SIG_FACS, ACPI_NAMESEG_SIZE);
    t->Length = Facs_size;
    t->Version = 2;
    // other fields written by OSPM or should be zero.
  }

  /**
   * Write Differentiated System Description Table (DSDT).
   */
  static void write_dsdt(Writer &wr)
  {
    auto *t = wr.start_table<ACPI_TABLE_HEADER>(Table::Dsdt);

    for (auto const &d : Acpi_device_hub::get()->devices())
      {
        void *ptr = wr.as_ptr(wr.pos());
        auto amend_size = d->amend_dsdt(ptr, wr.remaining_size());
        wr.reserve(amend_size);
      }

    // The revision of DSDT controls the integer width of AML code/interpreter.
    // Values less than two imply 32-bit integers and math, otherwise 64-bit
    // (see also ComplianceRevision in AML DefinitionBlock)
    wr.end_table(t, ACPI_SIG_DSDT, 1);
  }
};

class Bios_tables : public Tables
{
  enum : l4_uint32_t
  {
    /**
     * Physical location of the RSDP according to section 5.2.5.1 of the ACPI
     * Specification.
     */
    Phys_start_addr = 0x0E0000
  };

public:
  /**
   * ACPI control structure.
   *
   * \param ram  Guest RAM.
   */
  Bios_tables(Vdev::Device_lookup *devs)
  : _devs(devs)
  {
    info.printf("Initialize legacy BIOS ACPI tables.\n");
    _dest_addr = _devs->ram()->guest2host<l4_addr_t>(Vmm::Guest_addr(Phys_start_addr));
  }

  /**
   * Calculate positions for each table and write them in place.
   */
  void write_to_guest()
  {
    // we allow the rsdp and all tables to take up one page
    l4_size_t max_size = L4_PAGESIZE;

    auto acpi_mem = Vmm::Region::ss(Vmm::Guest_addr(Phys_start_addr), max_size,
                                    Vmm::Region_type::Ram);
    // Throws an exception if the ACPI memory region isn't within guest RAM.
    _devs->ram()->guest2host<l4_addr_t>(acpi_mem);

    // Clear memory because we do not rely on the DS provider to do this for
    // us, and we must not have spurious values in ACPI tables.
    memset(reinterpret_cast<void *>(_dest_addr), 0, max_size);

    Writer wr(_dest_addr, max_size);
    write_rsdp(wr);
    write_all_tables(wr, _devs);
    resolve_table_refs_and_checksums(wr);

    l4_addr_t facs_off = wr.table_offset(Tables::Table::Facs);
    Facs_storage::get()->set_addr(wr.as_ptr<ACPI_TABLE_FACS>(facs_off));
    Facs_storage::get()->set_gaddr(acpi_phys_addr(wr.as_addr(facs_off)));
  }

private:
  void resolve_table_refs_and_checksums(Writer &wr)
  {
    for (Writer::Table_ref const &ref : wr.table_refs())
      {
        l4_addr_t table_addr = wr.as_addr(wr.table_offset(ref.table));
        if (ref.size == sizeof(l4_uint32_t))
          *wr.as_ptr<l4_uint32_t>(ref.offset) = acpi_phys_addr(table_addr);
        else
          L4Re::throw_error(-L4_EINVAL, "Unsupported table offset size.");
      }

    for (Writer::Checksum const &checksum : wr.checksums())
      {
        l4_uint8_t *field = wr.as_ptr<l4_uint8_t>(checksum.field_off);
        // Calculate and write checksum.
        *field = compute_checksum(wr.as_ptr(checksum.offset), checksum.len);
      }
  }

  /**
   * Compute guest-physical address of target table.
   *
   * \param virt_target_addr  Virtual address of the target table.
   *
   * \return 32-bit guest-physical address of the target table.
   */
  l4_uint32_t acpi_phys_addr(l4_addr_t virt_target_addr) const
  {
    return Phys_start_addr + static_cast<l4_uint32_t>(virt_target_addr - _dest_addr);
  }

  Vdev::Device_lookup *_devs;
  l4_addr_t _dest_addr;
};


} // namespace Acpi
