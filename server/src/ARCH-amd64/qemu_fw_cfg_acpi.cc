/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020-2022 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *            Jan Klötzke <jan.kloetzke@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 */

#include "acpi.h"
#include "device/qemu_fw_cfg.h"

namespace {

using namespace Acpi;

/**
 * Provide tables via the Qemu_fw_cfg to the guest firmware.
 *
 * The details of the interface are documented in the Qemu sources in
 * hw/acpi/bios-linker-loader.c. It is actively used by firmwares such as
 * Tianocore, so it can be considered stable.
 *
 * Because the final address of the tables is not known here, a more flexible
 * interface is used. The guest firmware is instructed by the
 * "etc/table-loader" commands file how to install the tables correctly. It
 * holds the commands to allocate space for the tables, patch the pointers
 * between the different tables and how to compute the checksums.
 */
class Acpi_tables : public Tables
{
  enum
  {
    Dsdt_max_size = 4096,
    Tables_reservation = 8192,
    Loader_commands_reservation = 512,
  };

  enum
  {
    // Commands
    Qemu_loader_allocate = 1,
    Qemu_loader_add_pointer = 2,
    Qemu_loader_add_checksum = 3,

    Qemu_loader_zone_high = 1,
    Qemu_loader_zone_fseg = 2,

    Qemu_loader_file_name_size = Qemu_fw_cfg::File_name_size,
  };

  struct Qemu_loader_entry
  {
    l4_uint32_t type;
    union
    {
      struct Allocate
      {
        char file_name[Qemu_loader_file_name_size];
        l4_uint32_t alignment;
        l4_uint8_t zone;
      } allocate;
      struct Add_pointer
      {
        char dst_file_name[Qemu_loader_file_name_size];
        char src_file_name[Qemu_loader_file_name_size];
        l4_uint32_t dst_pointer_offset;
        l4_uint8_t dst_pointer_size;
      } add_pointer;
      struct Add_checksum
      {
        char file_name[Qemu_loader_file_name_size];
        l4_uint32_t checksum_offset;
        l4_uint32_t start;
        l4_uint32_t size;
      } add_checksum;

      l4_uint8_t pad[124];
    } cmd;
  };

  static_assert(sizeof(Qemu_loader_entry) == 128);

public:
  static char const constexpr *Rsdp_file_name = "etc/acpi/rsdp";
  static char const constexpr *Tables_file_name = "etc/acpi/tables";
  static char const constexpr *Loader_commands_file_name = "etc/table-loader";

  Acpi_tables(unsigned cpus)
  {
    info.printf("Initialize Qemu IF ACPI tables.\n");
    _tables.reserve(Tables_reservation);
    _loader_cmds.reserve(Loader_commands_reservation);

    cmd_add_alloc(Tables_file_name, 64 /* FACS requirement */, false);
    l4_size_t dsdt = write_dsdt();
    l4_size_t facs = write_facs();
    l4_size_t fadt = write_fadt(dsdt, facs);
    l4_size_t madt = write_madt(cpus);
    l4_size_t rsdt = write_rsdt(madt, fadt);

    cmd_add_alloc(Rsdp_file_name, 16, true /* EBDA area */);
    write_rsdp(rsdt);
  }

  std::vector<char> const &rsdp() const
  { return _rsdp; };
  std::vector<char> const &tables() const
  { return _tables; }
  std::string const & loader_cmds() const
  { return _loader_cmds; }

private:
  l4_size_t write_dsdt()
  {
    align(8);
    l4_size_t start = _tables.size();
    _tables.resize(start + Dsdt_max_size);
    l4_size_t len =
      Tables::write_dsdt(reinterpret_cast<ACPI_TABLE_HEADER *>(&_tables[start]),
                         Dsdt_max_size);
    l4_size_t end = start + len;
    _tables.resize(end);

    cmd_add_header_checksum(start);
    return start;
  }

  l4_size_t write_facs()
  {
    align(8);
    l4_size_t start = _tables.size();
    _tables.resize(start + Facs_size);
    Tables::write_facs(reinterpret_cast<ACPI_TABLE_FACS *>(&_tables[start]));

    return start;
  }

  l4_size_t write_fadt(l4_size_t dsdt, l4_size_t facs)
  {
    align(8);
    l4_size_t start = _tables.size();
    _tables.resize(start + Fadt_size);
    auto fadt = reinterpret_cast<ACPI_TABLE_FADT *>(&_tables[start]);
    Tables::write_fadt(fadt, dsdt, facs);

    cmd_add_pointer(Tables_file_name, start + offsetof(ACPI_TABLE_FADT, Dsdt),
                    sizeof(fadt->Dsdt), Tables_file_name);
    cmd_add_header_checksum(start);

    return start;
  }

  l4_size_t write_madt(unsigned cpus)
  {
    align(8);
    l4_size_t start = _tables.size();
    _tables.resize(start + madt_size(cpus));
    Tables::write_madt(reinterpret_cast<ACPI_TABLE_MADT *>(&_tables[start]),
                       cpus);
    cmd_add_header_checksum(start);
    return start;
  }

  l4_size_t write_rsdt(l4_size_t madt, l4_size_t fadt)
  {
    align(8);
    l4_size_t start = _tables.size();
    _tables.resize(start + Rsdt_size);
    auto rsdt = reinterpret_cast<ACPI_TABLE_RSDT *>(&_tables[start]);
    Tables::write_rsdt(rsdt, madt, fadt);

    cmd_add_pointer(Tables_file_name,
                    start + offsetof(ACPI_TABLE_RSDT, TableOffsetEntry[0]),
                    sizeof(rsdt->TableOffsetEntry[0]), Tables_file_name);
    cmd_add_pointer(Tables_file_name,
                    start + offsetof(ACPI_TABLE_RSDT, TableOffsetEntry[1]),
                    sizeof(rsdt->TableOffsetEntry[1]), Tables_file_name);
    cmd_add_header_checksum(start);

    return start;
  }

  void write_rsdp(l4_size_t rsdt)
  {
    align(8);
    _rsdp.resize(Rsdp_size);
    auto rsdp = reinterpret_cast<ACPI_TABLE_RSDP *>(&_rsdp[0]);
    Tables::write_rsdp(rsdp, rsdt);

    cmd_add_pointer(Rsdp_file_name,
                    offsetof(ACPI_TABLE_RSDP, RsdtPhysicalAddress),
                    sizeof(rsdp->RsdtPhysicalAddress), Tables_file_name);
    cmd_add_checksum(Rsdp_file_name, 0, Rsdp_v1_size,
                     offsetof(ACPI_TABLE_RSDP, Checksum));
    cmd_add_checksum(Rsdp_file_name, 0, Rsdp_size,
                     offsetof(ACPI_TABLE_RSDP, ExtendedChecksum));
  }

  void align(l4_size_t alignment)
  {
    while (_tables.size() & (alignment - 1U))
      _tables.push_back(0);
  }

  void cmd_add_header_checksum(l4_size_t start)
  {
    auto h = reinterpret_cast<ACPI_TABLE_HEADER *>(&_tables[start]);
    cmd_add_checksum(Tables_file_name, start, h->Length,
                     start + offsetof(ACPI_TABLE_HEADER, Checksum));
  }

  void cmd_add_checksum(char const *fn, l4_size_t start, l4_size_t size,
                        l4_size_t checksum)
  {
    Qemu_loader_entry e;
    std::memset(&e, 0, sizeof(e));

    e.type = Qemu_loader_add_checksum;
    std::strncpy(e.cmd.add_checksum.file_name, fn,
                 sizeof(e.cmd.add_checksum.file_name) - 1U);
    e.cmd.add_checksum.checksum_offset = checksum;
    e.cmd.add_checksum.start = start;
    e.cmd.add_checksum.size = size;

    _loader_cmds.append((char*)&e, sizeof(e));
  }

  /**
   * Add the pointer value to \a src_fn in the file \a dst_fn at offset
   * dst_off. The patched pointer size is dst_size.
   */
  void cmd_add_pointer(char const *dst_fn, l4_size_t dst_off, l4_size_t dst_size,
                       char const *src_fn)
  {
    Qemu_loader_entry e;
    std::memset(&e, 0, sizeof(e));

    e.type = Qemu_loader_add_pointer;
    std::strncpy(e.cmd.add_pointer.dst_file_name, dst_fn,
                 sizeof(e.cmd.add_pointer.dst_file_name) - 1U);
    std::strncpy(e.cmd.add_pointer.src_file_name, src_fn,
                 sizeof(e.cmd.add_pointer.src_file_name) - 1U);
    e.cmd.add_pointer.dst_pointer_offset = dst_off;
    e.cmd.add_pointer.dst_pointer_size = dst_size;

    _loader_cmds.append((char*)&e, sizeof(e));
  }

  void cmd_add_alloc(char const *fn, l4_size_t align, bool fseg_zone)
  {
    Qemu_loader_entry e;
    std::memset(&e, 0, sizeof(e));

    e.type = Qemu_loader_allocate;
    std::strncpy(e.cmd.allocate.file_name, fn,
                 sizeof(e.cmd.allocate.file_name) - 1U);
    e.cmd.allocate.alignment = align;
    e.cmd.allocate.zone = fseg_zone ? Qemu_loader_zone_fseg
                                    : Qemu_loader_zone_high;

    _loader_cmds.append((char*)&e, sizeof(e));
  }

  std::vector<char> _rsdp;
  std::vector<char> _tables;
  std::string _loader_cmds;
};

struct Qemu_fw_cfg_tables : public Qemu_fw_cfg::Provider
{
  void init_late(Vdev::Device_lookup *devs) override
  {
    Acpi_tables tables(devs->cpus()->max_cpuid() + 1);

    Qemu_fw_cfg::put_file(Acpi_tables::Rsdp_file_name, tables.rsdp());
    Qemu_fw_cfg::put_file(Acpi_tables::Tables_file_name, tables.tables());
    Qemu_fw_cfg::put_file(Acpi_tables::Loader_commands_file_name, tables.loader_cmds());
  }
};

static Qemu_fw_cfg_tables f;

}; // namespace
