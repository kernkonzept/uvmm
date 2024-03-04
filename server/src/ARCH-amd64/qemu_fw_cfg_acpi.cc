/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020-2023 Kernkonzept GmbH.
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

  static_assert(sizeof(Qemu_loader_entry) == 128,
                "Invalid size of Qemu_loader_entry");

public:
  static char const constexpr *Rsdp_file_name = "etc/acpi/rsdp";
  static char const constexpr *Tables_file_name = "etc/acpi/tables";
  static char const constexpr *Loader_commands_file_name = "etc/table-loader";
  static char const constexpr *System_states_file_name = "etc/system-states";

  Acpi_tables(Vdev::Device_lookup *devs)
  : _system_states_file(6)
  {
    info.printf("Initialize Qemu IF ACPI tables.\n");
    _tables.resize(Tables_reservation);
    _loader_cmds.reserve(Loader_commands_reservation);

    cmd_add_alloc(Tables_file_name, 64 /* FACS requirement */, false);
    Writer table_wr(reinterpret_cast<l4_addr_t>(_tables.data()), _tables.size());
    write_all_tables(table_wr, devs);
    _tables.resize(table_wr.pos());
    resolve_table_refs_and_checksums(Tables_file_name, table_wr, table_wr);

    cmd_add_alloc(Rsdp_file_name, 16, true /* EBDA area */);
    _rsdp.resize(Rsdp_size);
    Writer rdsp_wr(reinterpret_cast<l4_addr_t>(_rsdp.data()), _rsdp.size());
    write_rsdp(rdsp_wr);
    resolve_table_refs_and_checksums(Rsdp_file_name, rdsp_wr, table_wr);

    // This is a qemu <-> EFI Interface. It is "documented" in
    // edk2/Ovmf/Library/QemuFwCfgS3Lib/QemuFwCfgS3PeiDxe.c
    // QemuFwCfgS3Enabled()
    // We only implement the bit needed for EFI to signal S3 support.
    _system_states_file[3] = (1 << 7); // S3 supported
  }

  std::vector<char> const &rsdp() const
  { return _rsdp; };
  std::vector<char> const &tables() const
  { return _tables; }
  std::string const & loader_cmds() const
  { return _loader_cmds; }
  std::vector<char> const &system_states_file() const
  { return _system_states_file; }

private:
  void resolve_table_refs_and_checksums(char const *fn, Writer &wr,
                                        Writer &table_wr)
  {
    for (Writer::Table_ref const &ref : wr.table_refs())
      {
        if (ref.size == 4)
          *wr.as_ptr<l4_uint32_t>(ref.offset) = table_wr.table_offset(ref.table);
        else
          L4Re::throw_error(-L4_EINVAL, "Unsupported table offset size.");
        cmd_add_pointer(fn, ref.offset, ref.size, Tables_file_name);
      }

    for (Writer::Checksum const &checksum : wr.checksums())
      cmd_add_checksum(fn, checksum.offset, checksum.len, checksum.field_off);
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
   * Add the pointer value to `src_fn` in the file `dst_fn` at offset
   * `dst_off`. The patched pointer size is `dst_size`.
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
  std::vector<char> _system_states_file;
  std::string _loader_cmds;
};

struct Qemu_fw_cfg_tables : public Qemu_fw_cfg::Provider
{
  void init_late(Vdev::Device_lookup *devs) override
  {
    Acpi_tables tables(devs);
    Qemu_fw_cfg::put_file(Acpi_tables::Rsdp_file_name, tables.rsdp());
    Qemu_fw_cfg::put_file(Acpi_tables::Tables_file_name, tables.tables());
    Qemu_fw_cfg::put_file(Acpi_tables::Loader_commands_file_name, tables.loader_cmds());
    Qemu_fw_cfg::put_file(Acpi_tables::System_states_file_name,
                          tables.system_states_file());
  }
};

static Qemu_fw_cfg_tables f;

}; // namespace
