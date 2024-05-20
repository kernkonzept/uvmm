/*
 * Copyright (C) 2023-2024 genua GmbH, 85551 Kirchheim, Germany
 * All rights reserved. Alle Rechte vorbehalten.
 */
/*
 * Copyright (C) 2025 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "openbsd_bootparams.h"
#include "acpi.h"

namespace Vmm::Openbsd {

void Boot_params::dump()
{
  info().printf("OpenBSD Boot Parameters: =============================== \n");
  info().printf("  howto: 0x%x\n", _params.howto);
  info().printf("  apiversion: 0x%x\n", _params.apiversion);
  info().printf("  ac: %d\n", _params.ac);
  info().printf("  av: 0x%x\n", _params.av);
  info().printf("  bootdev: 0x%x\n", _params.bootdev);
  info().printf("  end: 0x%x\n", _params.end);
}

void Boot_params::add_to_memmap(Bios_memmap **map, size_t const num,
                                l4_uint32_t type, l4_uint64_t addr,
                                l4_uint64_t size)
{
  assert(num > 0); // we expect to allocate something and not free everything

  *map = static_cast<Bios_memmap *>(realloc(*map, num * sizeof(Bios_memmap)));
  if (*map == nullptr)
    L4Re::throw_error(-L4_ENOMEM, "Failed to setup memmap!");

  // Fill allocated map entry
  Bios_memmap &entry = (*map)[num - 1];
  entry.addr = static_cast<l4_uint64_t>(addr);
  entry.size = size;
  entry.type = type;

  std::string typestr;
  switch (type)
    {
    case Bios_map_free: typestr = "Adding free";     break;
    case Bios_map_res:  typestr = "Adding reserved"; break;
    case Bios_map_acpi: typestr = "Adding ACPI";     break;
    case Bios_map_nvs:  typestr = "Adding ACPI NVS"; break;
    default:            typestr = "Adding unknown";  break;
    }

  trace().printf("%s memory to map: addr=0x%llx size=0x%llx\n", typestr.c_str(),
                 addr, size);
}

void Boot_params::setup_memmap(Vm_ram *ram)
{
  Bios_memmap *bios_memmap = nullptr;
  size_t num = 0;

  // Loop over all regions and add them to guest RAM
  ram->foreach_region([&bios_memmap, &num, this](Vmm::Ram_ds const &r) mutable {
    if (r.writable())
      {
        if (r.vm_start().get() < Iom_end
            && (r.vm_start().get() + r.size()) > Iom_end)
          {
            // Split conventional and extended memory
            add_to_memmap(&bios_memmap, ++num, Bios_map_free,
                          r.vm_start().get(), Iom_end - r.vm_start().get());
            add_to_memmap(&bios_memmap, ++num, Bios_map_free, Iom_end,
                          r.size() - Iom_end + r.vm_start().get());
          }
        else
          {
            add_to_memmap(&bios_memmap, ++num, Bios_map_free,
                          r.vm_start().get(), r.size());
          }
      }
    else
      {
        add_to_memmap(&bios_memmap, ++num, Bios_map_res, r.vm_start().get(),
                      r.size());
      }
  });

  auto facs = Acpi::Facs_storage::get()->mem_region();
  add_to_memmap(&bios_memmap, ++num, Bios_map_acpi, facs.start.get(),
                facs.end - facs.start + 1);

  add_to_memmap(&bios_memmap, ++num, Bios_map_end, 0, 0);

  if (bios_memmap != nullptr)
    {
      info().printf("Add BIOS memmap at %p.\n", bios_memmap);
      add_bootarg(Bootarg_memmap, num * sizeof(Bios_memmap), bios_memmap);
      free(bios_memmap);
    }
}

void Boot_params::write(Vm_ram *ram)
{
  // Prepare BIOS ram regions
  setup_memmap(ram);

  // Add default uart console
  Bios_consdev cons;
  cons.consdev = makedev_obsd(8, 0); // com0
  cons.conspeed = 115200;
  cons.consaddr = 0x3f8;
  add_bootarg(Bootarg_consdev, sizeof(cons), &cons);

  // Finalize and write boot arguments to guest memory
  add_bootarg(Bootarg_end, 0, nullptr);
  Vmm::Guest_addr bootargs_pos = Vmm::Guest_addr(Phys_mem_addr * 9);
  memset(ram->guest2host<void *>(bootargs_pos), 0, _bootargs_size);
  memcpy(ram->guest2host<void *>(bootargs_pos), _bootargs, _bootargs_size);
  _params.av = bootargs_pos.get();
  _params.ac = _bootargs_size;

  // Write entry stack
  memset(ram->guest2host<void *>(_gp_addr), 0, Phys_mem_addr);
  memcpy(ram->guest2host<void *>(_gp_addr), &_params,
         sizeof(Openbsd_entry_stack));

  dump();
}

void Boot_params::add_bootarg(int type, size_t length, void const *data)
{
  // Prepare header
  Boot_args next;
  next.ba_type = type;
  next.ba_size = sizeof(next) - sizeof(next.ba_arg) + length;

  // Extend memory allocation
  size_t newsize = _bootargs_size + next.ba_size;
  if (newsize > L4_PAGESIZE)
      L4Re::throw_error(-L4_EINVAL, "OpenBSD bootargs: Too many arguments!");

  _bootargs = realloc(_bootargs, newsize);
  if (_bootargs == nullptr)
    L4Re::throw_error(-L4_ENOMEM, "Failed to add bootarg!");

  auto ptr_byte_add = [](void *ptr, l4_uint8_t param) {
      return static_cast<void *>(static_cast<l4_uint8_t *>(ptr) + param);
  };
  // Paste header and content to memory
  memcpy(ptr_byte_add(_bootargs, _bootargs_size), &next,
         sizeof(next) - sizeof(next.ba_arg));
  _bootargs_size = newsize;

  if (data)
    memcpy(ptr_byte_add(_bootargs, _bootargs_size - length), data, length);
}

} // namespace Vmm::Openbsd
