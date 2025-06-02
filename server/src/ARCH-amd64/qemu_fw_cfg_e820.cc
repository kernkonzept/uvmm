/*
 * Copyright (C) 2025 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "device/qemu_fw_cfg.h"
#include "e820_map.h"
#include "acpi.h"

namespace {

class Qemu_fw_cfg_e820: public Qemu_fw_cfg::Provider
{
  static char const constexpr *E820_file_name = "etc/e820";
  cxx::unique_ptr<E820_entry[]> _e820;

public:
  void init_late(Vdev::Device_lookup *devs) override
  {
    Vmm::Vm_ram *ram = devs->ram().get();
    unsigned num_regions = ram->num_regions();

    auto size = num_regions * sizeof(E820_entry);
    _e820 = cxx::make_unique<E820_entry[]>(size);

    unsigned index = 0;
    ram->foreach_region([this, &index](Vmm::Ram_ds const &r)
    {
      // Firmware needs to know RAM regions only
      if (!r.writable())
        return;
      _e820[index].addr = r.vm_start().get();
      _e820[index].size = r.size();
      _e820[index].type = E820_ram;
      index++;
    });

    Qemu_fw_cfg::put_file(E820_file_name,
                          reinterpret_cast<char const *>(_e820.get()),
                          index * sizeof(E820_entry));
  }
};

static Qemu_fw_cfg_e820 f;

}; // namespace
