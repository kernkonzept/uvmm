/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020-2022 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *            Jan Klötzke <jan.kloetzke@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 */

#include "cpu_dev_array.h"
#include "guest.h"
#include "device/qemu_fw_cfg.h"

#include <l4/cxx/unique_ptr>
#include <l4/re/util/env_ns>

namespace {

/**
 * Device to forward boot data over the qemu fw configuration interface.
 *
 * The qemu_fw_cfg node must have l4vmm,kernel, l4vmm,ramdisk and l4vmm,cmdline
 * as additional properties. Their value can be an empty string.
 *
 *      qemu_fw_if {
 *        compatible = "l4vmm,qemu-fw-cfg";
 *        reg = <0x1 0x510 0x0c>;
 *        l4vmm,kernel = "linux";
 *        l4vmm,ramdisk = "ramdisk";
 *        l4vmm,cmdline = "console=TTY0";
 *      };
 */
class Qemu_fw_cfg_boot : public Qemu_fw_cfg::Provider
{
  enum Fw_cfg_item_selectors
  {
    // Item selectors defined by Qemu
    Fw_cfg_cpu_count          = 0x05,
    Fw_cfg_kernel_size        = 0x08,
    Fw_cfg_initrd_size        = 0x0b,
    Fw_cfg_boot_menu          = 0x0e,
    Fw_cfg_kernel_data        = 0x11,
    Fw_cfg_commandline_size   = 0x14,
    Fw_cfg_commandline_data   = 0x15,
    Fw_cfg_kernel_setup_size  = 0x17,
    Fw_cfg_kernel_setup_data  = 0x18,
    Fw_cfg_initrd_data        = 0x12,

    // Added by KK
    Fw_cfg_uvmm_dt            = 0xe0,
  };

  void init(Vdev::Device_lookup * /*devs*/, Vdev::Dt_node const &node) override
  {
    _kernel = node.get_prop<char>("l4vmm,kernel", nullptr);
    _ramdisk = node.get_prop<char>("l4vmm,ramdisk", nullptr);
    _cmdline = node.get_prop<char>("l4vmm,cmdline", nullptr);
  };

  void init_late(Vdev::Device_lookup *devs) override
  {
    if (!_kernel.empty())
      {
        _kernel_binary = cxx::make_unique<Boot::Binary_ds>(_kernel.c_str());

        if (!_kernel_binary->is_valid())
          L4Re::throw_error(-L4_EINVAL, "Kernel dataspace not found.");

        if (_kernel_binary->is_elf_binary())
          L4Re::throw_error(-L4_EINVAL, "Elf files not supported for qemu fw.");

        l4_uint8_t num_setup_sects =
          *((char *)_kernel_binary->get_header() + Vmm::Bp_setup_sects);

        add_kernel(_kernel_binary->ds(), (num_setup_sects + 1) * 512);
      }

    if (!_ramdisk.empty())
      {
        _ramdisk_ds = L4Re::Util::Unique_cap<L4Re::Dataspace>(
          L4Re::chkcap(L4Re::Util::Env_ns().query<L4Re::Dataspace>(
                         _ramdisk.c_str()),
                       "Ramdisk dataspace not found"));
        add_initrd(_ramdisk_ds.get());
      }

    if (!_cmdline.empty())
        add_cmdline(_cmdline.c_str());

    add_dt_addr(devs->vmm()->dt_addr());

    add_cpu_count(devs->cpus()->max_cpuid() + 1);
  };

  void add_cmdline(char const *cmdline)
  {
    size_t len = strlen(cmdline) + 1U;
    Qemu_fw_cfg::set_item_u32le(Fw_cfg_commandline_size, len);
    Qemu_fw_cfg::set_item(Fw_cfg_commandline_data, cmdline, len);
  }

  void add_kernel(L4::Cap<L4Re::Dataspace> kernel, l4_size_t setup_size)
  {
    size_t image_size = kernel->size();
    Qemu_fw_cfg::set_item_u32le(Fw_cfg_kernel_setup_size, setup_size);
    Qemu_fw_cfg::set_item(Fw_cfg_kernel_setup_data, kernel, 0, setup_size);
    Qemu_fw_cfg::set_item_u32le(Fw_cfg_kernel_size, image_size - setup_size);
    Qemu_fw_cfg::set_item(Fw_cfg_kernel_data, kernel, setup_size);
  }

  void add_initrd(L4::Cap<L4Re::Dataspace> initrd)
  {
    Qemu_fw_cfg::set_item_u32le(Fw_cfg_initrd_size, initrd->size());
    Qemu_fw_cfg::set_item(Fw_cfg_initrd_data, initrd);
  }

  void add_dt_addr(l4_addr_t addr)
  {
    l4_uint64_t addr_le = htole64(addr);
    Qemu_fw_cfg::set_item(Fw_cfg_uvmm_dt, &addr_le, sizeof(addr_le));
  }

  void add_cpu_count(l4_uint16_t num)
  {
    Qemu_fw_cfg::set_item_u16le(Fw_cfg_cpu_count, num);
  }

  std::string _kernel;
  cxx::unique_ptr<Boot::Binary_ds> _kernel_binary;
  std::string _ramdisk;
  L4Re::Util::Unique_cap<L4Re::Dataspace> _ramdisk_ds;
  std::string _cmdline;
};

static Qemu_fw_cfg_boot f;

}; // namespace
