/*
 * Copyright (C) 2018-2019 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <vector>
#include <make_unique-l4>

#include <l4/cxx/bitfield>
#include <l4/cxx/bitmap>
#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>

#include "msi.h"
#include "msi_controller.h"
#include "virt_bus.h"
#include "mem_access.h"
#include "debug.h"
#include "io_device.h"
#include "pci_device.h"
#include "pci_virtio_config.h"

namespace Vdev { namespace Pci {

struct Devfn_address
{
  l4_uint32_t value;
  enum
  {
    Dev_shift = 16,
    Mask = 0xffff,
    Io_dev_shift = 0x3,
    Io_dev_mask = 0xf8,
    Io_fn_mask = 0x7,
  };

  Devfn_address(l4_uint32_t dev, l4_uint32_t func)
  { value = ((dev & Mask) << Dev_shift) | (func & Mask); }

  l4_uint16_t fn() const { return value & Mask; }
  l4_uint16_t dev() const { return (value >> Dev_shift) & Mask; }

  /**
   * Generate a devfn number which is compatible with the io expected format.
   *
   * io expects a devfn number in the lower eight bits of the srcid.
   * See io/server/src/acpi/acpi.cc. (X86 only!)
   *
   * \note Not compatible with ARM source IDs.
   */
  l4_uint16_t io_compatible_msi_srcid_devfn() const
  {
    return static_cast<l4_uint16_t>(
             ((dev() << Io_dev_shift) & Io_dev_mask)
             | (fn() & Io_fn_mask));
  }
};

struct Pci_cfg_bar
{
  enum Type
  {
    Unused,
    MMIO32,
    MMIO64,
    IO
  };

  l4_uint64_t addr;
  l4_size_t size;
  Type type;

  // for user: get address type dependent
  // auto addr =
  //  (type == MMIO64) ? addr : (l4_uint32_t)(addr && 0xffffffff);
};

struct Hw_pci_device
{
  Hw_pci_device(Devfn_address df) : devfn(df), has_msix(false)
  { memset(bars, 0, sizeof(bars)); }

  Devfn_address devfn;
  Pci_cfg_bar bars[Pci_config_consts::Bar_num_max_type0];
  Pci_msix_cap msix_cap;
  bool has_msix;
};

/**
 * PCI bus emulation.
 *
 * The emulated host bridge handles the PCI bus transaction initialized by the
 * guest OS. Linux detects the virtual host bridge and queries the root bus for
 * devices present.
 * If hardware devices are supplied via Vbus, the virtio devices are merged
 * into Vbus' PCI root bus.
 */
class Pci_bus_bridge : public Pci_dev, public Device
{
  Pci_header::Type1 *header()
  { return get_header<Pci_header::Type1>(); }

public:
  explicit Pci_bus_bridge(cxx::Ref_ptr<Vmm::Virt_bus> vbus)
  : _io_pci_bridge_present(false)
  {
    if (vbus.get() && vbus->available())
      {
        trace().printf("VBus found, searching for PCI devices\n");
        int err = vbus->bus()->root().device_by_hid(&_io_hb, "PNP0A03");
        if (err < 0)
          info().printf("No PCI bus found on VBus\n");
        else
          {
            iterate_pci_root_bus();
            _io_pci_bridge_present = true;
          }
      }

    if (!_io_pci_bridge_present)
      info().printf("No IO provided PCI host bridge found\n");

    _devfns.init();

    auto *hdr = header();
    // Linux' x86 PCI_direct code sanity checks for class code of first device,
    // either PCI_CLASS_DISPLAY_VGA(0x0300) or PCI_CLASS_BRIDGE_HOST(0x00)
    // device should be there. --> First device is BRIDGE_HOST device
    // see linux/arch/x86/pci/direct.c
    hdr->classcode[2] = Pci_class_code_bridge_device;
    hdr->classcode[1] = Pci_subclass_code_host;
    hdr->command = Bus_master_bit | Io_space_bit;
  }

  void init_bus_range(Dt_node const &node);
  void init_dev_resources(Device_lookup *devs,
                          cxx::Ref_ptr<Gic::Msix_controller> msix_ctrl);

  bool is_io_pci_host_bridge_present() const { return _io_pci_bridge_present; }

  /**
   * Register a UVMM emulated device with the PCI bus.
   *
   * In case the PCI bus is full, an exception is thrown.
   */
  void register_device(cxx::Ref_ptr<Pci_device> const &dev)
  {
    info().printf("register PCI device\n");
    _devfns.add_device(dev);
  }

  /// Internal interface to read from PCI devices.
  void cfg_space_read(Devfn_address devfn, unsigned reg, unsigned /* offset */,
                      Vmm::Mem_access::Width width, l4_uint32_t *value)
  {
    trace().printf("dev_read: devfn 0x%x\n", devfn.value);
    auto dev = _devfns.get_device(devfn);
    if (dev)
      dev->cfg_read(reg, value, width);
    else
      {
        if (!_io_pci_bridge_present)
          {
            *value = ~0U;
            return;
          }

        if (_io_hb.cfg_read(0, devfn.value, reg, value, 8 << width))
          {
            info().printf("Error while reading HW device 0x%x register 0x%x\n",
                          devfn.value, reg);
            *value = ~0U;
          }
      }
  }

  /// Internal interface to write to PCI devices.
  void cfg_space_write(Devfn_address devfn, unsigned reg, unsigned /* offset */,
                       Vmm::Mem_access::Width width, l4_uint32_t value)
  {
    auto dev = _devfns.get_device(devfn);
    if (dev)
      dev->cfg_write(reg, value, width);
    else
      {
        if (!_io_pci_bridge_present)
          return;

        if (_io_hb.cfg_write(0, devfn.value, reg, value, 8 << width))
          info().printf(
            "Error while writing 0x%x to HW device 0x%x register 0x%x\n", value,
            devfn.value, reg);
      }
  }

private:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI bus"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI bus"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI bus"); }

  enum
  {
    Max_num_dev_functions = 8,
    Max_bus_devs = 32,
    Max_devfn = Max_num_dev_functions * Max_bus_devs,
  };

  // return true if there is a device, false if not
  bool parse_pci_device_function(unsigned devnr, unsigned function)
  {
    l4_uint32_t val;
    Devfn_address devfn(devnr, function);

    int err =
      _io_hb.cfg_read(0, devfn.value, Pci_hdr_vendor_id_offset, &val, 16);
    if (err)
      return false;

    if (val == Pci_invalid_vendor_id)
      return false;

    _hwpci_devs.emplace_back(devfn);
    Hw_pci_device *hwdev = &_hwpci_devs.back();
    parse_all_pci_bars(hwdev);

    unsigned msix_cap_addr = get_capability(devfn.value, Cap_ident::Msi_x);

    if (msix_cap_addr != 0)
      {
        parse_msix_cap(devfn.value, msix_cap_addr, &hwdev->msix_cap);

        hwdev->has_msix = true;

        dbg().printf("DevFn 0x%x has an MSIX cap at 0x%x\n", devfn.value,
                     msix_cap_addr);
      }
    else
      dbg().printf("Did not find an MSI-X capability for %x\n", devfn.value);
    return true;
  }

  void iterate_pci_root_bus()
  {
    dbg().printf("Parsing io PCI config space\n");

    for (unsigned devnr = 0; devnr < Max_bus_devs; ++devnr)
      {
        if (!parse_pci_device_function(devnr, 0))
          continue;

        _devfns.alloc_used_dev_num(devnr);

        Devfn_address devfn(devnr, 0);
        l4_uint32_t type;
        int err =
          _io_hb.cfg_read(0, devfn.value, Pci_hdr_type_offset, &type, 8);
        if (err)
          continue;
        if (type & Multi_func_bit)
          {
            dbg().printf("Multifunction device found. Parsing functions.\n");

            for (unsigned fn = 1; fn < Max_num_dev_functions; ++fn)
              parse_pci_device_function(devnr, fn);
          }
      }
  }

  void parse_msix_cap(unsigned devfn, unsigned msix_cap_addr, Pci_msix_cap *cap)
  {
    l4_uint32_t ctrl = 0;
    L4Re::chksys(_io_hb.cfg_read(0, devfn, msix_cap_addr + 2,
                                 &ctrl, 16),
                 "Read HW PCI device MSI-X cap ctrl.");
    cap->ctrl.raw = (l4_uint16_t)ctrl;
    L4Re::chksys(_io_hb.cfg_read(0, devfn, msix_cap_addr + 4,
                                 &cap->tbl.raw, 32),
                 "Read HW PCI device MSI-X cap table.");
    L4Re::chksys(_io_hb.cfg_read(0, devfn, msix_cap_addr + 8,
                                 &cap->pba.raw, 32),
                 "Read HW PCI device MSI-X cap pba.");
  }

  void parse_all_pci_bars(Hw_pci_device *hwdev)
  {
    unsigned index = 0;
    while (index < 6)
      index = parse_pci_bar(hwdev->devfn.value, index, &hwdev->bars[index]);
  }

  /*
   * Read raw values of the address and size of a PCI BAR
   *
   * \param      devfn    PCI device function
   * \param      index    PCI BAR index. Valid are 0-5
   * \param[out] bar_addr The base address of the PCI bar
   * \param[out] bar_size The size of the memory area as read from the BAR
   *
   * \pre IO and MMIO decoding has been disabled for this device.
   *
   * \note This function is not thread safe.
   */
  void read_bar_raw(l4_uint32_t devfn, unsigned index, l4_uint32_t *bar_addr,
                    l4_uint32_t *bar_size)
  {
    assert(index <= 5);

    // Reading the size of a PCI BAR:
    // 1. Read original value
    // 2. Write -1
    // 3. Read value
    // 4. Write original value
    l4_uint32_t bar_offset = Pci_hdr_base_addr0_offset + index * 4;
    L4Re::chksys(_io_hb.cfg_read(0, devfn, bar_offset, bar_addr, 32),
                 "Read BAR register of PCI device header (org value).");
    L4Re::chksys(_io_hb.cfg_write(0, devfn, bar_offset, 0xffffffffUL, 32),
                 "Write BAR register of PCI device header (sizing).");
    L4Re::chksys(_io_hb.cfg_read(0, devfn, bar_offset, bar_size, 32),
                 "Read BAR register of PCI device header (size).");
    L4Re::chksys(_io_hb.cfg_write(0, devfn, bar_offset, *bar_addr, 32),
                 "Write BAR register of PCI device header (write back).");
  }

  /*
   * Parse a PCI BAR. Returns the index of the next PCI BAR.
   *
   * \param      devfn    PCI device function
   * \param      index    The index of the PCI BAR. Valid are 0-5
   * \param[out] bar_cfg  Parsed information about the PCI BAR
   * \retval              Index of the next PCI BAR
   *
   * \pre  bar_cfg needs to be initialized to zero.
   * \note This function is not thread safe.
   * \note This function does not check if the returned index is valid.
   */
  unsigned parse_pci_bar(l4_uint32_t devfn, unsigned index, Pci_cfg_bar *bar_cfg)
  {
    // disable decode in command register
    l4_uint32_t cmd_reg = 0;
    L4Re::chksys(_io_hb.cfg_read(0, devfn, Pci_hdr_command_offset, &cmd_reg,
                                 16),
                 "Read Command register of PCI device header.");

    // disable MMIO and IO accesses
    L4Re::chksys(_io_hb.cfg_write(0, devfn, Pci_hdr_command_offset,
                                  cmd_reg & ~0x3, 16),
                 "Write Command register of PCI device header (disable "
                 "decode).");

    l4_uint32_t bar_orig, bar_orig_high;
    l4_uint32_t bar_size_low, bar_size_high;

    read_bar_raw(devfn, index, &bar_orig, &bar_size_low);

    bool is_64 = (bar_orig & 0x6) == 0x4;
    if (is_64)
      {
        ++index;
        if (index > 5)
          L4Re::throw_error(-L4_EINVAL, "Interpret PCI BAR 6 as 64-bit BAR.");
        read_bar_raw(devfn, index, &bar_orig_high, &bar_size_high);
      }

    // Reenable bar decode
    L4Re::chksys(_io_hb.cfg_write(0, devfn, Pci_hdr_command_offset, cmd_reg,
                                  16),
                 "Write Command register of PCI device header (enable "
                 "decode).");

    // size calculation according to PCI Spec Version 3, Chapter 6.2.5.1.

    // 1. mask decoding information
    // 2. invert
    // 3. increment
    l4_uint64_t bar_size = 0;
    if (bar_orig & 1) // IO bar
      {
        bar_size_low &= ~1;
        bar_size_low  = ~bar_size_low;
        bar_size_low += 1;
        bar_size_low &= 0xff; // ignore upper 16 bit
        bar_size = static_cast<l4_uint64_t>(bar_size_low);
      }
    else if ((bar_orig & 0x6) == 0) // MMIO32
      {
        bar_size_low &= ~0xf;
        bar_size_low  = ~bar_size_low;
        bar_size_low += 1;
        bar_size = static_cast<l4_uint64_t>(bar_size_low);
      }
    else if (is_64) // MMIO64
      {
        bar_size |= static_cast<l4_uint64_t>(bar_size_high) << 32;
        bar_size |= static_cast<l4_uint64_t>(bar_size_low);
        bar_size &= ~0xf;
        bar_size = ~bar_size;
        bar_size += 1;
      }
    bar_cfg->size = bar_size;

    // bar not used, advance to next one
    if (!bar_size)
      return index + 1;

    if (bar_orig & 1) // IO
      {
        bar_cfg->addr = bar_orig & ~0x3;
        bar_cfg->type = Pci_cfg_bar::IO;
        info().printf("PCI IO BAR, size = %lx, addr = %llx\n",
                      bar_cfg->size, bar_cfg->addr);
      }
    else if ((bar_orig & 0x6) == 0) // MMIO32
      {
        bar_cfg->addr = bar_orig & ~0xf;
        bar_cfg->type = Pci_cfg_bar::MMIO32;
        info().printf("PCI MMIO32 BAR, size = %lx, addr = %llx\n",
                      bar_cfg->size, bar_cfg->addr);
      }
    else if (is_64) // MMIO64
      {
        bar_cfg->addr = bar_orig & ~0xf;
        bar_cfg->addr |= static_cast<l4_uint64_t>(bar_orig_high) << 32;
        bar_cfg->type = Pci_cfg_bar::MMIO64;
        info().printf("PCI MMIO64 BAR, size = %lx, addr = %llx\n",
                      bar_cfg->size, bar_cfg->addr);
      }

    return index + 1;
  }

  //
  // *** PCI cap ************************************************************
  //

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
  unsigned get_capability(unsigned devfn, l4_uint8_t cap_type) const
  {
    unsigned val = 0;
    if (_io_hb.cfg_read(0, devfn, Pci_hdr_status_offset, &val, 16))
      {
        dbg().printf("Failed to read Pci_hdr_status_offset.\n");
        return 0;
      }

    if (!(val & Pci_header_status_capability_bit))
      {
        dbg().printf("Pci_hdr_status_capability_bit is not set.\n");
        return 0;
      }

    if (_io_hb.cfg_read(0, devfn, Pci_hdr_capability_offset, &val, 8))
      {
        dbg().printf("Failed to read Pci_hdr_status_offset.\n");
        return 0;
      }

    l4_uint8_t next_cap = val & Pci_cap_mask::Next_cap;

    if (next_cap == 0)
      {
        dbg().printf("get_capability: Capability pointer is zero.\n");
        return 0;
      }

    while (!_io_hb.cfg_read(0, devfn, next_cap, &val, 16))
      {
        l4_uint8_t cap_id = val & Pci_cap_mask::Cap_id;
        dbg().printf("get_capability: found cap id 0x%x (cap addr 0x%x)\n",
                     cap_id, next_cap);

        if (cap_id == cap_type)
          return next_cap;

        next_cap = (val >> 8) & Pci_cap_mask::Next_cap;
        if (!next_cap) // next pointer is zero -> end of list
          break;
      }

    dbg().printf("get_capability: Did not find capability of type 0x%x "
                 "(devfn=0x%x)\n", cap_type, devfn);

    return 0;
  }

  /**
   * Manage virtual device-function number assignment on the PCI bus.
   *
   * The class can handle only virtual devices or work in conjunction with a
   * PCI bus provided on the VBUS.
   *
   * Assumptions:
   * * Initialization takes place before the first access.
   * * Device numbers used by Vbus's PCI bus are not added, e.g. no virtual
   *   devices are placed as function under physical device number.
   */
  class Devfn_list
  {
    // unused device numbers on HW PCI root bus
    cxx::Bitmap<Max_bus_devs> _free_dev_numbers;
    // offset to global view
    unsigned _init_dev;
    // hint for local index computation
    unsigned _next_dev;
    // hint for local index computation
    unsigned _next_fn;
    // Design decision: I trade fast indexing into the vector for higher
    // memory consumption. Alternatively, I could use a map.
    std::vector<cxx::Ref_ptr<Pci_device>> _functions;

    // This function assumes the returned index will be used. Internal data
    // structures are updated before it returns.
    unsigned alloc_next_index(bool is_multifunc_dev)
    {
      // _next_fn == 0 -> the next device is free to use as multifunc device.
      if (!is_multifunc_dev && _next_fn > 0)
        {
          _next_dev = alloc_next_dev();
          _next_fn = 0;
        }

      trace()
        .printf("Devfn_list: alloc_next_index: _next_dev 0x%x, _next_fn 0x%x\n",
                _next_dev, _next_fn);

      if (_next_dev >= Max_bus_devs)
        L4Re::chksys(-L4_ENOMEM,
                     "Acquire free PCI device number on the PCI bus.");

      unsigned next_idx = index(_next_dev, _next_fn);
      _next_fn += 1;

      if (!is_multifunc_dev || (_next_fn >= Max_num_dev_functions))
        {
          _next_dev = alloc_next_dev();
          _next_fn = 0;
        }

      return next_idx;
    }

    unsigned alloc_next_dev()
    {
      int next_free = _free_dev_numbers.scan_zero(_init_dev);
      if (-1 == next_free)
        L4Re::chksys(-L4_ENOMEM, "Acquire free PCI device number on "
                                 "the PCI bus.");

      _free_dev_numbers.set_bit(next_free);
      return next_free;
    }

    // assumes Devfn_list local values
    static unsigned index(unsigned dev, unsigned fn)
    {
      return dev * 8 + fn;
    }

  public:
    Devfn_list() : _init_dev(Max_bus_devs), _next_dev(-1), _next_fn(0)
    {
      _free_dev_numbers.clear_all();
    }

    void init()
    {
      int init_dev = _free_dev_numbers.scan_zero();
      if (-1 == init_dev)
        init_dev = Max_bus_devs;

      _init_dev = init_dev;
      _next_dev = _init_dev;

      _free_dev_numbers.set_bit(_next_dev);
      _functions.resize((Max_bus_devs - _init_dev) * 8);
    }

    void alloc_used_dev_num(unsigned dev)
    {
      _free_dev_numbers.set_bit(dev);
      trace().printf("Devfn_list: add used device number %u\n", dev);
    }

    void add_device(cxx::Ref_ptr<Pci_device> const &dev)
    {
      bool is_multifn = dev->is_multi_function_device();
      unsigned idx = alloc_next_index(is_multifn);

      _functions[idx] = dev;
      info().printf("Devfn_list add: Pci device under idx 0x%x\n", idx);
    }

    cxx::Ref_ptr<Pci_device> get_device(Devfn_address devfn) const
    {
      l4_uint16_t dev = devfn.dev();
      l4_uint16_t fn = devfn.fn();

      if (   (dev >= Max_bus_devs)
          || (fn >= Max_num_dev_functions)
          || (dev < _init_dev))
        return nullptr;

      // shift global value to local value
      dev -= _init_dev;

      return _functions[index(dev, fn)];
    }
  };

  bool _io_pci_bridge_present;
  /// pointer to IO's PCI host bridge
  L4vbus::Pci_host_bridge _io_hb;
  /// storage of HW PCI devices
  std::vector<Hw_pci_device> _hwpci_devs;
  /// Manages virtual devices and devfn numbers.
  Devfn_list _devfns;
}; // class Pci_bus_bridge


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
  cxx::Ref_ptr<Pci_bus_bridge> _bus;

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
  Pci_bus_cfg_io(cxx::Ref_ptr<Pci_bus_bridge> const &pci_bus) : _bus(pci_bus) {}

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
          _bus->cfg_space_write(Devfn_address(_cfg_addr.dev(), _cfg_addr.func()),
                                reg, 0, width, value);
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
          _bus->cfg_space_read(Devfn_address(_cfg_addr.dev().get(),
                                             _cfg_addr.func().get()),
                               reg, 0, width, value);
          trace().printf("IN access @0x%x/%d --> 0x%x\n", port, width, *value);
          return;
        }
      }
    trace().printf("Unhandled IN access @0x%x/%d\n", port, width);
  }
}; // Pci_bus_cfg_io

} } // namespace Vdev::Pci
