/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020-2022 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *            Jan Klötzke <jan.kloetzke@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * See docs/specs/fw_cfg.txt in Qemu sources for reference.
 */

#include <endian.h>
#include <l4/re/error_helper>
#include <l4/re/util/env_ns>
#include <l4/re/util/unique_cap>
#include <l4/sys/compiler.h>
#include <map>
#include <memory>
#include <string>

#include "debug.h"
#include "device.h"
#include "device_factory.h"
#include "guest.h"
#include "io_device.h"
#include "mem_access.h"
#include "mmio_device.h"
#include "qemu_fw_cfg.h"

namespace {

/**
 * Qemu firmware configuration device.
 *
 * The device allows guests to gain access to the hv's configuration or any
 * kind of data like boot/kernel images in a defined way. Some bootloaders make
 * use of this to setup the platform and start the guest OS.
 *
 * To enable it use a device tree entry like this:
 * io:
 *
 *      qemu_fw_cfg {
 *        compatible = "l4vmm,qemu-fw-cfg";
 *        reg = <0x1 0x510 0x0c>;
 *      };
 *
 * mmio:
 *      qemu_fw_cfg {
 *        compatible = "qemu,fw-cfg-mmio";
 *        reg = <0x0 0xf10000 0x0 0x10>;
 *      };
 *
 * The code here only implements the device serving the fw cfg data. The data
 * provider itself are implemented in separate entities. See
 * qemu_fw_cfg_boot.cc for example.
 */

static Dbg warn(Dbg::Dev, Dbg::Warn, "qemu_fw_cfg");
static Dbg info(Dbg::Dev, Dbg::Info, "qemu_fw_cfg");
static Dbg trace(Dbg::Dev, Dbg::Trace, "qemu_fw_cfg");

enum Fw_cfg_item_selectors
{
  // Item selectors defined by Qemu
  Fw_cfg_signature     = 0x00,
  Fw_cfg_if_version    = 0x01,
  Fw_cfg_uuid          = 0x02,
  Fw_cfg_file_dir      = 0x19,

  // dynamically added entries found through Fw_cfg_file_dir start here
  Fw_cfg_dynamic_start = 0x20,
};

enum
{
  Fw_cfg_version_traditional   = 1,
  Fw_cfg_version_dma_supported = 2,

  Fw_cfg_reg_selector_mmio     = 0x08,
  Fw_cfg_reg_data_mmio         = 0x00,
  Fw_cfg_reg_dma_addr_mmio     = 0x10,

  Fw_cfg_reg_selector_io       = 0x00,
  Fw_cfg_reg_data_io           = 0x01,
  Fw_cfg_reg_dma_addr_io       = 0x04,

  Fw_cfg_dma_control_error     = 0x01,
  Fw_cfg_dma_control_read      = 0x02,
  Fw_cfg_dma_control_skip      = 0x04,
  Fw_cfg_dma_control_select    = 0x08,
  Fw_cfg_dma_control_write     = 0x10,
};

class Fw_item
{
public:
  virtual ~Fw_item() = default;

  virtual char const *data() const = 0;
  virtual size_t size() const = 0;
};

class Fw_item_ds : public Fw_item
{
  l4_size_t _size;
  l4_addr_t _offset;
  L4Re::Rm::Unique_region<char *> _ds_region;

public:
  Fw_item_ds(L4::Cap<L4Re::Dataspace> ds, size_t offset = 0, size_t size = -1)
  {
    auto ds_size = ds->size();
    if (offset > ds_size)
      offset = ds_size;
    if (ds_size - offset < size)
      size = ds_size - offset;

    l4_addr_t pg_offset = l4_trunc_page(offset);
    l4_addr_t in_pg_offset = offset - pg_offset;
    size_t pg_size = l4_round_page(size + in_pg_offset);

    _size = size;
    _offset = in_pg_offset;
    auto *e = L4Re::Env::env();
    L4Re::chksys(e->rm()->attach(&_ds_region, pg_size,
                                 L4Re::Rm::F::Search_addr | L4Re::Rm::F::RWX,
                                 L4::Ipc::make_cap_rw(ds), pg_offset),
                 "Could not attach Fw_item_ds");
  }

  char const *data() const override
  { return _ds_region.get() + _offset; }

  size_t size() const override
  { return _size; }
};

class Fw_item_blob : public Fw_item
{
  std::string _blob;

public:
  Fw_item_blob() = default;
  Fw_item_blob(std::string const &blob) : _blob(blob) {}
  Fw_item_blob(std::string &&blob) : _blob(std::move(blob)) {}

  char const *data() const override
  { return _blob.data(); }

  size_t size() const override
  { return _blob.size(); }
};

class Fw_item_directory : public Fw_item
{
  struct Entry
  {
    l4_uint32_t size;    // big endian
    l4_uint16_t select;  // selector key for fw_cfg item, big endian
    l4_uint16_t reserved;
    char name[Qemu_fw_cfg::File_name_size]; // NUL-terminated ascii
  };

  std::string _dir;
  l4_uint16_t _num_files = 0;

public:
  Fw_item_directory() : _dir(4, '\0') {}

  l4_uint16_t add_file(char const *filename, l4_uint32_t size)
  {
    l4_uint16_t selector = Fw_cfg_dynamic_start + _num_files++;

    // append directory entry
    Entry e;
    e.size = htobe32(size);
    e.select = htobe16(selector);
    std::strncpy(e.name, filename, sizeof(e.name) - 1U);
    _dir.append(reinterpret_cast<char*>(&e), sizeof(e));

    // update header (files count)
    l4_uint32_t num_files = htobe32(_num_files);
    std::memcpy(&_dir[0], &num_files, sizeof(num_files));

    return selector;
  }

  char const *data() const override
  { return _dir.data(); }

  size_t size() const override
  { return _dir.size(); }
};

class Item_directory
{
public:
  Item_directory()
  {
    _directory = new Fw_item_directory();
    _blobs.emplace(Fw_cfg_file_dir, std::unique_ptr<Fw_item>(_directory));
  }

  void set_item(l4_uint16_t selector, void const *data, size_t length)
  {
    std::string blob((char const *)data, length);
    _blobs[selector].reset(new Fw_item_blob(std::move(blob)));
  }

  void set_item(l4_uint16_t selector, std::string const &blob)
  {
    _blobs[selector].reset(new Fw_item_blob(blob));
  }

  void set_item(l4_uint16_t selector, L4::Cap<L4Re::Dataspace> ds,
                size_t offset = 0, size_t size = -1)
  {
    _blobs[selector].reset(new Fw_item_ds(ds, offset, size));
  }

  void set_item_u16le(l4_uint16_t selector, l4_uint16_t data)
  {
    data = htole16(data);
    set_item(selector, &data, sizeof(data));
  }

  void set_item_u32le(l4_uint16_t selector, l4_uint32_t data)
  {
    data = htole32(data);
    set_item(selector, &data, sizeof(data));
  }

  void add_file(char const *filename, std::string &&blob)
  {
    l4_uint16_t selector = _directory->add_file(filename, blob.size());
    _blobs.emplace(selector,
                   std::unique_ptr<Fw_item>(new Fw_item_blob(std::move(blob))));
  }

  bool exists(l4_uint16_t selector)
  {
    return _blobs.count(selector) != 0;
  }

  Fw_item const *get_item(l4_uint16_t selector)
  {
    return _blobs[selector].get();
  }

private:
  std::map<l4_uint16_t, std::unique_ptr<Fw_item>> _blobs;
  Fw_item_directory *_directory;
};

class Qemu_fw_if : public Vdev::Device
{
  struct FWCfgDmaAccess
  {
    // everything is given in big endian!
    l4_uint32_t control;
    l4_uint32_t length;
    l4_uint64_t address;
  };

public:
  static Qemu_fw_if *get()
  {
    return _if;
  }

  Qemu_fw_if(Vdev::Device_lookup *devs, Vdev::Dt_node const &node)
  : _devs(devs), _ram(devs->ram())
  {
    if (_if)
      L4Re::throw_error(-L4_EEXIST, "Only one Qemu_fw_if allowed");
    _if = this;

    _items.set_item(Fw_cfg_signature, "QEMU");
    _items.set_item_u32le(Fw_cfg_if_version, Fw_cfg_version_traditional |
                                             Fw_cfg_version_dma_supported);

    for (auto *t: Qemu_fw_cfg::Provider::types)
      t->init(_devs, node);
  }

  void init_late()
  {
    if (_devs)
      {
        for (auto *t: Qemu_fw_cfg::Provider::types)
          t->init_late(_devs);
        _devs = nullptr;
      }
  }

  ~Qemu_fw_if()
  {
    _if = nullptr;
  }

  void set_item(l4_uint16_t selector, void const *data, size_t length)
  { _items.set_item(selector, data, length); }

  void set_item(l4_uint16_t selector, std::string const &blob)
  { _items.set_item(selector, blob); }

  void set_item(l4_uint16_t selector, L4::Cap<L4Re::Dataspace> ds,
                size_t offset = 0, size_t size = -1)
  { _items.set_item(selector, ds, offset, size); }

  void put_file(char const *fn, char const *blob, size_t size)
  {
    std::string b(blob, size);
    _items.add_file(fn, std::move(b));
  }

protected:
  Vdev::Device_lookup *_devs;
  cxx::Ref_ptr<Vmm::Vm_ram> _ram;
  int _selector = Fw_cfg_signature;
  l4_size_t _offset = 0;
  l4_uint64_t _dma_addr = 0; // big-endian!
  Item_directory _items;

  void handle_dma_access()
  {
    l4_addr_t dma_addr = be64toh(_dma_addr);
    volatile struct FWCfgDmaAccess *dma
      = _ram
      ->guest2host<volatile struct FWCfgDmaAccess*>(Vmm::Guest_addr(dma_addr));
    _dma_addr = 0;

    l4_uint32_t control = be32toh(dma->control);
    l4_uint32_t length  = be32toh(dma->length);
    l4_addr_t   address = be64toh(dma->address);

    l4_addr_t target_address =
      _ram->guest2host<l4_addr_t>(Vmm::Guest_addr(address));

    trace.printf("DMA Transfer Control @ 0x%lx: %x, Length: %d, Address: 0x%lx\n",
                 dma_addr, control, length, address);

    if (control & Fw_cfg_dma_control_select)
      {
        _selector = control >> 16;
        _offset = 0;
      }
    else if (control & Fw_cfg_dma_control_write)
      {
        warn.printf("DMA command: writes not supported\n");
        dma->control = htobe32(Fw_cfg_dma_control_error);
      }
    else // read/skip
      {
        Fw_item const *item = nullptr;
        if (_items.exists(_selector))
          {
            item = _items.get_item(_selector);
            l4_size_t size = item->size();
            if (size - _offset < length)
              length = size - _offset;
          }
        else
          warn.printf("DMA transfer: unknown selector: 0x%x\n", _selector);

        if (control & Fw_cfg_dma_control_read)
          {
            if (item)
              memcpy(reinterpret_cast<void *>(target_address),
                     item->data() + _offset, length);
            else
              memset(reinterpret_cast<void *>(target_address), 0, length);
          }

        _offset += length;
        dma->control = 0;
      }
  }

  l4_umword_t handle_pio_access(char size)
  {
    if (!_items.exists(_selector))
      {
        warn.printf("PIO transfer: unsupported selector: 0x%x\n", _selector);
        return 0;
      }

    auto const *item = _items.get_item(_selector);
    l4_size_t read_size = 1U << size;
    l4_size_t item_size = item->size();
    if (item_size - _offset < read_size)
      read_size = item_size - _offset;

    // Use bounce buffer because of potentially unaligned and/or truncated
    // access. Out-of-bounds reads return 0.
    union {
      l4_uint8_t u8;
      l4_uint16_t u16;
      l4_uint32_t u32;
      l4_uint64_t u64;
    } buf;
    memset(&buf, 0, sizeof(buf));
    memcpy(&buf, item->data() + _offset, read_size);
    _offset += read_size;

    switch (size)
      {
        case 0: return buf.u8;
        case 1: return buf.u16;
        case 2: return buf.u32;
        case 3: return buf.u64;
        default: assert(false); break;
      }

    return 0; // not reached
  }

private:
  static Qemu_fw_if *_if; /// singleton instance
};

Qemu_fw_if *Qemu_fw_if::_if;

class Qemu_fw_if_mmio
: public Qemu_fw_if,
  public Vmm::Mmio_device_t<Qemu_fw_if_mmio>
{
public:
  Qemu_fw_if_mmio(Vdev::Device_lookup *devs, Vdev::Dt_node const &node)
  : Qemu_fw_if(devs, node)
  {}

  l4_umword_t read(unsigned reg, char size, unsigned /* cpu_id */)
  {
    trace.printf("read reg=%x size=%d\n", reg, size);

    init_late();

    l4_uint32_t value = 0;
    switch (reg)
      {
      case Fw_cfg_reg_selector_mmio:
        value = htobe16(_selector);
        break;
      case Fw_cfg_reg_data_mmio:
        value = handle_pio_access(size);
        break;
      case Fw_cfg_reg_dma_addr_mmio:
        value =
          Vmm::Mem_access::read_width(reinterpret_cast<l4_addr_t>("QEMU CFG"),
                                      size);
        break;
      default:
        warn.printf("Unknown register: %u\n", reg);
        break;
      }

    return value;
  }

  void write(unsigned reg, char size, l4_umword_t value, unsigned /* cpu_id */)
  {
    trace.printf("write reg=%x size=%d value=0x%lx\n", reg, size, value);

    init_late();

    switch (reg)
      {
      case Fw_cfg_reg_selector_mmio:
        _selector = be16toh(value);
        _offset = 0;
        break;
      case Fw_cfg_reg_dma_addr_mmio:
        Vmm::Mem_access::write_width(reinterpret_cast<l4_addr_t>(&_dma_addr),
                                     value, size);
        if (size >= 3)
          handle_dma_access();
        break;
      case Fw_cfg_reg_dma_addr_mmio + 4:
        Vmm::Mem_access::write_width(reinterpret_cast<l4_addr_t>(&_dma_addr) + 4U,
                                     value, size);
        handle_dma_access();
        break;
      case Fw_cfg_reg_data_mmio:
        // writes not supported
        break;
      default:
        warn.printf("Unknown register: %u\n", reg);
        break;
      }
  }

  char const *dev_name() const override { return "Qemu_fw_if_mmio"; }
};

class Qemu_fw_if_io
: public Qemu_fw_if,
  public Vmm::Io_device
{
public:
  Qemu_fw_if_io(Vdev::Device_lookup *devs, Vdev::Dt_node const &node)
  : Qemu_fw_if(devs, node)
  {}

  char const *dev_name() const override
  { return "Firmware interface"; }

  /* IO write from the guest to device */
  void io_out(unsigned port, Vmm::Mem_access::Width width, l4_uint32_t value) override
  {
    trace.printf("OUT port=%d width=%d value=0x%x\n", port, width, value);

    init_late();

    switch (port)
      {
      case Fw_cfg_reg_selector_io:

        _selector = value;
        _offset = 0;
        break;
      case Fw_cfg_reg_dma_addr_io:
        Vmm::Mem_access::write_width(reinterpret_cast<l4_addr_t>(&_dma_addr),
                                     value, width);
        break;
      case Fw_cfg_reg_dma_addr_io + 4:
        Vmm::Mem_access::write_width(reinterpret_cast<l4_addr_t>(&_dma_addr) + 4U,
                                     value, width);
        handle_dma_access();
        break;
      case Fw_cfg_reg_data_io:
        // writes not supported
        break;
      default:
        warn.printf("Unknown port: %u\n", port);
      }
  }

  /* IO read from the guest */
  void io_in(unsigned port, Vmm::Mem_access::Width width, l4_uint32_t *value) override
  {
    trace.printf("IN port=%d width=%d\n", port, width);

    init_late();

    switch (port)
      {
      case Fw_cfg_reg_selector_io:
        *value = _selector;
        break;
      case Fw_cfg_reg_data_io:
        *value = handle_pio_access(width);
        break;
      default:
        warn.printf("Unknown port: %u\n", port);
        *value= -1U;
      }
  }
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    cxx::Ref_ptr<Vdev::Device> ret;

    if (Vmm::Guest::Has_io_space)
      {
        auto dev = cxx::Ref_ptr<Qemu_fw_if_io>(new Qemu_fw_if_io(devs, node));
        devs->vmm()->register_io_device(dev, Vmm::Region_type::Virtual, node);
        ret = dev;
      }
    else
      {
        auto dev = cxx::Ref_ptr<Qemu_fw_if_mmio>(new Qemu_fw_if_mmio(devs, node));
        devs->vmm()->register_mmio_device(dev, Vmm::Region_type::Virtual, node);
        ret = dev;
      }

    return ret;
  }
};

static F f;
static Vdev::Device_type t = { Vmm::Guest::Has_io_space ? "l4vmm,qemu-fw-cfg"
                                                        : "qemu,fw-cfg-mmio",
                               nullptr, &f};
} // namespace

// Public interface
cxx::H_list_t<Qemu_fw_cfg::Provider> Qemu_fw_cfg::Provider::types(true);

void
Qemu_fw_cfg::set_item(l4_uint16_t selector, std::string const &blob)
{
  if (auto *d = Qemu_fw_if::get())
    d->set_item(selector, blob);
}

void
Qemu_fw_cfg::set_item(l4_uint16_t selector, L4::Cap<L4Re::Dataspace> ds,
                  size_t offset, size_t size)
{
  if (auto *d = Qemu_fw_if::get())
    d->set_item(selector, ds, offset, size);
}

void
Qemu_fw_cfg::set_item(l4_uint16_t selector, void const *data, size_t length)
{ set_item(selector, std::string((char const *)data, length)); }

void
Qemu_fw_cfg::set_item_u16le(l4_uint16_t selector, l4_uint16_t data)
{
  data = htole16(data);
  set_item(selector, &data, sizeof(data));
}

void
Qemu_fw_cfg::set_item_u32le(l4_uint16_t selector, l4_uint32_t data)
{
  data = htole32(data);
  set_item(selector, &data, sizeof(data));
}

void
Qemu_fw_cfg::put_file(char const *fn, char const *blob, size_t size)
{
  if (auto *d = Qemu_fw_if::get())
    d->put_file(fn, blob, size);
  else
    warn.printf("Warning: Did not add '%s' because the Qemu_fw_if device does "
                "not exist yet. Please ensure the device node of Qemu_fw_if "
                "comes before the device serving '%s' in the device tree.\n",
                fn, fn);
}
