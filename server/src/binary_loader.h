/*
 * Copyright (C) 2015-2020, 2022, 2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <l4/sys/cache.h>
#include <l4/re/dataspace>
#include <l4/re/util/unique_cap>
#include <l4/re/util/env_ns>
#include <l4/re/error_helper>
#include <l4/libloader/elf>
#include <l4/cxx/hlist>

#include <memory>

#include "debug.h"
#include "vm_ram.h"

namespace Boot {

class Binary_ds
{
  static L4Re::Rm::Unique_region<char *> attach_ds(L4::Cap<L4Re::Dataspace> ds)
  {
    if (!ds.is_valid())
      return {};

    // Map the whole dataspace. Use superpage alignment to lower TLB pressure
    // when mapping large images, like the Linux kernel.
    auto *e = L4Re::Env::env();
    L4Re::Rm::Unique_region<char *> ret;
    L4Re::chksys(e->rm()->attach(&ret, ds->size(),
                                 L4Re::Rm::F::Search_addr | L4Re::Rm::F::R,
                                 L4::Ipc::make_cap_rw(ds), 0,
                                 L4_SUPERPAGESHIFT),
                 "Attach binary dataspace.");

    return ret;
  }

public:
  Binary_ds(char const *name)
  : _ds(L4Re::Util::Env_ns().query<L4Re::Dataspace>(name)),
    _data(attach_ds(_ds.get())),
    _elf(this, _ds.get())
  {}

  Binary_ds(L4::Cap<L4Re::Dataspace> d)
  : _ds(d),
    _data(attach_ds(d)),
    _elf(this, _ds.get())
  {}

  Ldr::Elf_binary<Binary_ds> *get_elf()
  { return &_elf; }

  bool is_valid()
  { return _ds.is_valid(); }

  bool is_elf_binary()
  {
    return _elf.is_valid();
  }

  bool is_elf64()
  {
    return _elf.is_64();
  }

  size_t loaded_size()
  { return _loaded_range_end - _loaded_range_start; }

  l4_addr_t load_as_elf(Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list)
  {
    Vmm::Guest_addr img_start(-1UL);
    Vmm::Guest_addr img_end(0);

    _elf.iterate_phdr([this,ram,free_list,&img_start,&img_end](Ldr::Elf_phdr ph) {
      if (ph.type() == PT_LOAD)
        {
          auto gstart = ram->boot2guest_phys(ph.paddr());
          // Note that we need to reserve all the memory, this block will
          // occupy in memory, even though only filesz() will be copied
          // later.
          if (!free_list->reserve_fixed(gstart, ph.memsz()))
            {
              Err().printf("Failed to load ELF kernel binary. "
                           "Region [0x%lx/0x%lx] not in RAM.\n",
                           ph.paddr(), ph.filesz());
              L4Re::chksys(-L4_ENOMEM, "Loading ELF binary.");
            }

          if (img_start > gstart)
            img_start = gstart;
          if (img_end.get() < gstart.get() + ph.filesz())
            img_end = gstart + ph.filesz();

          Dbg(Dbg::Mmio, Dbg::Info, "bin")
            .printf("Copy in ELF binary section @0x%lx from 0x%lx/0x%lx\n",
                    ph.paddr(), ph.offset(), ph.filesz());

          ram->copy_from_ds(_ds.get(), ph.offset(), gstart, ph.filesz());
        }
    });

    if (img_start >= img_end)
      {
        Err().printf("ELF binary does not have any PT_LOAD sections.\n");
        L4Re::chksys(-L4_ENOMEM, "Loading ELF binary.");
      }

    _loaded_range_start = ram->guest2host<l4_addr_t>(img_start);
    _loaded_range_end = ram->guest2host<l4_addr_t>(img_end);

    return _elf.entry();
  }

  l4_addr_t load_as_raw(Vmm::Vm_ram *ram, Vmm::Guest_addr start,
                        Vmm::Ram_free_list *free_list)
  {
    l4_size_t sz = _ds->size();

    if (!free_list->reserve_fixed(start, sz))
      {
        Err().printf("Failed to load kernel binary. Region [0x%lx/0x%llx] not in RAM.\n",
                     start.get(), _ds->size());
        L4Re::chksys(-L4_ENOMEM, "Loading kernel binary.");
      }

    ram->load_file(_ds.get(), start, sz);

    _loaded_range_start = ram->guest2host<l4_addr_t>(start);
    _loaded_range_end = _loaded_range_start + sz;

    return ram->guest_phys2boot(start);
  }

  void const *get_data() const
  { return _data.get(); }

  size_t size() const
  { return _ds->size(); }

  L4::Cap<L4Re::Dataspace> ds() const
  { return _ds.get(); }

  ~Binary_ds()
  {
    if (_loaded_range_start != 0 && _loaded_range_end != 0)
      l4_cache_coherent(_loaded_range_start, _loaded_range_end);
  }

  // App_model API
  typedef L4::Cap<L4Re::Dataspace> Const_dataspace;
  l4_addr_t local_attach_ds(Const_dataspace,
                            l4_size_t, l4_addr_t offset) const
  {
    return reinterpret_cast<l4_addr_t>(_data.get()) + offset;
  }

  void local_detach_ds(l4_addr_t, l4_size_t) const
  {}
  // end of App_model API

private:
  L4Re::Util::Unique_cap<L4Re::Dataspace> _ds;
  L4Re::Rm::Unique_region<char *> _data;
  Ldr::Elf_binary<Binary_ds> _elf;
  l4_addr_t _loaded_range_start = 0;
  l4_addr_t _loaded_range_end = 0;
};

/* Loader type
 *
 * Note: This list also defines the default priority in which the image format
 *       is detected. Raw should always be first. This ensures it will be
 *       processed last.
 */
enum Binary_type
{
  Invalid = 1000,
  Raw,
  Rom,
  Pe,
  Linux,
  LinuxGzip,
  Elf,
  OpenBSD, // Must be checked before ELF, since an OpenBSD image is also an ELF
};

class Binary_loader : public cxx::H_list_item_t<Binary_loader>
{
public:
  Binary_loader(Binary_type type)
  : _type(type)
  { types.push_front(this); }

  virtual int load(char const *bin, std::shared_ptr<Binary_ds> image,
                   Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list,
                   l4_addr_t *entry) = 0;

  bool is_64bit() const
  { return _64bit; }

  Binary_type type() const
  { return _type; }

  size_t size() const
  { return _binsize; }

  static Dbg warn()
  { return Dbg(Dbg::Core, Dbg::Warn, "loader"); }

  static Dbg info()
  { return Dbg(Dbg::Core, Dbg::Info, "loader"); }

  static Dbg trace()
  { return Dbg(Dbg::Core, Dbg::Trace, "loader"); }

  static cxx::H_list_t<Binary_loader> types;

protected:
  bool _64bit = false;
  Binary_type _type = Invalid;
  size_t _binsize = 0;
};

struct Binary_loader_factory
{
  int load(char const *bin, Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list,
           l4_addr_t *entry)
  {
    // Reverse search for the last ':'
    char const *file = bin;
    if (char const *t = strrchr(file, ':'))
      file = t + 1;

    std::shared_ptr<Boot::Binary_ds> image = std::make_shared<Boot::Binary_ds>(file);
    int res = -L4_EINVAL;
    for (auto *t: Binary_loader::types)
      {
        res = t->load(bin, image, ram, free_list, entry);
        if (res == L4_EOK)
          {
            _loader = t;
            break;
          }
      }

    if (res != L4_EOK)
      L4Re::throw_error(res, "No loader found for provided image.");

    return res;
  }

  bool is_64bit() const
  { return _loader ? _loader->is_64bit() : false; }

  Binary_type type() const
  { return _loader ? _loader->type() : Invalid; }

  size_t get_size() const
  { return _loader ? _loader->size() : 0UL; }

private:
  Binary_loader *_loader = nullptr;
};

} // namespace
