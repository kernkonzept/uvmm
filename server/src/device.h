/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/cxx/exceptions>

#include "device_tree.h"
#include "debug.h"

namespace Vmm {
  class Guest;
  class Ram_ds;
  class Virt_bus;
  class Cpu_dev_array;
}

namespace Vdev {

struct Dt_error_hdl
{
  template<typename ...Args>
  Dt_error_hdl(Dtb::Node<Dt_error_hdl> const *n, char const *fmt, Args ...args)
  {
    Err().printf("%s: ", n->get_name());
    Err().cprintf(fmt, args...);
    Err().cprintf("\n");
    throw L4::Runtime_error(-L4_EINVAL);
  }

  template<typename ...Args>
  Dt_error_hdl(Dtb::Node<Dt_error_hdl> const *n, int error, char const *fmt, Args ...args)
  {
    Err().printf("%s: ", n->get_name());
    Err().cprintf(fmt, args...);
    Err().cprintf(": %s\n", fdt_strerror(error));
    throw L4::Runtime_error(-L4_EINVAL);
  }

  template<typename ...Args>
  Dt_error_hdl(char const *fmt, Args ...args)
  {
    Err().cprintf(fmt, args...);
    Err().cprintf("\n");
    throw L4::Runtime_error(-L4_EINVAL);
  }
};
typedef Dtb::Node<Dt_error_hdl> Dt_node;
typedef Dtb::Tree<Dt_error_hdl> Device_tree;

struct Dev_ref
{
  virtual void add_ref() const noexcept = 0;
  virtual int remove_ref() const noexcept = 0;
};

template <typename BASE>
class Dev_ref_obj : public virtual Dev_ref, public BASE
{
private:
  mutable int _ref_cnt;

public:
  template <typename... Args>
  Dev_ref_obj(Args &&... args)
  : BASE(cxx::forward<Args>(args)...), _ref_cnt(0)
  {}

  void add_ref() const noexcept override
  { __atomic_add_fetch(&_ref_cnt, 1, __ATOMIC_ACQUIRE); }

  int remove_ref() const noexcept override
  { return __atomic_sub_fetch(&_ref_cnt, 1, __ATOMIC_RELEASE); }
};

template< typename T, typename... Args >
cxx::Ref_ptr<T>
make_device(Args &&... args)
{ return cxx::make_ref_obj<Dev_ref_obj<T> >(cxx::forward<Args>(args)...); }

struct Device_lookup;

/**
 * Base class for all devices in the system.
 */
struct Device : public virtual Dev_ref
{
  virtual ~Device() = 0;
  virtual void init_device(Device_lookup const *devs, Dt_node const &node) = 0;
};

inline Device::~Device() = default;

/**
 * Interface with functions for finding device objects.
 */
struct Device_lookup
{
  virtual cxx::Ref_ptr<Device> device_from_node(Dt_node const &node) const = 0;
  virtual Vmm::Guest *vmm() const = 0;
  virtual cxx::Ref_ptr<Vmm::Ram_ds> ram() const = 0;
  virtual cxx::Ref_ptr<Vmm::Virt_bus> vbus() const = 0;
  virtual cxx::Ref_ptr<Vmm::Cpu_dev_array> cpus() const = 0;
};


} // namespace
