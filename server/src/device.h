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

namespace Gic {
  struct Ic;
}
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
  Dt_error_hdl(Dtb::Node<Dt_error_hdl> const *n, char const *msg)
  {
    Err().printf("%s: %s", n->get_name(), msg);
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
  Dt_error_hdl(Dtb::Node<Dt_error_hdl> const *n, int error, char const *msg)
  {
    Err().printf("%s: %s: %s", n->get_name(), msg, fdt_strerror(error));
    throw L4::Runtime_error(-L4_EINVAL);
  }

  template<typename ...Args>
  Dt_error_hdl(char const *fmt, Args ...args)
  {
    Err().cprintf(fmt, args...);
    Err().cprintf("\n");
    throw L4::Runtime_error(-L4_EINVAL);
  }

  template<typename ...Args>
  Dt_error_hdl(char const *msg)
  {
    Err().printf("%s\n", msg);
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
};

inline Device::~Device() = default;

/**
 * Interface with functions for finding device objects.
 */
struct Device_lookup
{
  virtual void add_device(Vdev::Dt_node const &node,
                          cxx::Ref_ptr<Vdev::Device> dev) = 0;
  virtual cxx::Ref_ptr<Device> device_from_node(Dt_node const &node) const = 0;
  virtual Vmm::Guest *vmm() const = 0;
  virtual cxx::Ref_ptr<Vmm::Ram_ds> ram() const = 0;
  virtual cxx::Ref_ptr<Vmm::Virt_bus> vbus() const = 0;
  virtual cxx::Ref_ptr<Vmm::Cpu_dev_array> cpus() const = 0;

  /// Result values for get_or_create_ic()
  enum Ic_error
  {
    Ic_ok,           ///< There is a valid interrupt parent device
    Ic_e_no_iparent, ///< Node does not have an interrupt parent property
    Ic_e_disabled,   ///< Node is disabled
    Ic_e_no_virtic,  ///< Interrupt parent is not a virtual interrupt controller
    Ic_e_failed,     ///< Creation of an interrupt parent failed
  };

  /**
   * Get a textual description for an Ic_error value.
   *
   * \param res  The error a textual description is looked for.
   *
   * \return Pointer to error string.
   *
   */
  static const char * ic_err_str(Vdev::Device_lookup::Ic_error res)
  {
    char const *err[] = {
        "no interrupt parent found",
        "interrupt parent node disabled"
        "interrupt parent is not a virtual interrupt controller",
        "creation of interrupt parent failed"
    };
    return (res < sizeof(err)/sizeof(err[0])) ? err[res] : "unknown error";
  }
  /**
   * Get the interrupt controller for a given node.
   *
   * \param node   The device tree node an interrupt parent is looked for.
   * \param fatal  Abort if true and no virtual device for the interrupt parent
   *               could be found.
   *
   * \return Either a pointer to the virtual device of the interrupt parent or
   *         nullptr in case of an error
   *
   * This method tries to fetch and return the interrupt parent of the node. If
   * the device doesn't exist yet and is a virtual device it tries to create it.
   * It walks the interrupt tree up and creates the missing devices starting
   * with the top most missing device. If creation of any device fails it
   * emits a diagnostic message and aborts if fatal is true. Otherwise it
   * returns a nullptr.
   */
  virtual cxx::Ref_ptr<Gic::Ic>get_or_create_ic_dev(Vdev::Dt_node const &node,
                                                    bool fatal) = 0;
  /**
   * Get the interrupt controller for a given node.
   *
   * \param node         The device tree node an interrupt parent is looked for.
   * \param[out] ic_ptr  A pointer to the virtual device of the interrupt parent
   *                     if there is one.
   *
   * \retval Ic_ok            interrupt parent was returned in ic_ptr
   * \retval Ic_e_no_iparent  node does not have an interrupt parent property
   * \retval Ic_e_disabled    interrupt parent node is
   * \retval Ic_e_no_virtic   interrupt parent is not a virtual interrupt
   *                          controller
   * \retval Ic_e_failed      creation of an interrupt parent failed
   *
   * This method tries to fetch and return the interrupt parent of the node. If
   * the device doesn't exist yet and is a virtual device it tries to create it.
   * It walks the interrupt tree up and creates the missing devices starting
   * with the top most missing device. On success it returns Ic_ok and ic_ptr
   * points to the virtual device of the interrupt parent. Otherwise one of the
   * remaining return codes describes the error.
   */
   virtual Ic_error get_or_create_ic(Vdev::Dt_node const &node,
                                     cxx::Ref_ptr<Gic::Ic> *ic_ptr) = 0;

};
} // namespace
