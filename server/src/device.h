/*
 * Copyright (C) 2016-2021, 2023 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/cxx/exceptions>

#include <string>

#include "device_tree.h"
#include "debug.h"

namespace Gic {
  struct Ic;
  struct Msix_controller;
}
namespace Vmm {
  class Guest;
  class Vm_ram;
  class Virt_bus;
  class Cpu_dev_array;
  class Pm;
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

class Dev_ref
{
private:
  mutable int _ref_cnt = 0;

public:
  void add_ref() const noexcept
  { __atomic_add_fetch(&_ref_cnt, 1, __ATOMIC_ACQUIRE); }

  int remove_ref() const noexcept
  { return __atomic_sub_fetch(&_ref_cnt, 1, __ATOMIC_RELEASE); }
};

template< typename T, typename... Args >
cxx::Ref_ptr<T>
make_device(Args &&... args)
{ return cxx::make_ref_obj<T>(cxx::forward<Args>(args)...); }

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
                          cxx::Ref_ptr<Vdev::Device> dev,
                          std::string const &path = std::string()) = 0;
  virtual cxx::Ref_ptr<Device> device_from_node(Dt_node const &node,
                                                std::string *path = nullptr)
                                                const = 0;
  virtual Vmm::Guest *vmm() const = 0;
  virtual cxx::Ref_ptr<Vmm::Vm_ram> ram() const = 0;
  virtual cxx::Ref_ptr<Vmm::Virt_bus> vbus() const = 0;
  virtual cxx::Ref_ptr<Vmm::Cpu_dev_array> cpus() const = 0;
  virtual cxx::Ref_ptr<Vmm::Pm> pm() const = 0;

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
        "ok",
        "no interrupt parent found",
        "interrupt parent node disabled",
        "interrupt parent is not a virtual interrupt controller",
        "creation of interrupt parent failed"
    };
    return (res < sizeof(err)/sizeof(err[0])) ? err[res] : "unknown error";
  }

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

  /// Result values for get_or_create_mc()
  enum Mc_error
  {
    Mc_ok,             ///< There is a valid MSI parent device.
    Mc_e_no_msiparent, ///< Node does not have an MSI parent property.
    Mc_e_disabled,     ///< Node is disabled.
    Mc_e_no_msictrl,   ///< Interrupt parent is not a virtual interrupt controller.
    Mc_e_failed,       ///< Creation of an MSI parent failed.
  };

  /**
   * Get a textual description for an Mc_error value.
   *
   * \param res  The error a textual description is looked for.
   *
   * \return Pointer to error string.
   *
   */
  static const char *mc_err_str(Mc_error res)
  {
    char const *err[] = {
        "ok",
        "no MSI parent found",
        "MSI parent node disabled",
        "MSI parent is not an MSI controller",
        "creation of MSI parent failed"
    };
    return (res < sizeof(err)/sizeof(err[0])) ? err[res] : "unknown error";
  }

  /**
   * Get the virtual MSI controller device for a given node.
   *
   * \param node         The device tree node to look up the MSI parent for.
   * \param[out] mc_ptr  A pointer to the virtual device of the MSI parent
   *                     if there is one.
   *
   * \retval Mc_ok              MSI parent was returned in mc_ptr.
   * \retval Mc_e_no_msiparent  Node does not have an MSI parent property.
   * \retval Mc_e_disabled      MSI parent node is disabled.
   * \retval Mc_e_no_msictrl    MSI parent is not a virtual MSI controller.
   * \retval Mc_e_failed        Creation of an MSI parent failed.
   */
  virtual Mc_error
  get_or_create_mc(Vdev::Dt_node const &node,
                   cxx::Ref_ptr<Gic::Msix_controller> *mc_ptr) = 0;

  /**
   * Get the virtual MSI controller device for a given node.
   *
   * \param node  The device tree node to look up the MSI parent for.
   *
   * \returns  A virtual MSI controller device or an exception is thrown.
   */
  virtual cxx::Ref_ptr<Gic::Msix_controller>
  get_or_create_mc_dev(Vdev::Dt_node const &node) = 0;
};
} // namespace
