/*
 * Copyright (C) 2024 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <tuple>
#include <l4/re/error_helper>

#include "device_tree.h"
#include "debug.h"
#include "pci_device.h"

namespace Vdev { namespace Pci {

/**
 * Allocator for a consecutive range of a PCI window resource.
 */
class Pci_window_alloc
{
public:
  enum : unsigned
  {
    Invalid_addr = 0xf ///< Unaligned address, never allocated
  };

  Pci_window_alloc() = default;

  Pci_window_alloc(l4_addr_t base, l4_size_t size)
  : _base(base), _size(size), _free_addr(base)
  {}

  /**
   * Initialize allocator with area to manage.
   */
  void init(l4_addr_t base, l4_size_t size, char const *type_info)
  {
    _base = base;
    _size = size;
    _free_addr = _base;
    info().printf("Init PCI window with range [0x%lx, 0x%lx %s]\n", _base,
                  end(), type_info);
  }

  /**
   * Allocate a consecutive chunk of memory from the MMIO resource window.
   *
   * \param size   Size of the allocation.
   *
   * \return `Invalid_addr` if the allocation failed, otherwise a valid address.
   *
   * Allocations must be naturally aligned. Sub-page allocations and
   * alignments are rounded up.
   */
  l4_addr_t alloc_mmio(l4_size_t size)
  {
    if (_base == Invalid_addr) // allocator not initialized
      return Invalid_addr;

    l4_size_t rounded_size = l4_round_page(size); // at least 4KB allocations

    unsigned align = 12;
    while ((((rounded_size >> align) & 1) == 0) && ((rounded_size >> align) > 0))
      ++align;

    return alloc(l4_round_size(_free_addr, align), size);
  }

  /**
   * Allocate a consecutive chunk of IO ports from the IO resource window.
   *
   * \param size   Size of the allocation.
   *
   * \return `Invalid_addr` if the allocation failed, otherwise a valid IO port.
   *
   * Allocations adhere to the PCI BAR size and alignmnet requirements.
   */
  l4_addr_t alloc_io(l4_size_t size)
  {
    if (_base == Invalid_addr) // allocator not initialized
      return Invalid_addr;

    // check for power of two alignment and compute the next aligned size.
    while ((size & (size - 1)) != 0)
      ++size;

    // Pad the start addr to be size aligned.
    unsigned align = 0;
    while ((((size >> align) & 1) == 0))
      ++align;

    return alloc(l4_round_size(_free_addr, align), size);
  }

  /// Return a tuple (start, size) describing the allocator area.
  std::pair<l4_addr_t, l4_addr_t> area() const
  { return {_base, _size}; }

  /// Free an area described by `start` and `size`.
  // TODO void free(l4_addr_t start, l4_size_t size);

  /// dump current memory status
  void dump_state(char const *type_info) const
  {
    warn()
      .printf("State[%s]: base 0x%lx, first free address 0x%lx, end 0x%lx\n",
              type_info, _base, _free_addr, end());
  }

private:
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "Pci_window_alloc"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "Pci_window_alloc"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "Pci_window_alloc"); }

  /// compute the inclusive end of the area
  l4_addr_t end() const { return _base + _size - 1; }

  /**
   * Allocate a consecutive chunk from the resource window.
   *
   * \param start  Aligned allocation start address.
   * \param size   Aligned allocation size request.
   *
   * \return `Invalid_addr` if the allocation failed, otherwise a valid
   *         allocation start address.
   */
  l4_addr_t alloc(l4_addr_t start, l4_size_t size)
  {
    l4_addr_t alloc_end = start + size;
    if (alloc_end > end())
      return Invalid_addr;

    l4_addr_t ret = start;
    _free_addr = alloc_end;
    return ret;
  };

  // assumptions: single-threaded, consecutive allocation, no free
  l4_addr_t _base = Invalid_addr;
  l4_addr_t _size = Invalid_addr;
  l4_addr_t _free_addr = Invalid_addr;
};

/**
 * Manager for all types of PCI bridge window resources.
 *
 * This class parses the DT node of the PCI bridge and sets up all resource
 * windows. This is currently limited to one window per resource type.
 * If multiple resource windows of the same type are specified in th DT node,
 * the last resource window is selected.
 */
class Pci_bridge_windows
{
  enum Type
  {
    MMIO32 = Pci_cfg_bar::Type::MMIO32,
    MMIO64 = Pci_cfg_bar::Type::MMIO64,
    IO = Pci_cfg_bar::Type::IO
  };

public:
  Pci_bridge_windows(Dt_node const &node)
  {
    init_bridge_window(node);
  }

  /**
   * Retrieve bridge MMIO and I/O windows from ranges property.
   */
  void init_bridge_window(Dt_node const &node)
  {
    int prop_size;
    auto prop = node.get_prop<fdt32_t>("ranges", &prop_size);
    if (!prop)
      L4Re::throw_error(-L4_EINVAL,
                        "PCI bridge: Missing ranges property in DT node");

    auto parent = node.parent_node();
    size_t parent_addr_cells = node.get_address_cells(parent);
    size_t child_addr_cells = node.get_address_cells(node);
    size_t child_size_cells = node.get_size_cells(node);

    unsigned range_size =
      child_addr_cells + parent_addr_cells + child_size_cells;
    if (prop_size % range_size != 0)
      {
        Err().printf("Ranges property size: %i, Range entry size %u, "
                     "#child cells %zu, #parent cells %zu, #size cells %zu\n",
                     prop_size, range_size, child_addr_cells, parent_addr_cells,
                     child_size_cells);
        L4Re::throw_error(-L4_EINVAL,
                          "PCI bridge: Invalid ranges property: Property size not a multiple of entry size.");
      }

    for (auto end = prop + prop_size; prop < end; prop += range_size)
      {
        auto flags = Dtb::Reg_flags::pci(fdt32_to_cpu(*prop));
        Dtb::Cell dt_parent_base(prop + child_addr_cells, parent_addr_cells);
        Dtb::Cell dt_size(prop + child_addr_cells + parent_addr_cells,
                       child_size_cells);

        l4_uint64_t base = dt_parent_base.get_uint64();
        l4_uint64_t size = dt_size.get_uint64();
        if (flags.is_mmio32())
          _mmio_alloc.init(base, size, type_to_str(Type::MMIO32));
        else if (flags.is_mmio64())
          _mmio64_alloc.init(base, size, type_to_str(Type::MMIO64));
        else if (flags.is_ioport())
          _io_alloc.init(base, size, type_to_str(Type::IO));
      }
  }


  /**
   * Request the area description of the resource window of Type `t`.
   *
   * \param t  Type of the window resource.
   *
   * \return  A tuple (base, size) describing the window area.
   */
  std::pair<l4_addr_t, l4_addr_t> get_window(Pci_cfg_bar::Type t) const
  {
    Type type = to_type(t);

    std::pair<l4_addr_t, l4_addr_t> ret;
    ret = window(type).area();
    return ret;
  }

  /**
   * Allocate a `size` chunk within a resouce window of type `t`.
   *
   * \param size  Size of the allocation.
   * \param t     Type of the resource window to allocate from.
   *
   * \return Base address of the new allocation or zero in case of failure.
   */
  l4_addr_t alloc_bar_resource(l4_size_t size, Pci_cfg_bar::Type t)
  {
    Type type = to_type(t);
    unsigned constexpr Invalid_addr = Pci_window_alloc::Invalid_addr;

    l4_addr_t ret = alloc_type(window(type), type, size);

    if (ret == Invalid_addr)
      {
        Err().printf("Allocation of type '%s' for 0x%zx bytes failed.\n",
                     type_to_str(type), size);
        window(type).dump_state(type_to_str(type));
        L4Re::throw_error(-L4_ENOMEM, "PCI bridge: Not enough free memory in PCI window.");
      }

    info().printf("[%s] allocated [0x%lx, 0x%lx]\n", type_to_str(type), ret,
                  ret + size - 1);
    return ret;
  }

private:
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "Pci_bridge_windows"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "Pci_bridge_windows"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "Pci_bridge_windows"); }

  static char const *type_to_str(Type t)
  {
    switch(t)
      {
      case Type::MMIO32: return "MMIO32";
      case Type::MMIO64: return "MMIO64";
      case Type::IO: return "IO";
      default: return "Invalid Type";
      }
  }

  static Type to_type(Pci_cfg_bar::Type t)
  {
    switch(t)
      {
      case Pci_cfg_bar::Type::MMIO32: return Type::MMIO32;
      case Pci_cfg_bar::Type::MMIO64: return Type::MMIO64;
      case Pci_cfg_bar::Type::IO: return Type::IO;
      default: L4Re::throw_error(-L4_ERANGE, "Invalid PCI MMIO window type.");
      }
  }

  l4_addr_t alloc_type(Pci_window_alloc &win, Type t, l4_size_t size)
  {
    if (t == Type::IO)
      return win.alloc_io(size);
    else
      return win.alloc_mmio(size);
  }

  Pci_window_alloc &window(Type type)
  {
    switch(type)
      {
      case Type::MMIO32: return _mmio_alloc;
      case Type::MMIO64: return _mmio64_alloc;
      case Type::IO: return _io_alloc;
      default: L4Re::throw_error(-L4_ERANGE, "Invalid PCI MMIO window type.");
      }
  }

  Pci_window_alloc const &window(Type type) const
  {
    switch(type)
      {
      case Type::MMIO32: return _mmio_alloc;
      case Type::MMIO64: return _mmio64_alloc;
      case Type::IO: return _io_alloc;
      default: L4Re::throw_error(-L4_ERANGE, "Invalid PCI MMIO window type.");
      }
  }

  /// IO window, maximum size 16bit
  Pci_window_alloc _io_alloc;
  /// maximum size 32bit, non-prefetchable
  Pci_window_alloc _mmio_alloc;
  /// maximum size min(64bit, HW addressable bits), prefetchable
  Pci_window_alloc _mmio64_alloc;
}; // class Pci_bridge_windows

} } // namespace Vdev::Pci
