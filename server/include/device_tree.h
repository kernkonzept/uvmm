/*
 * Copyright (C) 2015-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/l4int.h>
#include <l4/re/error_helper>
#include <utility>
#include <map>

extern "C" {
#include <libfdt.h>
}

#include "cell.h"

namespace Dtb {

/**
 * Meta data about reg property.
 *
 * Depending on the bus type additionaly information is stored about a reg
 * property in the high word of the child node address.
 */
class Reg_flags
{
  // Internally stored in PCI device tree binding representation.
  enum
  {
    Reg_flags_pci_reg_mask      = 0xff,
    Reg_flags_pci_func_mask     = 0x07,
    Reg_flags_pci_func_shift    = 8,
    Reg_flags_pci_device_mask   = 0x1f,
    Reg_flags_pci_device_shift  = 11,
    Reg_flags_pci_bus_mask      = 0xff,
    Reg_flags_pci_bus_shift     = 16,

    Reg_flags_type_mask      = 0x03UL << 24,
    Reg_flags_type_cfgspace  = 0x00UL << 24,
    Reg_flags_type_ioport    = 0x01UL << 24,
    Reg_flags_type_mmio_32   = 0x02UL << 24,
    Reg_flags_type_mmio_64   = 0x03UL << 24,

    Reg_flags_aliased            = 1UL << 29,
    Reg_flags_mmio_prefetchable  = 1UL << 30,
    Reg_flags_non_relocatable    = 1UL << 31,
  };

  Reg_flags(l4_uint32_t flags) : _flags(flags) {}

public:
  Reg_flags() = default;
  Reg_flags(Reg_flags const &other) : _flags(other._flags) {}

  Reg_flags &operator=(Reg_flags const &other)
  { _flags = other._flags; return *this; }

  static Reg_flags pci(l4_uint32_t f) { return Reg_flags(f); }
  static Reg_flags ioport() { return Reg_flags(Reg_flags_type_ioport); }
  static Reg_flags mmio() { return Reg_flags(Reg_flags_type_mmio_32); }

  inline bool is_cfgspace() const
  { return (_flags & Reg_flags_type_mask) == Reg_flags_type_cfgspace; }

  inline bool is_ioport() const
  { return (_flags & Reg_flags_type_mask) == Reg_flags_type_ioport; }

  inline bool is_mmio32() const
  { return (_flags & Reg_flags_type_mask) == Reg_flags_type_mmio_32; }

  inline bool is_mmio64() const
  { return (_flags & Reg_flags_type_mask) == Reg_flags_type_mmio_64; }

  inline bool is_mmio() const
  { return is_mmio32() || is_mmio64(); }

  inline unsigned pci_reg() const
  { return _flags & Reg_flags_pci_reg_mask; }

  inline unsigned pci_function() const
  { return (_flags >> Reg_flags_pci_func_shift) & Reg_flags_pci_func_mask; }

  inline unsigned pci_device() const
  { return (_flags >> Reg_flags_pci_device_shift) & Reg_flags_pci_device_mask; }

  inline unsigned pci_bus() const
  { return (_flags >> Reg_flags_pci_bus_shift) & Reg_flags_pci_bus_mask; }

private:
  l4_uint32_t _flags = 0;
};

/**
 * Wrapper around the actual device tree memory to allow results caching of
 * certain functions. 'fdt' functions altering the tree have to use the
 * implemented wrapper functions. 'fdt_' functions reading the tree use dt() to
 * access the device tree memory read only.
 *
 * Additionally this class can handle external dt memory or manage a copy
 * itself.
 */
class Fdt
{
public:
  Fdt() {}
  Fdt(void *dtmem) : _dtmem(dtmem) {}
  Fdt(Fdt const &o, int padding = 0)
  : _owned(true)
  {
    size_t s = o.size() + padding;
    _dtmem = malloc(s);
    if (!_dtmem)
      L4Re::chksys(-L4_ENOMEM, "Allocating memory for device tree.");

    memcpy(_dtmem, o.dt(), o.size());
    fdt_set_totalsize(_dtmem, s);
  }

  ~Fdt()
  {
    if (_owned && _dtmem)
      {
        free(_dtmem);
        _dtmem = nullptr;
      }
  }

  size_t size() const
  { return fdt_totalsize(_dtmem); }

  // read-only access
  const void *dt() const
  { return _dtmem; }

  void move(void *dst)
  {
    fdt_move(dt_rw(), dst, size());
    if (_owned)
      free(_dtmem);

    _dtmem = nullptr;
  }

  void pack()
  { fdt_pack(dt_rw()); }

  int overlay_apply(void *fdt_overlay)
  { return fdt_overlay_apply(dt_rw(), fdt_overlay); }

  int add_subnode(int node, char const *name)
  { return fdt_add_subnode(dt_rw(), node, name); }

  int del_node(int node)
  { return fdt_del_node(dt_rw(), node); }

  int setprop_u32(int node, char const *name, fdt32_t value)
  { return fdt_setprop_u32(dt_rw(), node, name, value); }

  int setprop_u64(int node, char const *name, fdt64_t value)
  { return fdt_setprop_u64(dt_rw(), node, name, value); }

  int setprop_string(int node, char const *name, char const *value)
  {
    int err = fdt_setprop_inplace_namelen_partial(_dtmem, node, name,
                                                  strlen(name), 0, value,
                                                  strlen(value) + 1);
    if (err >= 0)
      return err;

    return fdt_setprop_string(dt_rw(), node, name, value);
  }

  int setprop(int node, char const *name, void const *data, int len)
  { return fdt_setprop(dt_rw(), node, name, data, len); }

  int setprop_placeholder(int node, char const *name, int len, void **prop_data)
  { return fdt_setprop_placeholder(dt_rw(), node, name, len, prop_data); }

  int setprop_inplace_namelen_partial(int node,
                                      char const *name, int name_len,
                                      uint32_t idx, void const *val, int len)
  {
    // That function does not change any node offset as it just replaces the
    // property without changing its size. Hence, use _dtmem as flushing the
    // caches is not necessary.
    return fdt_setprop_inplace_namelen_partial(_dtmem, node, name,
                                               name_len, idx, val, len);
  }

  int appendprop_u32(int node, char const *name, fdt32_t value)
  { return fdt_appendprop_u32(dt_rw(), node, name, value); }

  int appendprop_u64(int node, char const *name, fdt64_t value)
  { return fdt_appendprop_u64(dt_rw(), node, name, value); }

  int delprop(int node, char const *name)
  { return fdt_delprop(dt_rw(), node, name); }

  fdt32_t phandle(fdt32_t prop) const
  {
    int offs;
    auto it = _phandles.find(prop);
    if (it == _phandles.end())
      {
        offs = fdt_node_offset_by_phandle(_dtmem, fdt32_to_cpu(prop));
        _phandles[prop] = offs;
      }
    else
      offs = it->second;

    return offs;
  }

  int parent(int node) const
  {
    int offs;
    auto it = _parents.find(node);
    if (it == _parents.end())
      {
        offs = fdt_parent_offset(_dtmem, node);
        _parents[node] = offs;
      }
    else
      offs = it->second;
    return offs;
  }

private:
  // private write access
  void *dt_rw()
  {
    _phandles.clear();
    _parents.clear();
    return _dtmem;
  }

  // Caches
  mutable std::map<fdt32_t, int> _phandles;
  mutable std::map<int, int> _parents;

  void *_dtmem = nullptr;
  bool _owned = false;
};

template<typename ERR>
class Node
{
  friend class Property;

public:
  enum
  {
    // Defaults according to include/linux/of.h, overridden with
    // address_cells = 2 for sparc
    Default_address_cells = 1,
    Default_size_cells = 1,
  };
  /** Additional error codes */
  enum
  {
    ERR_BAD_INDEX = FDT_ERR_MAX + 1, /**< An index into a structured
                                          property like "reg" or
                                          "range" was out of range */
    ERR_RANGE,                       /**< A cell value does not fit
                                          into a 64bit value */
    ERR_NOT_TRANSLATABLE             /**< A reg value could not be
                                          translated and is a bus
                                          local address */
  };

  static char const *strerror(int errval)
  {
    switch (errval)
      {
      case -ERR_BAD_INDEX:        return "Index out of range";
      case -ERR_RANGE:            return "Value does not fit into 64bit value";
      case -ERR_NOT_TRANSLATABLE: return "Reg entry is not translatable";
      default:                    return fdt_strerror(errval);
      }
  }

public:
  Node() : _node(-1) {}
  Node(Fdt *dt, int node) : _fdt(dt), _node(node) {}

  bool operator == (Node const &other) const
  { return (_fdt == other._fdt) && (_node == other._node); }

  bool operator != (Node const &other) const
  { return !operator==(other); }

  bool is_valid() const
  { return _node >= 0; }

  /**
   * Add a subnode
   *
   * \param name Name of the new subnode
   *
   * \return New node or an invalid node (node offset equals the
   *         libfdt error)
   */
  Node add_subnode(char const *name)
  { return Node(_fdt, _fdt->add_subnode(_node, name)); }

  /**
   * Delete a node
   *
   * \return 0 on success, negative fdt_error otherwise
   */
  int del_node()
  {
    int res = _fdt->del_node(_node);
    if (res == 0)
      _node = -1; // invalidate node
    return res;
  }

  /**
   * Get the next node of this tree
   *
   * \param depth  Pointer to the depth of the current node; If not
   *               null, depth will be updated to reflect the depth of
   *               the returned node (unchanged for a sibling, depth +
   *               1 for a child, depth - 1 for a sibling of the
   *               parent).
   *
   * \return Next node of the tree or an invalid node (node
   *         offset equals the libfdt error)
   */
  Node next_node(int *depth = nullptr) const
  { return Node(_fdt, fdt_next_node(_fdt->dt(), _node, depth)); }

  /**
   * Get the next compatible node of this tree
   *
   * \param  compatible 'compatible' string to match against
   *
   * \return Next compatible node of the tree or an invalid node (node
   *         offset equals the libfdt error)
   */
  Node next_compatible_node(char const *compatible) const
  { return Node(_fdt, fdt_node_offset_by_compatible(_fdt->dt(), _node, compatible)); }

  /**
   * Get the first child node
   *
   * \return node The first child node or an invalid node (node offset
   *              equals the libfdt error)
   */
  Node first_child_node() const
  { return Node(_fdt, fdt_first_subnode(_fdt->dt(), _node)); }

  /**
   * Get the next sibling
   *
   * \return node The next sibling or an invalid node (node offset
   *              equals the libfdt error)
   */
  Node sibling_node() const
  { return Node(_fdt, fdt_next_subnode(_fdt->dt(), _node)); }

  Node parent_node() const
  { return Node(_fdt, _fdt->parent(_node)); }

  bool is_root_node() const
  { return _node == 0; };

  bool has_children() const
  { return fdt_first_subnode(_fdt->dt(), _node) >= 0; }

  int get_depth() const
  { return fdt_node_depth(_fdt->dt(), _node); }

  char const *get_name() const
  {
    if (is_root_node())
      return "/";

    char const *name = fdt_get_name(_fdt->dt(), _node, nullptr);
    return name ? name : "<unknown name>";
  }

  int get_cells_attrib(char const *name) const
  {
    if (!is_valid())
      return -FDT_ERR_BADSTRUCTURE;

    int size;
    auto *prop = get_prop<fdt32_t>(name, &size);

    if (!prop)
      return size;

    int val = fdt32_to_cpu(*prop);
    if ((size != 1) || (val > FDT_MAX_NCELLS))
      return -FDT_ERR_BADNCELLS;

    return val;
  }

  size_t get_cells_attrib_default(const char *name, int default_cells,
                                  Node const &parent) const
  {
    int val = parent.get_cells_attrib(name);
    if (val >= 0)
      return val;

    if (val == -FDT_ERR_NOTFOUND)
      {
        // The spec states, that the address/size cells attribute
        // should be attached to each node that has children. If it is
        // missing the caller should assume 2 for #addr-cells and 1
        // for #size-cells (passed as parameter by the caller).
        //
        // It looks like some device trees assume the cells attributes
        // of the root node as default, so we check the root node
        // here, before returning the default value.
        auto root_node = Node(_fdt, 0); // Tree::first_node()
        val = root_node.get_cells_attrib(name);
        if (val >= 0)
          return val;

        if (val == -FDT_ERR_NOTFOUND)
          return default_cells;
      }

    ERR(this, "Unable to lookup %s: %s", name, fdt_strerror(val));
    return default_cells;
  }

  size_t get_address_cells(Node const &parent) const
  {
    return get_cells_attrib_default("#address-cells", Default_address_cells,
                                    parent);
  }

  size_t get_size_cells(Node const &parent) const
  {
    return get_cells_attrib_default("#size-cells", Default_size_cells,
                                    parent);
  }

  void setprop_u32(char const *name, l4_uint32_t value) const
  {
    int r = _fdt->setprop_u32(_node, name, value);
    if (r < 0)
      ERR(this, "cannot set property '%s' to '0x%x': %s", name, value,
          fdt_strerror(r));
  }

  void setprop_u64(char const *name, l4_uint64_t value) const
  {
    int r = _fdt->setprop_u64(_node, name, value);
    if (r < 0)
      ERR(this, "cannot set property '%s' to '0x%llx': %s", name, value,
          fdt_strerror(r));
  }

  void setprop(char const *name, l4_uint64_t value, unsigned cells) const
  {
    switch (cells)
      {
      case 1:
        if (value >= (1ULL << 32))
          ERR(this, "Value too large for property %s", name);

        setprop_u32(name, value);
        break;

      case 2:
        setprop_u64(name, value);
        break;

      default:
        ERR(this, "Unexpected property value cell size: %u", cells);
        break;
    }
  }

  void setprop_string(char const *name, char const *value) const
  {
    int r = _fdt->setprop_string(_node, name, value);
    if (r < 0)
      ERR(this, "cannot set property '%s' to '%s'", name, value);
  }

  void setprop_data(char const *name, void const *data, int len) const
  {
    int r = _fdt->setprop(_node, name, data, len);
    if (r < 0)
      ERR(this, "cannot set property '%s'", name);
  }

  void setprop_placeholder(char const *name, int len, void **prop_data) const
  {
    int r = _fdt->setprop_placeholder(_node, name, len, prop_data);
    if (r < 0)
      ERR(this, "cannot resize property '%s' to %d bytes", name, len);
  }

  void appendprop_u32(char const *name, l4_uint32_t value) const
  {
    int r = _fdt->appendprop_u32(_node, name, value);
    if (r < 0)
      ERR(this, "cannot append '0x%x' to property '%s': %s", value, name,
          fdt_strerror(r));
  }

  void appendprop_u64(char const *name, l4_uint64_t value) const
  {
    int r = _fdt->appendprop_u64(_node, name, value);
    if (r < 0)
      ERR(this, "cannot append '0x%llx' to property '%s': %s", value, name,
          fdt_strerror(r));
  }

  void appendprop(char const *name, l4_uint64_t value, unsigned cells) const
  {
    switch (cells)
      {
      case 1:
        if (value >= (1ULL << 32))
          ERR(this, "Value too large for property: %s", name);

        appendprop_u32(name, value);
        break;

      case 2:
        appendprop_u64(name, value);
        break;

      default:
        ERR(this, "Unexpected property value cell size %u", cells);
        break;
    }
  }

  /**
   * Delete a property of this node
   *
   * \param name Name of the property to delete
   *
   * \return 0 on success, libfdt error codes otherwise
   */
  int delprop(char const *name) const
  { return _fdt->delprop(_node, name); }

  bool is_enabled() const
  {
    int lenp;
    char const *p = get_prop<char>("status", &lenp);
    if (!p)
      return true;

    return lenp > 2 && (!strncmp(p, "okay", lenp) || !strcmp(p, "ok"));
  }

  /**
   * Disable a device node.
   *
   * Linux treats a node as enabled if
   *  \li \c status == "ok"
   *  \li \c status == "okay"
   *  \li \c status property does not exist
   *
   * Linux convention for disabling a node:
   * \li \c status == "disabled"
   *
   * Writing "disa" instead of "disabled" would increase the chance that an
   * existing status == "okay" can be replaced without changing the property
   * size. A change of the property size can change node offsets requiring a
   * flush of the caches. However, as the documentation is not entirely clear
   * about other status words for disabled nodes, we play safe.
   */
  void disable() const
  { setprop_string("status", "disabled"); }

  bool has_prop(char const *name) const
  {
    return fdt_getprop_namelen(_fdt->dt(), _node, name, strlen(name), nullptr)
           != nullptr;
  }

  bool has_compatible() const
  { return has_prop("compatible"); }

  bool is_compatible(char const *compatible) const
  { return fdt_node_check_compatible(_fdt->dt(), _node, compatible) == 0; }

  void get_path(char *buf, int buflen) const
  {
    int r = fdt_get_path(_fdt->dt(), _node, buf, buflen);
    if (r < 0)
      ERR(this, r, "cannot get path for node");
  }

  l4_uint32_t get_phandle() const
  { return fdt_get_phandle(_fdt->dt(), _node); }

  int stringlist_count(char const *property) const
  { return fdt_stringlist_count(_fdt->dt(), _node, property); }

  char const *stringlist_get(char const *property, int index, int *lenp) const
  { return fdt_stringlist_get(_fdt->dt(), _node, property, index, lenp); }

  l4_uint64_t get_prop_val(fdt32_t const *prop, l4_uint32_t size,
                           bool check_range) const
  {
    l4_uint64_t val;
    // fdt32_t is unsigned and guaranteed to be 4 byte aligned
    switch (size)
      {
      case 1:
        val = fdt32_to_cpu(*prop);
        break;

      case 2:
        val = (l4_uint64_t(fdt32_to_cpu(*prop)) << 32)
              + fdt32_to_cpu(*(prop + 1));
        if (check_range && (sizeof(l4_addr_t) == 4) && (val >= (1ULL << 32)))
          ERR(this, "property value too large for 32bit systems");

        break;

      default:
        ERR(this, "Invalid value for address/size cell: %d", size);
        val = 0;
        break;
      }
    return val;
  }

  void set_prop_partial(char const *property, uint32_t idx,
                        const void *val, int len) const
  {
    int r = _fdt->setprop_inplace_namelen_partial(_node,
                                                  property, strlen(property),
                                                  idx, val, len);
    if (r < 0)
      ERR(this, "cannot update property '%s' partially (idx=%u, len=%d): %s",
          property, idx, len, fdt_strerror(r));
  }

  /**
   * Get address/size pair from reg property.
   *
   * Note that in case of a PCI device the `index` is the BAR register (0..5).
   *
   * \param[in]  index             Index of pair
   * \param[out] address           Store address in *address if address != 0
   * \param[out] size              Store size in *size if size != 0
   * \param[out] flags             Store Reg_flags of address
   *
   * \retval -ERR_BAD_INDEX        node does not have a reg entry with the
   *                               specified index
   * \retval -ERR_RANGE            a reg value does not fit into a 64bit value
   * \retval -ERR_NOT_TRANSLATABLE reg entry exists, but is not translatable
   * \retval <0                    other fdt related errors
   * \retval 0                     ok
   */
  int get_reg_val(int index, l4_uint64_t *address, l4_uint64_t *size,
                  Reg_flags *flags = nullptr) const
  {
    auto parent = parent_node();
    size_t addr_cells = get_address_cells(parent);
    size_t size_cells = get_size_cells(parent);
    int rsize = addr_cells + size_cells;

    int prop_size;
    auto *prop = get_prop<fdt32_t>(parent.is_pci_bus() ? "assigned-addresses"
                                                       : "reg",
                                   &prop_size);
    if (!prop && prop_size < 0)
      return prop_size;

    if (!prop)
      return -FDT_ERR_INTERNAL;

    if (prop_size < rsize * (index + 1))
      return -ERR_BAD_INDEX;

    prop += rsize * index;

    Reg reg{Cell{prop, addr_cells}, Cell(prop + addr_cells, size_cells)};
    bool res = translate_reg(parent, &reg);

    if (!reg.address.is_uint64() || !reg.size.is_uint64())
      return -ERR_RANGE;

    if (address)
      *address = reg.address.get_uint64();
    if (size)
      *size = reg.size.get_uint64();
    if (flags)
      *flags = parent.get_flags(prop);

    return res ? 0 : -ERR_NOT_TRANSLATABLE;
  }

  /**
   * Get size and/or flags of reg entry.
   *
   * \param[in]  index   Index of reg property entry
   * \param[out] size    Store size in *size if size != 0
   * \param[out] flags   Store Reg_flags of address if flags != 0
   *
   * The reg property is not translated into the root address space. In case
   * of a PCI device the `flags` will hold the information about type and
   * BAR register index.
   */
  int get_reg_size_flags(int index, l4_uint64_t *size, Reg_flags *flags) const
  {
    auto parent = parent_node();
    size_t addr_cells = get_address_cells(parent);
    size_t size_cells = get_size_cells(parent);
    int rsize = addr_cells + size_cells;

    int prop_size;
    auto *prop = get_prop<fdt32_t>("reg", &prop_size);
    if (!prop && prop_size < 0)
      return prop_size;

    if (!prop)
      return -FDT_ERR_INTERNAL;

    if (prop_size < rsize * (index + 1))
      return -ERR_BAD_INDEX;

    prop += rsize * index;

    Cell sz(prop + addr_cells, size_cells);
    if (!sz.is_uint64())
      return -ERR_RANGE;

    if (size)
      *size = sz.get_uint64();
    if (flags)
      *flags = parent.get_flags(prop);

    return 0;
  }

  /**
   * Set address/size pair of reg property
   *
   * \param[in] address  Address value to store in reg pair
   * \param[in] size     Size value to store in reg pair
   * \param[in] append   true, if reg val is supposed to be appended
   *
   * This function throws an exception if "reg" property does not exist.
   */
  void set_reg_val(l4_uint64_t address, l4_uint64_t size, bool append = false) const
  {
    auto parent = parent_node();
    size_t addr_cells = get_address_cells(parent);
    size_t size_cells = get_size_cells(parent);

    if (append)
      appendprop("reg", address, addr_cells);
    else
      setprop("reg", address, addr_cells);

    appendprop("reg", size, size_cells);
  }

  /**
   * Append address/size pair to reg property
   *
   * \param[in] address Address value to store in reg pair
   * \param[in] size Size value to store in reg pair
   *
   * This function throws an exception if "reg" property does not exist.
   */
  void append_reg_val(l4_uint64_t address, l4_uint64_t size) const
  {
    set_reg_val(address, size, true);
  }

  /**
   * Update the address part of a reg property in-place.
   *
   * \param[in] idx      Index of address/size pair in reg property
   * \param[in] address  New address value to store in reg pair
   *
   * This function throws an exception if "reg" property does not exist.
   */
  void update_reg_address(uint32_t idx, uint64_t address) const
  { update_reg_val(idx, idx, address); }

  /**
   * Update the size part of a reg property in-place.
   *
   * \param[in] idx   Index of address/size pair in reg property
   * \param[in] size  New size value to store in reg pair
   *
   * This function throws an exception if "reg" property does not exist.
   */
  void update_reg_size(uint32_t idx, uint64_t size) const
  { update_reg_val(idx + 1, idx, size); }

  /**
   * Resize the reg property to the specified number of address/size pairs.
   *
   * \param[in] num_regs  Number of address/size pairs to reserve space for
   *
   * When shrinking the property (= new size is smaller than current size)
   * the existing values are preserved. When growing the property (= new size
   * is larger than current size, or property does not exist yet) additional
   * space is reserved but left uninitialized.
   *
   * This function throws an exception if the device tree cannot be resized.
   */
  void resize_reg(int num_regs) const
  {
    auto parent = parent_node();
    size_t addr_cells = get_address_cells(parent);
    size_t size_cells = get_size_cells(parent);
    int len = (addr_cells + size_cells) * num_regs * sizeof(fdt32_t);
    void *prop_data;
    setprop_placeholder("reg", len, &prop_data);
  }

  /**
   * Set address value
   *
   * \param[in] address Address value to store
   *
   * This function throws an exception if "reg" property does not exist.
   */
  void set_prop_address(char const *property, l4_addr_t address) const
  {
    switch (sizeof(address))
      {
      case 4:
        setprop_u32(property, address);
        break;
      case 8:
        setprop_u64(property, address);
        break;
      default:
        static_assert((sizeof(address) == 4) || (sizeof(address) == 8),
                      "Unexpected address size");
      }
  }

  /**
   * Check whether a node has irq resources associated
   *
   * This function checks whether the node has an "interrupts"
   * or "interrupts-extended" property.
   *
   * \return True if there is an "interrupts" property.
   */
  bool has_irqs() const
  { return has_prop("interrupts") || has_prop("interrupts-extended"); }


  /**
   * Check whether a node has mmio resources associated
   *
   * This function checks whether the node has "reg" properties and
   * any of the reg property values are mapped to mmio resources on
   * the root bus.
   *
   * \return True if there are mmio resources
   */
  bool has_mmio_regs() const;

  /**
   * Translate a reg entry
   *
   * Reg entries are bus local information. To get an address valid on
   * the "root bus" we have to traverse the tree and translate the reg
   * entry using ranges properties. If we reach the root node, the
   * translation was successful and reg contains the translated
   * address. If any of the intermediate nodes is unable to translate
   * the reg, the translation fails and reg is not changed.
   *
   * \param parent     Parent node. Performance optimization.
   * \param[inout] reg Pointer to reg structures which shall be
   *                   translated. If the translation was successful,
   *                   *reg contains the translated values.
   * \return True if the translation was successful.
   */
  bool translate_reg(Node const &parent, Reg *reg) const
  {
    if (is_root_node())
      return true;

    Cell tmp{reg->address};
    if (!translate_reg(parent, &tmp, reg->size))
      return false;

    reg->address = tmp;
    return true;
  }

  template <typename T>
  T const *get_prop(char const *name, int *size) const
  {
    void const *p = fdt_getprop_namelen(_fdt->dt(), _node, name, strlen(name), size);

    if (p && size)
      *size /= sizeof(T);

    return reinterpret_cast<T const *>(p);
  }

  template <typename T>
  T const *check_prop(char const *name, int size) const
  {
    int len;
    void const *prop = fdt_getprop_namelen(_fdt->dt(), _node, name, strlen(name),
                                           &len);
    if (!prop)
      ERR(this, "could not get property '%s': %s", name, fdt_strerror(len));

    if (len < static_cast<int>(sizeof(T)) * size)
      ERR(this, "property '%s' is too small (%d need %u)",
          name, len, static_cast<unsigned>(sizeof(T) * size));

    return reinterpret_cast<T const *>(prop);
  }

  Node find_phandle(fdt32_t prop) const
  { return Node(_fdt, _fdt->phandle(prop)); }

  /**
   * Find IRQ parent of node.
   *
   * \return  The node of the IRQ parent or an invalid node, if no parent is
   *          found.
   *
   * Traverses the device tree upwards and tries to find the IRQ parent. If no
   * IRQ parent is found or the IRQ parent is identical to the node itself an
   * invalid node is returned.
   */
  Node find_irq_parent() const
  {
    Node node = *this;

    while (node.is_valid())
      {
        int size = 0;
        auto *prop = node.get_prop<fdt32_t>("interrupt-parent", &size);

        if (prop)
          node = (size > 0) ? find_phandle(*prop) : Node(_fdt, -1);
        else
          node = node.parent_node();

        if (node.is_valid() && node.has_prop("#interrupt-cells"))
          {
            if (node != *this)
              return node;
            else
              break;
          }
      }

    return Node(_fdt, -1);
  }

  template <typename PRE, typename POST>
  void scan_recursive(int depth,
                      PRE &&pre_order_cb, POST &&post_order_cb,
                      bool skip_disabled = true) const;

private:
  /**
   * Update the address or size part of a reg property in-place.
   *
   * \param[in] addr_idx  Number of address cells to skip from the beginning
   * \param[in] size_idx  Number of size cells to skip from the beginning
   * \param[in] val       New value to store in reg pair
   *
   * To update the address part, addr_idx should be equal to size_idx.
   * To update the size part, addr_idx = size_idx + 1.
   * This function throws an exception if "reg" property does not exist.
   */
  void update_reg_val(uint32_t addr_idx, uint32_t size_idx, uint64_t val) const
  {
    auto parent = parent_node();
    size_t addr_cells = get_address_cells(parent);
    size_t size_cells = get_size_cells(parent);

    unsigned poff = (addr_idx * addr_cells + size_idx * size_cells) * sizeof(fdt32_t);
    unsigned cells = addr_idx > size_idx ? size_cells : addr_cells;
    switch (cells)
      {
        case 1:
          {
            fdt32_t tmp = cpu_to_fdt32(val);
            set_prop_partial("reg", poff, &tmp, sizeof(tmp));
            break;
          }
        case 2:
          {
            fdt64_t tmp = cpu_to_fdt64(val);
            set_prop_partial("reg", poff, &tmp, sizeof(tmp));
            break;
          }
        default:
          ERR(this, "Unexpected cell size %u", cells);
        }
  }


  /**
   * Translate a (address, size) cell pair
   *
   * Reg entries are bus local information. To get an address valid on
   * the "root bus" we have to traverse the tree and translate the reg
   * entry using ranges properties. If we reach the root node, the
   * translation was successful and reg contains the translated
   * address. If any of the intermediate nodes is unable to translate
   * the reg, the translation fails and reg is not changed.
   *
   * \param parent         Parent node. Performance optimization.
   * \param[inout] address Pointer to address cell which shall be
   *                       translated. If the translation was
   *                       successful, *address contains the
   *                       translated values.
   * \param[in] size       Size cell describing the size of the region
   * \return True if the translation was successful.
   */
  bool translate_reg(Node const &parent, Cell *address, Cell const &size) const;

  /**
   * Get flags from reg property of a child.
   *
   * Depending on the bus type, the first reg property word has some
   * information about the reg entry.
   *
   * \param[in] reg   Pointer first word of reg property
   */
  Reg_flags get_flags(fdt32_t const *reg) const
  {
    Reg_flags ret;

    l4_uint32_t addr = fdt32_to_cpu(*reg);
    if (is_pci_bus())
      ret = Reg_flags::pci(addr);
    else if (is_isa_bus())
      ret = (addr & 0x01U) ? Reg_flags::ioport() : Reg_flags::mmio();
    else
      ret = Reg_flags::mmio();

    return ret;
  }

  bool is_pci_bus() const
  {
    char const *devtype = get_prop<char>("device_type", nullptr);
    return devtype && strcmp(devtype, "pci") == 0;
  }

  bool is_isa_bus() const
  {
    char const *devtype = get_prop<char>("device_type", nullptr);
    if (!devtype)
      return false;

    return strcmp(devtype, "isa") == 0 || strcmp(devtype, "eisa") == 0;
  }

  Fdt *_fdt = nullptr;
  int _node;
};

template<typename ERR>
class Tree
{
public:
  typedef Dtb::Node<ERR> Node;
  explicit Tree(Fdt *dt) : _fdt(dt) {}

  void check_tree()
  {
    if (fdt_check_header(_fdt->dt()) < 0)
      ERR("Not a device tree");
  }

  unsigned size() const
  { return _fdt->size(); }

  /**
   * Apply the device tree overlay at 'fdt_overlay'.
   *
   * \param  fdt_overlay address of the device tree overlay which
   *                     should be applied to this device tree.
   * \param  name        name of the overlay for logging purposes.
   *
   * \note The overlay device tree is changed as well. Its magic value
   *       is invalidated on success.
   */
  void apply_overlay(void *fdt_overlay, char const *name)
  {
    int ret = _fdt->overlay_apply(fdt_overlay);
    if (ret < 0)
      ERR("cannot apply overlay '%s': %d\n", name, ret);
  }

  Node first_node() const
  { return Node(_fdt, 0); }

  /**
   * Get the first compatible node of this tree
   *
   * \param  compatible 'compatible' string to match against
   *
   * \return First compatible node of the tree or an invalid node (node
   *         offset equals the libfdt error)
   */
  Node first_compatible_node(char const *compatible) const
  { return Node(_fdt, fdt_node_offset_by_compatible(_fdt->dt(), -1, compatible)); }

  /**
   * Return the node at the given path.
   *
   * \throws No node could be found for the path.
   */
  Node path_offset(char const *path) const
  {
    int ret = fdt_path_offset_namelen(_fdt->dt(), path, strlen(path));
    if (ret < 0)
      ERR("cannot find node '%s'", path);

    return Node(_fdt, ret);
  }

  template <typename PRE, typename POST>
  void scan(PRE &&pre_order_cb, POST &&post_order_cb,
            bool skip_disabled = true) const;

  /**
   * Delete all nodes with specific property value and status.
   *
   * \param prop             Property to compare.
   * \param value            Node is deleted if `prop` has this value.
   * \param delete_disabled  Delete only disabled nodes if true, otherwise
   *                         delete all
   *
   * \return 0 on success, negative fdt_error otherwise
   */
  int remove_nodes_by_property(char const *prop, char const *value,
                               bool delete_disabled) const
  {
    Node node = first_node();

    while (node.is_valid())
      {
        int prop_size;
        char const *property;

        property = node.template get_prop<char>(prop, &prop_size);

        if (   (property && strncmp(value, property, prop_size) == 0)
            && (!delete_disabled || !node.is_enabled()))
          {
            int err = node.del_node();
            if (err)
              return err;

            // node was deleted and is invalid. The documentation
            // states that some node offsets changed (without
            // specifying which ones) - so we do not try anything
            // clever (like continuing with the last known node) and
            // simply restart at the beginning. Since we usually only
            // have one or two memory nodes this seems to be ok.
            node = first_node();
          }
        else
          node = node.next_node();
      }

    return 0;
  }

private:
  Fdt *_fdt;
};

template<typename ERR>
bool
Node<ERR>::translate_reg(Node const &parent, Cell *address, Cell const &size) const
{
  static Cell no_reg_mask;
  static Cell pci_bus_reg_mask = Cell::make_cell({0x03000000U, 0xffffffffU, 0xffffffffU});
  static Cell isa_bus_reg_mask = Cell::make_cell({0x0000'0001U, 0xffff'ffffU});

  if (parent.is_root_node())
    return true;

  int prop_size;
  auto prop = parent.template get_prop<fdt32_t>("ranges", &prop_size);
  if (!prop)
    return false; // no translation possible

  if (!prop_size)
    return true; // Ident mapping

  auto child_addr = get_address_cells(parent);
  auto parent_parent = parent.parent_node();
  auto parent_addr = parent.get_address_cells(parent_parent);
  auto child_size = get_size_cells(parent);

  Cell const *mask = &no_reg_mask;
  if (parent.is_pci_bus())
    {
      if (child_addr != 3 || child_size != 2)
        ERR(this, "Invalid reg size %u/%u", child_addr, child_size);

      mask = &pci_bus_reg_mask;
      *address &= pci_bus_reg_mask;
    }
  else if (parent.is_isa_bus())
    {
      if (child_addr != 2 || child_size != 1)
        ERR(this, "Invalid reg size %u/%u", child_addr, child_size);

      mask = &isa_bus_reg_mask;
      *address &= isa_bus_reg_mask;
    }

  unsigned range_size = child_addr + parent_addr + child_size;
  if (prop_size % range_size != 0)
    ERR("%s: Unexpected property size %d/%d/%d vs %d",
        get_name(), child_addr, parent_addr, child_size,
        prop_size);

  for (auto end = prop + prop_size; prop < end; prop += range_size)
    {
      Range range{Cell(prop, child_addr) & *mask,
                  Cell(prop + child_addr, parent_addr),
                  Cell(prop + child_addr + parent_addr, child_size)};
      if (range.translate(address, size))
        return parent.translate_reg(parent_parent, address, size);
    }
  return false;
}

template<typename ERR>
bool
Node<ERR>::has_mmio_regs() const
{
  int prop_size;
  auto prop = get_prop<fdt32_t>("reg", &prop_size);
  if (!prop)
    return false;

  auto parent = parent_node();
  size_t addr_cells = get_address_cells(parent);
  size_t size_cells = get_size_cells(parent);
  size_t reg_size = addr_cells + size_cells;
  size_t num_regs = prop_size/reg_size;

  if (prop_size % reg_size != 0)
    ERR(this, "Unexpected property size %zd/%zd vs %zd",
        addr_cells, size_cells, prop_size);

  for (size_t i = 0; i < num_regs; ++i, prop += reg_size)
    {
      Reg reg{Cell{prop, addr_cells}, Cell(prop + addr_cells, size_cells)};
      if (translate_reg(parent, &reg))
        return true;
    }
  return false;
}

/**
 * Traverse a subtree and invoke callbacks on all nodes
 *
 * This function traverses the sub-tree starting at node
 * and invokes a pre-order and a post-order callback on
 * each node. It considers the "enabled" state (ignores
 * disabled nodes by default) and does not visit children
 * of a node if the pre-order callback returns false.
 *
 * \param node           Device tree node the traversal shall start on
 * \param pre_order_cb   A callback function invoked before traversing
 *                       subtrees. The callback gets two arguments: the
 *                       current node and the current depth in the tree
 *                       (cb(Dtb::Node<ERR> const, int)). It should
 *                       return true, if the traversal shall visit child
 *                       nodes.
 * \param post_order_cb  A callback function invoked after traversing
 *                       the subtree. It gets the same arguments as the
 *                       pre_order_cb, return values are ignored.
 */
template <typename ERR>
template <typename PRE, typename POST>
void
Node<ERR>::scan_recursive(int depth,
                          PRE &&pre_order_cb, POST &&post_order_cb,
                          bool skip_disabled) const
{
  assert(is_valid());

  if (skip_disabled && !is_enabled())
    return;

  if (!pre_order_cb(*this, depth))
    return;

  // scan child nodes
  for (auto child_node = first_child_node();
       child_node.is_valid();
       child_node = child_node.sibling_node())
    child_node.scan_recursive(depth + 1, std::forward<PRE>(pre_order_cb),
                              std::forward<POST>(post_order_cb),
                              skip_disabled);

  post_order_cb(*this, depth);
}

/**
 * Traverse the device tree and invoke callbacks on all nodes
 *
 * This function invokes scan_node on the root node of the tree.
 */
template <typename ERR>
template <typename PRE, typename POST>
inline void
Tree<ERR>::scan(PRE &&pre_order_cb, POST &&post_order_cb,
                bool skip_disabled) const
{
  auto first = first_node();
  int depth = 0;
  first.scan_recursive(depth, std::forward<PRE>(pre_order_cb),
                       std::forward<POST>(post_order_cb), skip_disabled);
}

}
