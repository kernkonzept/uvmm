/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/l4int.h>
#include <utility>

extern "C" {
#include <libfdt.h>
}

#include "cell.h"

namespace Dtb {

template<typename ERR>
class Node
{
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
  Node(void *dt, int node) : _tree(dt), _node(node) {}

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
  { return Node(_tree, fdt_add_subnode(_tree, _node, name)); }

  /**
   * Delete a node
   *
   * \return 0 on success, negative fdt_error otherwise
   */
  int del_node()
  {
    int res = fdt_del_node(_tree, _node);
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
  { return Node(_tree, fdt_next_node(_tree, _node, depth)); }

  /**
   * Get the next compatible node of this tree
   *
   * \param  compatible 'compatible' string to match against
   *
   * \return Next compatible node of the tree or an invalid node (node
   *         offset equals the libfdt error)
   */
  Node next_compatible_node(char const *compatible) const
  { return Node(_tree, fdt_node_offset_by_compatible(_tree, _node, compatible)); }

  /**
   * Get the first child node
   *
   * \return node The first child node or an invalid node (node offset
   *              equals the libfdt error)
   */
  Node first_child_node() const
  { return Node(_tree, fdt_first_subnode(_tree, _node)); }

  /**
   * Get the next sibling
   *
   * \return node The next sibling or an invalid node (node offset
   *              equals the libfdt error)
   */
  Node sibling_node() const
  { return Node(_tree, fdt_next_subnode(_tree, _node)); }

  Node parent_node() const
  { return Node(_tree, fdt_parent_offset(_tree, _node)); }

  bool is_root_node() const
  { return _node == 0; };

  bool has_children() const
  { return fdt_first_subnode(_tree, _node) >= 0; }

  char const *get_name(int *length = nullptr) const
  { return fdt_get_name(_tree, _node, length); }

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

  size_t get_cells_attrib_default(const char *name, int default_cells) const
  {
    int val = parent_node().get_cells_attrib(name);
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
        auto root_node = Node(_tree, 0); // Tree::first_node()
        val = root_node.get_cells_attrib(name);
        if (val >= 0)
          return val;

        if (val == -FDT_ERR_NOTFOUND)
          return default_cells;
      }

    ERR(this, "Unable to lookup %s: %s", name, fdt_strerror(val));
    return default_cells;
  }

  size_t get_address_cells() const
  { return get_cells_attrib_default("#address-cells", Default_address_cells); }

  size_t get_size_cells() const
  { return get_cells_attrib_default("#size-cells", Default_size_cells); }

  void setprop_u32(char const *name, l4_uint32_t value) const
  {
    int r = fdt_setprop_u32(_tree, _node, name, value);
    if (r < 0)
      ERR(this, "cannot set property '%s' to '0x%x': %s", name, value,
          fdt_strerror(r));
  }

  void setprop_u64(char const *name, l4_uint64_t value) const
  {
    int r = fdt_setprop_u64(_tree, _node, name, value);
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
    int r = fdt_setprop_string(_tree, _node, name, value);
    if (r < 0)
      ERR(this, "cannot set property '%s' to '%s'", name, value);
  }

  void setprop_data(char const *name, void const *data, int len) const
  {
    int r = fdt_setprop(_tree, _node, name, data, len);
    if (r < 0)
      ERR(this, "cannot set property '%s'", name);
  }

  void appendprop_u32(char const *name, l4_uint32_t value) const
  {
    int r = fdt_appendprop_u32(_tree, _node, name, value);
    if (r < 0)
      ERR(this, "cannot append '0x%x' to property '%s': %s", value, name,
          fdt_strerror(r));
  }

  void appendprop_u64(char const *name, l4_uint64_t value) const
  {
    int r = fdt_appendprop_u64(_tree, _node, name, value);
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
  int delprop(char const *name)
  { return fdt_delprop(_tree, _node, name); }

  bool is_enabled() const
  {
    int lenp;
    char const *p = get_prop<char>("status", &lenp);
    if (!p)
      return true;

    return lenp > 2 && (!strncmp(p, "okay", lenp) || !strcmp(p, "ok"));
  }

  bool has_prop(char const *name) const
  { return fdt_getprop(_tree, _node, name, nullptr) != nullptr; }

  bool has_compatible() const
  { return has_prop("compatible"); }

  bool is_compatible(char const *compatible) const
  { return fdt_node_check_compatible(_tree, _node, compatible) == 0; }

  void get_path(char *buf, int buflen) const
  {
    int r = fdt_get_path(_tree, _node, buf, buflen);
    if (r < 0)
      ERR(this, r, "cannot get path for node");
  }

  l4_uint32_t get_phandle() const
  { return fdt_get_phandle(_tree, _node); }

  int stringlist_count(char const *property) const
  { return fdt_stringlist_count(_tree, _node, property); }

  char const *stringlist_get(char const *property, int index, int *lenp) const
  { return fdt_stringlist_get(_tree, _node, property, index, lenp); }

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

  /**
   * Get address/size pair from reg property
   *
   * \param[in]  index             Index of pair
   * \param[out] address           Store address in *address if address != 0
   * \param[out] size              Store size in *size if size != 0
   * \param[int] check_range       If true, check whether address/size fit into
   *                               l4_addr_t
   * \retval -ERR_BAD_INDEX        node does not have a reg entry with the
   *                               specified index
   * \retval -ERR_RANGE            a reg value does not fit into a 64bit value
   * \retval -ERR_NOT_TRANSLATABLE reg entry exists, but is not translatable
   * \retval <0                    other fdt related errors
   * \retval 0                     ok
   *
   * This function throws an exception if "reg" property does not exist
   * or the index is out of range
   */
  int get_reg_val(int index, l4_uint64_t *address, l4_uint64_t *size) const
  {
    size_t addr_cells = get_address_cells();
    size_t size_cells = get_size_cells();
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

    Reg reg{Cell{prop, addr_cells}, Cell(prop + addr_cells, size_cells)};
    bool res = translate_reg(&reg);

    if (!reg.address.is_uint64() || !reg.size.is_uint64())
      return -ERR_RANGE;

    if (address)
      *address = reg.address.get_uint64();
    if (size)
      *size = reg.size.get_uint64();

    return res ? 0 : -ERR_NOT_TRANSLATABLE;
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
    if (append)
      appendprop("reg", address, get_address_cells());
    else
      setprop("reg", address, get_address_cells());

    appendprop("reg", size, get_size_cells());
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
   * This function checks whether the node has an "interrupts" property.
   *
   * \return True if there is an "interrupts" property.
   */
  bool has_irqs() const
  { return get_prop<fdt32_t>("interrupts", nullptr) != nullptr; }


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
   * Check whether a node has irq or mmio resources associated
   *
   * This function checks whether the node has "reg" or "interrupts"
   * properties and any of the reg property values are mapped to mmio
   * resources on the root bus.
   *
   * \return True if there are irq or mmio resources
   */
  bool needs_vbus_resources() const
  { return has_irqs() || has_mmio_regs(); }

  /**
   * Translate a reg entry
   *
   * Reg entries are bus local information. To get an address valid on
   * the "root bus" we have to traverse the tree and translate the reg
   * entry using ranges properties. If we reach the root node, the
   * translation was successfull and reg contains the translated
   * address. If any of the intermediate nodes is unable to translate
   * the reg, the translation fails and reg is not changed.
   *
   * \param[inout] reg Pointer to reg structures which shall be
   *                   translated. If the translation was successful,
   *                   *reg contains the translated values.
   * \return True if the translation was successful.
   */
  bool translate_reg(Reg *reg) const
  {
    if (is_root_node())
      return true;

    Cell tmp{reg->address};
    if (!translate_reg(&tmp, reg->size))
      return false;

    reg->address = tmp;
    return true;
  }

  template <typename T>
  T const *get_prop(char const *name, int *size) const
  {
    void const *p = fdt_getprop(_tree, _node, name, size);

    if (p && size)
      *size /= sizeof(T);

    return reinterpret_cast<T const *>(p);
  }

  template <typename T>
  T const *check_prop(char const *name, int size) const
  {
    int len;
    void const *prop = fdt_getprop(_tree, _node, name, &len);
    if (!prop)
      ERR(this, "could not get '%s' property of %s: %d", name);

    if (len < (int) sizeof(T) * size)
      ERR(this, "property %s is too small (%d need %u)",
          name, (unsigned) (sizeof(T) * size));

    return reinterpret_cast<T const *>(prop);
  }

  Node find_irq_parent() const
  {
    int node = _node;

    while (node >= 0)
      {
        auto *prop = fdt_getprop(_tree, node, "interrupt-parent", nullptr);
        if (prop)
          {
            auto *phdl = reinterpret_cast<fdt32_t const *>(prop);
            node = fdt_node_offset_by_phandle(_tree, fdt32_to_cpu(phdl[0]));
          }
        else
          node = fdt_parent_offset(_tree, node);

        if (node >= 0 && fdt_getprop(_tree, node, "#interrupt-cells", nullptr))
          return Node(_tree, node);
      }

    return Node(_tree, -1);
  }

  template <typename PRE, typename POST>
  void scan_recursive(int depth,
                      PRE &&pre_order_cb, POST &&post_order_cb,
                      bool skip_disabled = true) const;

private:
  /**
   * Translate a (address, size) cell pair
   *
   * Reg entries are bus local information. To get an address valid on
   * the "root bus" we have to traverse the tree and translate the reg
   * entry using ranges properties. If we reach the root node, the
   * translation was successfull and reg contains the translated
   * address. If any of the intermediate nodes is unable to translate
   * the reg, the translation fails and reg is not changed.
   *
   * \param[inout] address Pointer to address cell which shall be
   *                       translated. If the translation was
   *                       successful, *address contains the
   *                       translated values.
   * \param[in] size       Size cell describing the size of the region
   * \return True if the translation was successful.
   */
  bool translate_reg(Cell *address, Cell const &size) const;

  void *_tree;
  int _node;
};

template<typename ERR>
class Tree
{
public:
  typedef Dtb::Node<ERR> Node;
  explicit Tree(void *dt) : _tree(dt) {}

  void check_tree()
  {
    if (fdt_check_header(_tree) < 0)
      ERR("Not a device tree");
  }

  unsigned size() const
  { return fdt_totalsize(_tree); }

  void add_to_size(l4_size_t padding) const
  { fdt_set_totalsize(_tree, fdt_totalsize(_tree) + padding); }

  Node first_node() const
  { return Node(_tree, 0); }

  /**
   * Get the first compatible node of this tree
   *
   * \param  compatible 'compatible' string to match against
   *
   * \return First compatible node of the tree or an invalid node (node
   *         offset equals the libfdt error)
   */
  Node first_compatible_node(char const *compatible) const
  { return Node(_tree, fdt_node_offset_by_compatible(_tree, -1, compatible)); }

  /**
   * Return the node at the given path.
   *
   * \throws No node could be found for the path.
   */
  Node path_offset(char const *path) const
  {
    int ret = fdt_path_offset(_tree, path);
    if (ret < 0)
      ERR("cannot find node '%s'", path);

    return Node(_tree, ret);
  }

  /**
   * Return the device tree node for the given handle.
   *
   * \return The node for the handle or an invalid node
   *         if phandle was not found.
   */
  Node phandle_offset(l4_uint32_t phandle) const
  {
    int node = fdt_node_offset_by_phandle(_tree, phandle);
    return Node(_tree, node);
  }

  template <typename PRE, typename POST>
  void scan(PRE &&pre_order_cb, POST &&post_order_cb,
            bool skip_disabled = true) const;

private:
  void *_tree;
};

template<typename ERR>
bool
Node<ERR>::translate_reg(Cell *address, Cell const &size) const
{
  auto parent = parent_node();
  if (parent.is_root_node())
    return true;

  int prop_size;
  auto prop = parent.template get_prop<fdt32_t>("ranges", &prop_size);
  if (!prop)
    return false; // no translation possible

  if (!prop_size)
    return true; // Ident mapping

  auto child_addr = get_address_cells();
  auto parent_addr = parent.get_address_cells();
  auto child_size = get_size_cells();

  unsigned range_size = child_addr + parent_addr + child_size;
  if (prop_size % range_size != 0)
    ERR("%s: Unexpected property size %d/%d/%d vs %d",
        get_name(), child_addr, parent_addr, child_size,
        prop_size);

  for (auto end = prop + prop_size; prop < end; prop += range_size)
    {
      Range range{Cell(prop, child_addr),
                  Cell(prop + child_addr, parent_addr),
                  Cell(prop + child_addr + parent_addr, child_size)};
      if (range.translate(address, size))
        return parent.translate_reg(address, size);
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

  unsigned addr_cells = get_address_cells();
  unsigned size_cells = get_size_cells();
  unsigned reg_size = addr_cells + size_cells;
  unsigned num_regs = prop_size/reg_size;

  if (prop_size % reg_size != 0)
    ERR(this, "Unexpected property size %d/%d vs %d",
        addr_cells, size_cells, reg_size);

  for (unsigned i = 0; i < num_regs; ++i, prop += reg_size)
    {
      Reg reg{Cell{prop, addr_cells}, Cell(prop + addr_cells, size_cells)};
      if (translate_reg(&reg))
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
