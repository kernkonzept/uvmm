/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/error_helper>

#include "debug.h"

extern "C" {
#include <libfdt.h>
}

namespace Vdev {

class Dt_node
{
  enum
  {
    // Defaults according to include/linux/of.h, overridden with
    // address_cells = 2 for sparc
    Default_address_cells = 1,
    Default_size_cells = 1,
  };

public:
  Dt_node(void *dt, int node) : _tree(dt), _node(node) {}

  bool is_valid() const
  { return _node >= 0; }

  Dt_node next_node() const
  { return Dt_node(_tree, fdt_next_node(_tree, _node, nullptr)); }

  Dt_node parent_node() const
  { return Dt_node(_tree, fdt_parent_offset(_tree, _node)); }

  char const *get_name(int *length)
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

    // Spec says, that the address/size cells attribute should be
    // attached to the parent node, but Linux also checks the root
    // node and returns a default value if it doesn find a valid
    // attribute. We do the same here.
    if (val == -FDT_ERR_NOTFOUND)
      {
        auto root_node = Dt_node(_tree, 0); // Device_tree::first_node()
        val = root_node.get_cells_attrib(name);
        if (val >= 0)
          return val;

        if (val == -FDT_ERR_NOTFOUND)
          return default_cells;
      }

    Err().printf("Unable to lookup #address-cells: %d\n", val);
    L4Re::chksys(-L4_EIO);
    return 0;
  }

  size_t get_address_cells() const
  {
    return get_cells_attrib_default("#address-cells", Default_address_cells);
  }

  size_t get_size_cells() const
  {
    return get_cells_attrib_default("#size-cells", Default_size_cells);
  }

  void setprop_u32(char const *name, l4_uint32_t value) const
  {
    if (fdt_setprop_u32(_tree, _node, name, value) < 0)
      {
        Err().printf("cannot set property '%s' to '0x%x'\n", name, value);
        L4Re::chksys(-L4_EIO);
      }
  }

  void setprop_u64(char const *name, l4_uint64_t value) const
  {
    if (fdt_setprop_u64(_tree, _node, name, value) < 0)
      {
        Err().printf("cannot set property '%s' to '0x%llx'\n", name, value);
        L4Re::chksys(-L4_EIO);
      }
  }

  void setprop(char const *name, l4_uint64_t value, unsigned cells) const
  {
    switch (cells)
      {
      case 1:
        if (value >= (1ULL << 32))
          L4Re::chksys(-L4_ERANGE, "Value too large for property\n");

        setprop_u32(name, value);
        break;

      case 2:
        setprop_u64(name, value);
        break;

      default:
        L4Re::chksys(-L4_EINVAL, "Unexpected property value cell size");
        break;
    }
  }

  void setprop_string(char const *name, char const *value) const
  {
    if (fdt_setprop_string(_tree, _node, name, value) < 0)
      {
        Err().printf("cannot set property '%s' to '%s'\n", name, value);
        L4Re::chksys(-L4_EIO);
      }
  }

  void appendprop_u32(char const *name, l4_uint32_t value) const
  {
    if (fdt_appendprop_u32(_tree, _node, name, value) < 0)
      {
        Err().printf("cannot append '0x%x' to property '%s'\n", value, name);
        L4Re::chksys(-L4_EIO);
      }
  }

  void appendprop_u64(char const *name, l4_uint64_t value) const
  {
    if (fdt_appendprop_u64(_tree, _node, name, value) < 0)
      {
        Err().printf("cannot append '0x%llx' to property '%s'\n", value, name);
        L4Re::chksys(-L4_EIO);
      }
  }

  void appendprop(char const *name, l4_uint64_t value, unsigned cells) const
  {
    switch (cells)
      {
      case 1:
        if (value >= (1ULL << 32))
          L4Re::chksys(-L4_ERANGE, "Value too large for property\n");

        appendprop_u32(name, value);
        break;

      case 2:
        appendprop_u64(name, value);
        break;

      default:
        L4Re::chksys(-L4_EINVAL, "Unexpected property value cell size");
        break;
    }
  }

  bool is_enabled()
  {
    int lenp;
    char const *p = get_prop<char>("status", &lenp);
    if (!p)
      return true;

    return lenp > 2 && (!strncmp(p, "okay", lenp) || !strcmp(p, "ok"));
  }

  int is_compatible(const char *compatible) const
  { return fdt_node_check_compatible(_tree, _node, compatible); }

  void get_path(char *buf, int buflen) const
  {
    if (fdt_get_path(_tree, _node, buf, buflen) < 0)
      {
        Err().printf("cannot get path for node\n");
        L4Re::chksys(-L4_EINVAL);
      }
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
            {
              Err().printf("Specified value too large for 32bit systems.\n");
              L4Re::chksys(-L4_ERANGE);
            }
        break;

      default:
        Err().printf("Invalid value for address/size cell: %d\n", size);
        L4Re::chksys(-L4_ERANGE);
        val = 0;
        break;
      }
    return val;
  }

  /**
   * Get address/size pair from reg property
   *
   * \param[in]  index        Index of pair
   * \param[out] address      Store address in *address if address != 0
   * \param[out] size         Store size in *size if size != 0
   * \param[int] check_range  If true, check whether address/size fit into
   *                          l4_addr_t
   *
   * This function throws an exception if "reg" property does not exist
   * or the index is out of range
   */
  void get_reg_val(int index, l4_uint64_t *address, l4_uint64_t *size,
                   bool check_range = true) const
  {
    int addr_cells = get_address_cells();
    int size_cells = get_size_cells();
    int rsize = addr_cells + size_cells;

    auto *prop = check_prop<fdt32_t>("reg", rsize * (index+1));

    prop += rsize * index;
    if (address)
      *address = get_prop_val(prop, addr_cells, check_range);
    prop += addr_cells;
    if (size)
      *size = get_prop_val(prop, size_cells, check_range);
  }

  /**
   * Set address/size pair of reg property
   *
   * \param[in] address  Address value to store in reg pair
   * \param[in] size     Size value to store in reg pair
   *
   * This function throws an exception if "reg" property does not exist.
   */
  void
  set_reg_val(l4_uint64_t address, l4_uint64_t size, bool append = false) const
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
  void
  append_reg_val(l4_uint64_t address, l4_uint64_t size) const
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
  void
  set_prop_address(char const *property, l4_addr_t address) const
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

  template <typename T>
  T const *get_prop(char const *name, int *size) const
  {
    void const *p = fdt_getprop(_tree, _node, name, size);

    if (size)
      *size /= sizeof(T);

    return reinterpret_cast<T const *>(p);
  }

  template <typename T>
  T const *check_prop(char const *name, int size) const
  {
    int len;
    void const *prop = fdt_getprop(_tree, _node, name, &len);
    if (!prop)
      {
        char buf[256];
        if (fdt_get_path(_tree, _node, buf, sizeof(buf)) < 0)
          buf[0] = 0;
        Err().printf("could not get '%s' property of %s: %d\n", name, buf, len);
        L4Re::chksys(-L4_EINVAL);
      }

    if (len < (int) sizeof(T) * size)
      {
        char buf[256];
        if (fdt_get_path(_tree, _node, buf, sizeof(buf)) < 0)
          buf[0] = 0;
        Err().printf("'%s' property of %s is too small (%d need %u)\n",
                     name, buf, len, (unsigned) (sizeof(T) * size));
        L4Re::chksys(-L4_ERANGE);
      }

    return reinterpret_cast<T const *>(prop);
  }

  Dt_node find_irq_parent() const
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
          return Dt_node(_tree, node);
      }

    return Dt_node(_tree, -L4_ENODEV);
  }

private:
  void *_tree;
  int _node;
};

class Device_tree
{
public:
  explicit Device_tree(void *dt) : _tree(dt) {}

  void check_tree()
  {
    if (fdt_check_header(_tree) < 0)
      throw L4::Runtime_error(-L4_EINVAL, "Not a device tree");
  }

  unsigned size() const
  { return fdt_totalsize(_tree); }

  void add_to_size(l4_size_t padding) const
  { fdt_set_totalsize(_tree, fdt_totalsize(_tree) + padding); }

  Dt_node first_node()
  { return Dt_node(_tree, 0); }

  Dt_node invalid_node()
  { return Dt_node(_tree, -1); }

  /**
   * Return the node at the given path.
   *
   * \throws No node could be found for the path.
   */
  Dt_node path_offset(char const *path) const
  {
    int ret = fdt_path_offset(_tree, path);
    if (ret < 0)
      {
        Err().printf("cannot find node '%s'\n", path);
        L4Re::chksys(-L4_ENOENT);
      }

    return Dt_node(_tree, ret);
  }

  /**
   * Return the device tree node for the given handle.
   *
   * \return The node for the handle or an invalid node
   *         if phandle was not found.
   */
  Dt_node phandle_offset(l4_uint32_t phandle) const
  {
    int node = fdt_node_offset_by_phandle(_tree, phandle);
    return Dt_node(_tree, node);
  }

private:
  void *_tree;
};

}
