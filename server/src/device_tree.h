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
public:
  Dt_node(void *dt, int node) : _tree(dt), _node(node) {}

  bool is_valid() const
  { return _node >= 0; }

  Dt_node next_node() const
  { return Dt_node(_tree, fdt_next_node(_tree, _node, nullptr)); }

  char const *get_name(int *length)
  { return fdt_get_name(_tree, _node, length); }

  void setprop_u32(char const *name, l4_uint32_t value) const
  {
    if (fdt_setprop_u32(_tree, _node, name, value) < 0)
      {
        Err().printf("cannot set property '%s' to '0x%x'\n", name, value);
        L4Re::chksys(-L4_EIO);
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
