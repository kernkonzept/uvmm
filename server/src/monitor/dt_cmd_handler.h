/*
 * Copyright (C) 2019-2020 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <algorithm>
#include <cstdio>
#include <stack>
#include <vector>

#include <l4/sys/l4int.h>

extern "C" {
#include <libfdt.h>
}

#include "device_tree.h"
#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Dtb {

class Property
{
public:
  enum Value_type
  {
    Prop_novalue,
    Prop_stringlist,
    Prop_string,
    Prop_uint8_array,
    Prop_uint32_array
  };

  Property(Dtb::Fdt *fdt, int node, struct fdt_property const *prop)
  : _fdt(fdt),
    _node(node),
    _prop(prop)
  {}

  template<typename T>
  static std::vector<Property> get_all(T const &node)
  {
    std::vector<Property> properties;

    int offset;
    fdt_for_each_property_offset(offset, node._fdt->dt(), node._node)
      {
        properties.emplace_back(
          node._fdt, node._node,
          fdt_get_property_by_offset(node._fdt->dt(), offset, nullptr));
      }

    return properties;
  }

  char const *get_name() const
  { return fdt_get_string(_fdt->dt(), fdt32_ld(&_prop->nameoff), nullptr); }

  Value_type get_value_type() const
  {
    // unfortunately we have to make a guess here as this information is not
    // encoded in the device tree itself

    l4_uint32_t len = length();

    if (len == 0)
      return Prop_novalue;

    // the value of the 'compatible' property is always a list of strings
    if (is_compatible_property())
      return Prop_stringlist;

    // otherwise, if the property value is zero terminated and otherwise
    // contains no zero characters, it is most likely a string
    bool is_string = true;

    if (data()[len - 1] != '\0')
      is_string = false;
    else
      is_string = !memchr(data(), 0, len - 1);

    if (is_string)
      return Prop_string;

    // any non-string property value is interpreted as a sequence of bytes or
    // 32bit unsigned integers, depending on whether its length is divisible by
    // four, there seems to be no more reliable way of deciding this
    return len % 4 == 0 ? Prop_uint32_array : Prop_uint8_array;
  }

  std::vector<char const *> get_stringlist() const
  {
    std::vector<char const *> values;

    char const *name = get_name();
    for (int i = 0; i < fdt_stringlist_count(_fdt->dt(), _node, name); ++i)
      {
        values.push_back(
          fdt_stringlist_get(_fdt->dt(), _node, name, i, nullptr));
      }

    return values;
  }

  char const *get_string() const
  { return data(); }

  template<typename T>
  std::vector<T> get_array() const
  {
    std::vector<T> values;

    T const *arr = reinterpret_cast<T const *>(data());

    for (auto i = 0u; i < length() / sizeof(T); ++i)
      values.push_back(arr[i]);

    return values;
  }

private:
  bool is_compatible_property() const
  { return strcmp(get_name(), "compatible") == 0; }

  char const *data() const
  { return _prop->data; }

  l4_uint32_t length() const
  { return fdt32_ld(&_prop->len); }

  Dtb::Fdt *_fdt;
  int _node;
  struct fdt_property const *_prop;
};

} // namespace Dtb

namespace Monitor {

template<bool, typename T>
class Dt_cmd_handler {};

template<typename T>
class Dt_cmd_handler<true, T> : public Cmd
{
public:
  Dt_cmd_handler()
  { register_toplevel("dt"); }

  char const *help() const override
  { return "Device tree source"; }

  void exec(FILE *f, Arglist *) override
  { decompile(f); }

private:
  void decompile(FILE *f) const
  {
    auto *dt = host_dt();

    if (!dt->valid())
      {
        fprintf(f, "No device tree loaded\n");
        return;
      }

    // print header
    fprintf(f, "/dts-v1/;\n\n");

    // prepare node stack
    auto root(dt->get().first_node());

    std::stack<decltype(root)> nodes;
    nodes.push(root);

    // indent/dedent helper methods
    int current_depth = 0;
    int last_depth = -1;

    auto indent = [&](int depth)
    {
      fprintf(f, "%*s", depth * 4, "");
    };

    auto close = [&](int depth)
    {
      current_depth = depth;
      if (current_depth <= last_depth)
        {
          for (int depth = last_depth; depth >= current_depth; --depth)
            {
              indent(depth);
              fprintf(f, "};\n");
            }
        }

      if (depth > 0)
        fputc('\n', f);

      last_depth = current_depth;
    };

    // print device tree
    while (!nodes.empty())
      {
        auto node(nodes.top());
        nodes.pop();

        if (!node.is_valid())
          continue;

        // print closing braces after returning from a more deeply nested level
        close(node.get_depth());

        // print node name
        indent(current_depth);
        fprintf(f, "%s {\n", node.get_name());

        // print node properties
        auto properties(Dtb::Property::get_all(node));
        std::sort(properties.begin(),
                  properties.end(),
                  sort_named<Dtb::Property>);

        for (auto const &prop : properties)
          {
            // property name
            indent(current_depth + 1);
            fprintf(f, "%s", prop.get_name());

            // property value(s)
            switch (prop.get_value_type())
              {
              case Dtb::Property::Prop_novalue:
                fprintf(f, ";\n");
                break;
              case Dtb::Property::Prop_stringlist:
                {
                  auto values(prop.get_stringlist());

                  fprintf(f, " = \"%s\"", values[0]);
                  for (auto i = 1u; i < values.size(); ++i)
                    fprintf(f, ", \"%s\"", values[i]);

                  fprintf(f, ";\n");
                }
                break;
              case Dtb::Property::Prop_string:
                fprintf(f, " = \"%s\";\n", prop.get_string());
                break;
              case Dtb::Property::Prop_uint8_array:
                {
                  auto values(prop.template get_array<l4_uint8_t>());

                  fprintf(f, " = [");

                  fprintf(f, "0x%0x", values[0]);
                  for (auto i = 1u; i < values.size(); ++i)
                    fprintf(f, " 0x%0x", values[i]);

                  fprintf(f, "];\n");
                }
                break;
              case Dtb::Property::Prop_uint32_array:
                {
                  auto values(prop.template get_array<l4_uint32_t>());

                  fprintf(f, " = <");

                  fprintf(f, "0x%0x", fdt32_to_cpu(values[0]));
                  for (auto i = 1u; i < values.size(); ++i)
                    fprintf(f, " 0x%0x", fdt32_to_cpu(values[i]));

                  fprintf(f, ">;\n");
                }
                break;
              }
          }

        // add nodes children to stack in alphabetical order
        if (node.has_children())
          {
            std::vector<decltype(node)> children;

            auto child(node.first_child_node());
            while (child.is_valid())
              {
                children.push_back(child);
                child = child.sibling_node();
              }

            std::sort(children.begin(),
                      children.end(),
                      sort_named<decltype(node)>);

            for (auto it = children.rbegin(); it != children.rend(); ++it)
              nodes.push(*it);
          }
      }

    close(0);
  }

  template<typename U>
  static int sort_named(U const &a, U const &b)
  { return strcmp(a.get_name(), b.get_name()) < 0; }

  T const *host_dt() const
  { return static_cast<T const *>(this); }
};

} // namespace Monitor
