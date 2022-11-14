/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>

#include "device.h"
#include "libfdt.h"

struct OutputBin
{
  ~OutputBin()
  { free(_fdt); }

  void build(Tree *t)
  {
    _fdt = (char*)malloc(Default_size);
    if (!_fdt)
      throw Exception("out of memory");
    if (fdt_create_empty_tree(_fdt, Default_size))
      throw Exception("dt creation failed");

    build_int(t, "/", fdt_path_offset(_fdt, "/"));

    // Fix-up phandles
    for (auto const &a: _phandles)
      {
        int i = fdt_path_offset(_fdt, a.first.c_str());
        fdt_appendprop_u32(_fdt, i, "phandle", a.second);
      }

    fdt_pack(_fdt);
  }

  size_t size() const
  { return _fdt ? fdt_totalsize(_fdt) : 0; }

  const void *addr() const
  { return _fdt; }

private:
  enum
  {
    Default_size = 1 * 1024 * 1024
  };

  void build_int(Tree *t, const std::string &path, int node)
  {
    for (auto const &n: t->props())
      {
        switch (n.id())
          {
          case Prop::Empty:
            {
              fdt_setprop_empty(_fdt, node, n.name().c_str());
              break;
            }
          case Prop::Str:
            {
              auto const &v = n.as<std::string>();
              fdt_appendprop(_fdt, node, n.name().c_str(), v.c_str(),
                             v.size() + 1);
              break;
            }
          case Prop::StrVec:
            {
              for (auto const &w: n.as<std::vector<std::string>>())
                fdt_appendprop(_fdt, node, n.name().c_str(), w.c_str(),
                               w.size() + 1);
              break;
            }
          case Prop::Int:
            {
              fdt_appendprop_u32(_fdt, node, n.name().c_str(),
                                 n.as<unsigned>());
              break;
            }
          case Prop::IntVec:
            {
              for (auto const &w: n.as<std::vector<unsigned>>())
                fdt_appendprop_u32(_fdt, node, n.name().c_str(), w);
              break;
            }
          case Prop::Handle:
            {
              add_phandle(node, n.name(), n.as<std::string>());
              break;
            }
          case Prop::MixedVec:
            {
              std::vector<std::string> s;
              for (auto const &a: n.as<std::vector<Mixed_type>>())
                {
                  switch (a._type)
                    {
                    case Mixed_type::Int:
                      {
                        fdt_appendprop_u32(_fdt, node, n.name().c_str(),
                                           a.as<unsigned>());
                        break;
                      }
                    case Mixed_type::Handle:
                      {
                        add_phandle(node, n.name(), a.as<std::string>());
                        break;
                      }
                    case Mixed_type::Addr:
                      {
                        std::vector<unsigned> c;
                        t->to_addr({a.as<Addr_ref>()->addr()}, &c);
                        for (auto b: c)
                          fdt_appendprop_u32(_fdt, node, n.name().c_str(), b);
                        break;
                      }
                    case Mixed_type::Size:
                      {
                        std::vector<unsigned> c;
                        t->to_size({a.as<Size_ref>()->size()}, &c);
                        for (auto b: c)
                          fdt_appendprop_u32(_fdt, node, n.name().c_str(), b);
                        break;
                      }
                    }
                }
              break;
            }
          };
      }

    for (auto n = t->sections().rbegin(); n != t->sections().rend(); ++n)
      {
        int w = fdt_add_subnode(_fdt, node, (*n)->addr_name().c_str());
        build_int(*n, path + "/" + (*n)->name(), w);
      }
  }

  void add_phandle(int node, const std::string &name, const std::string &val)
  {
    auto i = _phandles.find(val);
    if (i == _phandles.end())
      {
        fdt32_t phandle = _max_phandle++;
        fdt_appendprop_u32(_fdt, node, name.c_str(), phandle);
        _phandles.insert({val, phandle});
      }
    else
      fdt_appendprop_u32(_fdt, node, name.c_str(), i->second);
  }

  std::map<std::string, fdt32_t> _phandles;
  char *_fdt = NULL;
  unsigned _max_phandle = 1;
};
