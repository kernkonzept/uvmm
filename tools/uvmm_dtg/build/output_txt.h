/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <string>
#include <cstdio>
#include <iomanip>

#include <iostream>

#include "device.h"

struct OutputTxt
{
  void build(Tree *t)
  {
    std::ostringstream ss;

    printi(0, ss, "/dts-v1/;");
    printi(0, ss, "/");
    printi(t, ss, 0);

    _res = ss.str();
  }

  size_t size() const
  { return _res.size(); }

  const void *addr()
  { return _res.c_str(); }

private:
  void printi(size_t i, std::ostringstream &ss, const std::string s)
  {
    if (i > 0)
      ss << std::setw(i*2) << " ";
    ss << s << std::endl;
  }

  void printi(Tree *t, std::ostringstream &ss, size_t i = 0)
  {
    std::string path = t->addr_name();
    if (!t->alias().empty())
      path = t->alias() + ": " + t->addr_name();
    if (t->props().empty() && t->sections().empty())
      printi(i, ss, path + " { };");
    else
      {
        printi(i, ss, path);
        printi(i, ss, "{");

        for (auto const &n: t->props())
          {
            switch (n.id())
              {
              case Prop::Empty:
                {
                  printi(i + 1, ss, n.name() + ";");
                  break;
                }
              case Prop::Str:
                {
                  printi(i + 1, ss,
                         n.name() + " = \"" + n.as<std::string>() + "\";");
                  break;
                }
              case Prop::StrVec:
                {
                  printi(i + 1, ss,
                         n.name() + " = "
                         + string_list(n.as<std::vector<std::string>>()) + ";");
                  break;
                }
              case Prop::Int:
                {
                  printi(i + 1, ss,
                         n.name() + " = <0x" + to_string(n.as<unsigned>(),
                                                         std::hex) + ">;");
                  break;
                }
              case Prop::IntVec:
                {
                  printi(i + 1, ss,
                         n.name() + " = "
                         + int_list(n.as<std::vector<unsigned>>()) + ";");
                  break;
                }
              case Prop::Handle:
                {
                  auto handle = t->section(n.as<std::string>());
                  if (handle)
                    printi(i + 1, ss,
                           n.name() + " = <&" + handle->name_or_alias() + ">;");
                  else
                    printf("handle error for %s\n", n.name().c_str());
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
                            s.emplace_back("0x" + to_string(a.as<unsigned>(),
                                                            std::hex));
                            break;
                          }
                        case Mixed_type::Handle:
                          {
                            auto handle = t->section(a.as<std::string>());
                            s.emplace_back("&" + handle->name_or_alias());
                            break;
                          }
                        case Mixed_type::Addr:
                          {
                            std::vector<unsigned> c;
                            t->to_addr({a.as<Addr_ref>()->addr()}, &c);
                            for (auto b: c)
                              s.emplace_back("0x" + to_string(b, std::hex));
                            break;
                          }
                        case Mixed_type::Size:
                          {
                            std::vector<unsigned> c;
                            t->to_size({a.as<Size_ref>()->size()}, &c);
                            for (auto b: c)
                              s.emplace_back("0x" + to_string(b, std::hex));
                            break;
                          }
                        }
                    }
                  printi(i + 1, ss, n.name() + " = " + int_list(s) + ";");
                  break;
                }
              };
          }
        for (auto n: t->sections())
          printi(n, ss, i + 1);
        printi(i, ss, "};");
      }
  }

  std::string _res;
};
