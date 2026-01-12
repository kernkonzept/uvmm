/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include <sstream>
#include <iterator>
#include <stdarg.h>
#include <map>
#include <set>
#include <limits>

#include <iostream>

#include "const.h"
#include "algh.h"
#include "generic.h"

// Generic dt property class
//
// It can save the types in "Type" all in an generic class. This class can then
// be saved in a std container.
struct Prop: Shared_value
{
  enum Type
  {
    Empty,
    Int,
    IntVec,
    Str,
    StrVec,
    Handle,
    MixedVec,
  };

  Prop(std::string &&name)
  : _name(std::move(name)),
    _id(Empty)
  {}

  template <typename T>
  Prop(std::string &&name, Type id, const T &val)
  : Shared_value(val),
    _name(std::move(name)),
    _id(id)
  {}

  template <typename T>
  Prop(std::string &&name, Type id, T &&val)
  : Shared_value(std::move(val)),
    _name(std::move(name)),
    _id(id)
  {}

  const std::string &name() const { return _name; }
  Type id() const { return _id; }

private:
  std::string _name;
  Type _id;
};

enum
{
  INVALID_ADDR = ~0ULL
};

struct Region_mapper
{
  struct Region
  {
    Region(uint64_t addr, uint64_t size)
    : _a(addr),
      _s(size)
    {}

    bool operator < (Region const &o) const
    { return (_a + _s - 1) < o._a; }

    uint64_t _a;
    uint64_t _s;
  };

  Region_mapper(uint64_t min, uint64_t max)
  : _min(min),
    _max(max)
  {}

  void add_addr(uint64_t addr, uint64_t size)
  {
    auto e = _map.insert({addr, size});
    if (!e.second)
      throw Exception("address [0x" +
                      to_string(addr, std::hex) + ", 0x" +
                      to_string(size, std::hex) + "] already in use");
  }

  uint64_t next_addr(uint64_t size, uint32_t align, uint64_t min, uint64_t max)
  {
    Exception error("could not find a free address");

    if (size == 0)
      throw error;

    uint64_t a = std::max(_min, min);
    max = std::min(_max, max);

    a = round_size(a, align);
    if (a + size - 1 > max)
      throw error;

    for (;;)
      {
        auto n = _map.find(Region(a, a + size - 1));
        if (n == _map.end())
          return a;

        a = (*n)._a + (*n)._s - 1;
        if (a >= max)
          throw error;

        a = a + 1;
        a = round_size(a, align);
        if (a >= max)
          throw error;

        if (a + size - 1 > max)
          throw error;
      }

    throw error;
  }

  uint64_t _min;
  uint64_t _max;
  std::set<Region> _map;
};

struct Addr_type
{
  Addr_type(uint64_t addr, uint64_t size, uint32_t align,
            Region_mapper *rm = nullptr,
            uint64_t min = std::numeric_limits<uint64_t>::min(),
            uint64_t max = std::numeric_limits<uint64_t>::max())
  : _addr(addr),
    _size(size),
    _align(align),
    _min(min),
    _max(max),
    _rm(rm)
  {
    if (addr != INVALID_ADDR && _rm)
      _rm->add_addr(addr, size);
  }

  Addr_type(uint64_t addr, uint64_t size, Region_mapper *rm = nullptr,
            uint64_t min = std::numeric_limits<uint64_t>::min(),
            uint64_t max = std::numeric_limits<uint64_t>::max())
  : Addr_type(addr, size, 12, rm, min, max)
  {}

  Addr_type(uint64_t size, Region_mapper *rm = nullptr,
            uint64_t min = std::numeric_limits<uint64_t>::min(),
            uint64_t max = std::numeric_limits<uint64_t>::max())
  : Addr_type(INVALID_ADDR, size, 12, rm, min, max)
  {}

  uint64_t addr() const
  {
    if (_addr == INVALID_ADDR && _rm)
      {
        _addr = _rm->next_addr(_size, _align, _min, _max);
        _rm->add_addr(_addr, _size);
      }
    return _addr;
  }

  uint64_t size() const
  { return _size; }

protected:
  mutable uint64_t _addr;
  uint64_t _size;
  uint32_t _align;
  uint64_t _min;
  uint64_t _max;
  Region_mapper *_rm;
};

struct Addr_ref: std::shared_ptr<Addr_type>
{
  Addr_ref(std::shared_ptr<Addr_type> a)
  : std::shared_ptr<Addr_type>(a)
  {}
};

struct Size_ref: std::shared_ptr<Addr_type>
{
  Size_ref(std::shared_ptr<Addr_type> a)
  : std::shared_ptr<Addr_type>(a)
  {}
};

struct Mixed_type: Shared_value
{
  enum Type
  {
    Int,
    Handle,
    Addr,
    Size
  };

  Mixed_type(const unsigned &val)
  : Shared_value(val),
    _type(Int)
  {}

  Mixed_type(const std::string &val)
  : Shared_value(val),
    _type(Handle)
  {}

  Mixed_type(std::string &&val)
  : Shared_value(std::move(val)),
    _type(Handle)
  {}

  Mixed_type(Addr_ref &&val)
  : Shared_value(std::move(val)),
    _type(Addr)
  {}

  Mixed_type(Size_ref &&val)
  : Shared_value(std::move(val)),
    _type(Size)
  {}

  Type _type;
};

inline std::vector<Mixed_type>& operator +=(std::vector<Mixed_type>& v1,
                                            const std::vector<Mixed_type>& v2)
{
  v1.insert(v1.end(), v2.begin(), v2.end());
  return v1;
}

inline std::vector<Mixed_type>& operator +=(std::vector<Mixed_type>& v1,
                                            std::vector<Mixed_type> &&v2)
{
  v1.insert(v1.end(), std::make_move_iterator(v2.begin()),
                      std::make_move_iterator(v2.end()));
  return v1;
}

inline std::vector<Mixed_type>& operator +=(std::vector<Mixed_type>& v1,
                                           const std::vector<unsigned>& v2)
{
  v1.insert(v1.end(), v2.begin(), v2.end());
  return v1;
}


// Internal dt representation
struct Tree
{
  Tree(const Arch &arch, Region_mapper *rm)
  : _arch(arch),
    _rm(rm)
  {
    _root = this;
    add_default_cells();
    add_str_property("model", "L4 VM");
    add_compatible({"l4,virt", "linux,dummy-virt"});
    add_section("chosen");
    add_section("aliases");
  }
 
  Tree(Tree *parent, const std::string &name, const std::string &alias)
  : _name(name),
    _alias(alias),
    _arch(parent->_arch),
    _parent(parent),
    _root(parent->_root),
    _acells(parent->_acells),
    _scells(parent->_scells),
    _rm(parent->_rm)
  {}

  Tree *root() const { return _root; }
  Tree *parent() const { return _parent; }
  bool is_root() const { return _root == this; }
  bool is_arch(int arch) const { return _arch.arch == arch; }

  const std::string name() const
  { return _name; }
  const std::string addr_name() const
  { return _pos ? (_name + "@" + to_string(_pos->addr(), std::hex)) : _name; }
  const std::string &name_or_alias() const
  { return _alias.empty() ? _name : _alias; }
  const std::string &alias() const { return _alias; }

  const std::string path() const
  { return is_root() ? "" : parent()->path() + "/" + name(); }

  const std::string addr_path() const
  { return is_root() ? "" : parent()->path() + "/" + addr_name(); }

  const std::vector<Prop> & props() const { return _props; };
  const std::vector<Tree*> & sections() const { return _sections; };

  Tree *l4vmm()
  {
    auto l4vmm = section("/l4vmm");
    if (!l4vmm)
      {
        l4vmm = root()->add_section("l4vmm", "l4vmm");
        l4vmm->add_default_cells();
        l4vmm->add_compatible("simple-bus");
        l4vmm->add_empty_property("ranges");
      }

    return l4vmm;
  }

  Tree *section(const std::string &path)
  {
    if (path == "/")
      return root();

    Tree *t = root();
    auto s = split(path, "/");
    for (auto a: s)
      {
        auto e = t->_tree.find(a);
        if (e != t->_tree.end())
          t = e->second;
        else
          return nullptr;
      }
    return t;
  }

  Tree *add_section(const std::string &name, const std::string &alias = "",
                    int addr = -1, int size = -1)
  {
    auto e = _tree.find(name);
    if (e != _tree.end())
      return (*e).second;

    auto t = new Tree(this, name, alias);
    if (addr != -1)
      t->add_address_cells(addr);
    if (size != -1)
      t->add_size_cells(size);
    if (!alias.empty())
      _aliases.push_back(t);
    _tree.insert({name, t});
    _sections.push_back(t);
    return t;
  }

  void add_empty_property(std::string &&name)
  { _props.emplace_back(std::move(name)); }

  void add_str_property(std::string &&name, const std::string &prop)
  { _props.emplace_back(std::move(name), Prop::Str, prop); }

  void add_str_property(std::string &&name, std::string &&prop)
  { _props.emplace_back(std::move(name), Prop::Str, std::move(prop)); }

  void add_str_property(std::string &&name,
                        std::initializer_list<std::string> &&prop)
  { _props.emplace_back(std::move(name), Prop::StrVec,
                        (std::vector<std::string>)prop); }

  void add_num_property(std::string &&name, unsigned prop)
  { add_num_property(std::move(name), { prop }); }

  void add_num_property(std::string &&name,
                        std::initializer_list<unsigned> &&prop)
  { _props.emplace_back(std::move(name), Prop::IntVec,
                        (std::vector<unsigned>)prop); }

  void add_num_property(std::string &&name, std::vector<unsigned> &&prop)
  { _props.emplace_back(std::move(name), Prop::IntVec,
                        std::move(prop)); }

  void add_num_property(std::string &&name, const std::vector<Mixed_type> &prop)
  { _props.emplace_back(std::move(name), Prop::MixedVec, prop); }

  void add_num_property(std::string &&name, std::vector<Mixed_type> &&prop)
  { _props.emplace_back(std::move(name), Prop::MixedVec,
                        std::move(prop)); }

  void add_handle_property(std::string &&name, const std::string &prop)
  { _props.emplace_back(std::move(name), Prop::Handle, prop); }

  void add_reg_property(std::initializer_list<Addr_type> &&prop)
  {
    std::vector<Mixed_type> reg;
    for (auto &&a: prop)
      {
        auto b = std::make_shared<Addr_type>(std::move(a));
        if (!_pos) // have we already stored a position reference?
          _pos = b;
        reg += {Addr_ref(b), Size_ref(b)};
      }
    add_num_property("reg", std::move(reg));
  }

  void add_reg_property(Addr_type &&prop)
  { add_reg_property({ std::move(prop) }); }

  void add_position(const std::shared_ptr<Addr_type> &pos)
  { _pos = pos; }

  void add_default_cells()
  {
    add_address_cells(_arch.acells);
    add_size_cells(_arch.scells);
  }

  void add_address_cells(int prop)
  {
    _acells = prop;
    add_num_property("#address-cells", prop);
  }

  void add_size_cells(int prop)
  {
    _scells = prop;
    add_num_property("#size-cells", prop);
  }

  void add_interrupt_cells(int prop)
  { add_num_property("#interrupt-cells", prop); }

  void add_compatible(std::string&& prop)
  { add_str_property("compatible", std::move(prop)); }

  void add_compatible(std::initializer_list<std::string> &&prop)
  { add_str_property("compatible", std::move(prop)); }

  void add_device_type(std::string &&prop)
  { add_str_property("device_type", std::move(prop)); }

  void to_addr(std::initializer_list<std::uint64_t> &&prop,
               std::vector<unsigned> *v)
  {
    unsigned cells = _parent ? _parent->_acells : root()->_acells;
    for (auto a: prop)
      {
        if (cells > 1)
          v->insert(v->end(), { unsigned(a >> 32), (unsigned)a });
        else
          {
            if (a > std::numeric_limits<uint32_t>::max())
              throw Exception("addr 0x" + to_string(a, std::hex) + " is too big");
            v->insert(v->end(), { (unsigned)a });
          }
      }
  }

  void to_size(std::initializer_list<std::uint64_t> &&prop,
               std::vector<unsigned> *v)
  {
    unsigned cells = _parent ? _parent->_scells : root()->_scells;
    for (auto a: prop)
      {
        if (cells > 1)
          v->insert(v->end(), { unsigned(a >> 32), (unsigned)a });
        else
          {
            if (a > std::numeric_limits<uint32_t>::max())
              throw Exception("size 0x" + to_string(a, std::hex) + " is too big");
            v->insert(v->end(), { (unsigned)a });
          }
      }
  }

  void finalize()
  {
    if (!_aliases.empty())
      {
        auto a = add_section("aliases");
        for (auto b: _aliases)
          a->add_str_property(std::string(b->alias()), b->addr_path());
      }
  }

  Region_mapper *rm()
  { return _rm; }

private:
  std::string _name;
  std::string _alias;
  Arch _arch;
  Tree *_parent = nullptr;
  Tree *_root = nullptr;

  std::vector<Prop> _props;
  std::vector<Tree*> _sections;
  static std::vector<Tree*> _aliases;
  std::map<std::string, Tree*> _tree;

  unsigned _acells;
  unsigned _scells;

  std::shared_ptr<Addr_type> _pos;

  Region_mapper *_rm;
};
