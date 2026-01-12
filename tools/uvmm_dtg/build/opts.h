/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <memory>
#include <string>
#include <algorithm>
#include <map>
#include <iostream>
#include <iomanip>
#include <functional>
#include <limits>

#include "generic.h"
#include "algh.h"

struct Result: Shared_value
{
  Result() = default;

  template <typename T>
  Result(const T &val)
  : Shared_value(val)
  {}

  template <typename T>
  Result(T &&val)
  : Shared_value(std::move(val))
  {}

  void set_help(const std::string &desc)
  {
    _err = true;
    _desc = desc;
  }

  void set_error(const std::string &desc)
  {
    _err = true;
    _desc = "Error: " + desc;
  }

  void set_error(const Result &res)
  {
    _err = res.is_error();
    _desc = res.error();
  }

  bool is_error() const { return _err; }
  bool is_valid() const { return !_err; }
  const std::string &error() const { return _desc; }

  int print_error() const
  {
    std::cerr << _desc << std::endl;
    return 1;
  }

private:
  bool _err = false;
  std::string _desc;
};

struct Results: std::multimap<std::string, Result>, Result
{
  void store(const std::string &key, const Result &res)
  { insert({key, res}); }

  bool has(const std::string &key) const
  { return count(key) > 0; }

  template <typename T>
  const T &as(const std::string &key, const T &v) const
  {
    auto f = find(key);
    if (f != end())
      return f->second.as<T>();
    return v;
  }

  template <typename T>
  const T &as(const std::string &key, T &&v = T()) const
  {
    auto f = find(key);
    if (f != end())
      return f->second.as<T>();
    return v;
  }

  void dump()
  {
    for (auto a = begin(); a != end(); ++a)
      printf("results: %s\n", (*a).first.c_str());
  }
};

struct Auto_value_base
{
  virtual Result auto_result(const Results &) const = 0;
  virtual std::string to_string() const = 0;
};

template <typename T>
struct Auto_value: Auto_value_base
{
  Auto_value(const T &r)
  : _val(r)
  {}

  Auto_value(T &&r)
  : _val(std::move(r))
  {}

  virtual ~Auto_value()
  {}

  Result auto_result(const Results &) const override { return Result(_val); }

  std::string to_string() const override
    {
    std::ostringstream oss;
    oss << _val;
    return oss.str();
  }

  T _val;
};

template <>
struct Auto_value<uint64_t>: Auto_value_base
{
  Auto_value(const uint64_t &r)
  : _val(r)
  {}

  Auto_value(uint64_t &&r)
  : _val(std::move(r))
  {}

  virtual ~Auto_value()
  {}

  Result auto_result(const Results &) const override { return Result(_val); }

  std::string to_string() const override
    {
    std::ostringstream oss;
    oss << std::hex;
    oss << "0x" << _val;
    return oss.str();
  }
  uint64_t _val;
};

template <typename T, class... Args>
std::shared_ptr<T>
make_auto(Args&&... args)
{ return std::make_shared<T>(std::forward<Args>(args)...); }

template <typename T, class... Args>
std::shared_ptr<Auto_value<T>>
make_default(Args&&... args)
{ return make_auto<Auto_value<T>>(std::forward<Args>(args)...); }

using arg_vec = std::vector<std::string>;
using arg_vec_it = std::vector<std::string>::iterator;

struct Parser
{
  Parser(bool args = false)
  : needs_arg(args) {}

  virtual Result parse(const std::string &opt, arg_vec *vec, arg_vec_it s) = 0;
  virtual Result auto_fill(const Results & /*res*/) { return Result(); }

  bool needs_arg;
};

struct Parser_with_args: Parser
{ Parser_with_args(): Parser(true) {} };

// One option
struct Option
{
  enum Flags
  {
    None = 0,
    Default  = 1UL << 0,
    Required = 1UL << 1,
    Multiple = 1UL << 2
  };

  Option(const std::string &name,  const std::string &desc,
         std::shared_ptr<Parser> parser,
         Flags flags = None)
  : _name(name),
    _desc(desc),
    _parser(parser),
    _flags(flags)
  {}

  Option(const std::string &name,  const std::string &desc,
         std::shared_ptr<Parser> parser,
         std::shared_ptr<Auto_value_base> auto_val,
         Flags flags = None)
  : _name(name),
    _desc(desc),
    _parser(parser),
    _auto_val(auto_val),
    _flags(flags)
  {}

  Result parse(const std::string &opt, arg_vec *vec, arg_vec_it s)
  { return _parser->parse(opt, vec, s); }

  bool has_auto_val() const
  { return (bool)_auto_val; }

  Result auto_fill(const Results &res) const
  {
    if (_auto_val)
      return _auto_val->auto_result(res);
    else
      return _parser->auto_fill(res);
  }

  std::string flags2str() const
  {
    std::vector<std::string> vec;
    if (_flags & Option::Default)
      vec.emplace_back("default");
    if (_flags & Option::Required)
      vec.emplace_back("required");
    if (_flags & Option::Multiple)
      vec.emplace_back("multiple");

    std::ostringstream oss;
    for (auto i = vec.begin(); i != vec.end(); i++)
      oss << (i != vec.begin() ? ", " : "") << *i;
    return oss.str();
  }

  std::string _name;
  std::string _desc;
  std::shared_ptr<Parser> _parser;
  std::shared_ptr<Auto_value_base> _auto_val;
  Flags _flags;
};

// Sub option with additional options attached
struct Options
{
  Options(const std::string &name, const std::string &desc)
  : _name(name),
    _desc(desc)
  {}

  Options(const std::string &name, const std::string &desc,
          std::initializer_list<Option> &&opts)
  : _name(name),
    _desc(desc),
    _opts(std::move(opts))
  {}

  bool has_opts() const { return _opts.size(); }

  void add_option(const std::string &name, const std::string &desc,
                  std::shared_ptr<Parser> parser,
                  Option::Flags flags = Option::None)
  { _opts.emplace_back(name, desc, parser, flags); }

  void add_option(const std::string &name, const std::string &desc,
                  std::shared_ptr<Parser> parser,
                  std::shared_ptr<Auto_value_base> auto_val,
                  Option::Flags flags = Option::None)
  { _opts.emplace_back(name, desc, parser, auto_val, flags); }

  void add_option(Option &&opt)
  { _opts.push_back(std::move(opt)); }

  void add_option(std::initializer_list<Option> &&opts)
  { _opts.insert(_opts.end(), std::move(opts)); }

  void add_option(std::vector<Option> &&opts)
  {
    _opts.insert(_opts.end(), std::make_move_iterator(opts.begin()),
                              std::make_move_iterator(opts.end()));
  }

  std::string help() const
  {
    std::ostringstream ss;

    ss << _name << ": " << _desc << std::endl << std::endl;
    size_t max = 0;
    for (auto &a: _opts)
      max = std::max(max, a._name.size());
    for (auto &a: _opts)
      {
        std::string f;
        std::string v;
        if (a._flags != Option::None)
          f = std::string(" (") + a.flags2str() + ")";
        if (a.has_auto_val())
          v = std::string(" [") + a._auto_val->to_string() + "]";
        ss << " " << std::left << std::setw(max + 2) << a._name + ": "
          << a._desc << v << f << std::endl;
      }

    return ss.str();
  }

  Results parse_one(const std::string &opt, arg_vec *vec, arg_vec_it s)
  {
    Results res;
    while (s != vec->end())
      {
        if (*s == opt)
          {
            if (!parse(&res, vec, &s))
              break;
          }
        else
          ++s;
      }

    // Auto fill values
    if (res.is_valid() && !res.has(opt))
      for (auto const &o: _opts)
        if (o._name == opt && o.has_auto_val())
          {
            Result r = o.auto_fill(res);
            if (r.has_value())
              {
                res.store(o._name, r);
                break;
              }
          }

    return res;
  }

  Results parse(arg_vec *vec, arg_vec_it s, bool match = false)
  {
    Results res;
    while (s != vec->end())
      {
        if (!parse(&res, vec, &s, match))
          break;
      }

    // Auto fill values
    if (res.is_valid())
      for (auto const &o: _opts)
        {
          if (!res.has(o._name))
            {
              if (o.has_auto_val())
                {
                  Result r = o.auto_fill(res);
                  if (r.has_value())
                    {
                      res.store(o._name, r);
                      continue;
                    }
                }

              // Check if this option is required
              if (o._flags & Option::Required)
                {
                  res.set_error(o._name + " is required");
                  break;
                }
            }
        }

    return res;
  }

  Results auto_fill(const Results &res)
  {
    Results e;
    // Auto fill values
    for (auto const &o: _opts)
      {
        Result r = o.auto_fill(res);
        if (r.has_value())
          e.store(o._name, r);
      }

    return e;
  }

private:
  bool parse(Results *res, arg_vec *vec, arg_vec_it *v, bool match = false)
  {
    arg_vec_it &s = *v;
    auto key = *s;
    auto o = find(key);
    if (o)
      {
        s = vec->erase(s);
        if (!(o->_flags & Option::Multiple) && res->has(key))
          {
            res->set_error(key + " is only allowed once");
            return false;
          }
        else if (o->_parser->needs_arg && s == vec->end())
          {
            res->set_error(key + " needs one argument");
            return false;
          }
        else
          {
            Result r = o->parse(key, vec, s);
            if (r.is_error())
              {
                res->set_error(r);
                return false;
              }
            else
              res->store(key, r);
          }
      }
    else if (match)
      {
        res->set_error(key + " is not a valid option");
        return false;
      }
    else
      ++s;
    return true;
  }

  Option *find(const std::string &name)
  {
    for (auto &a: _opts)
      if (a._name == name)
        return &a;
    return nullptr;
  }

  std::string _name;
  std::string _desc;
  std::vector<Option> _opts;
};

/*
 * Basic parsers
 */

struct Help_parser: Parser
{
  Help_parser(Options *opts)
  : _opts(opts) {}

  virtual ~Help_parser()
  {}

  Result parse(const std::string &, arg_vec *, arg_vec_it) override
  {
    Result r;
    r.set_help(_opts->help());
    return r;
  }

private:
  Options *_opts;
};

struct Switch_parser: Parser
{
  virtual ~Switch_parser()
  {}

  Result parse(const std::string &, arg_vec *, arg_vec_it) override
  { return Result(true); }
};

struct stoll
{
   long long operator()(const std::string &str, std::size_t *pos, int base)
   { return std::stoll(str, pos, base); }
};

struct stoull
{
   unsigned long long operator()(const std::string &str, std::size_t *pos,
                                 int base)
   { return std::stoull(str, pos, base); }
};

template<typename T, typename Op>
struct Int_parser: Parser_with_args
{
  Int_parser(T min = std::numeric_limits<T>::min(),
            T max = std::numeric_limits<T>::max())
  : _min(min),
    _max(max)
  {}

  virtual ~Int_parser()
  {}

  Result parse(const std::string &opt, arg_vec *vec, arg_vec_it s) override
  {
    Result r;
    try
      {
        std::size_t pos;
        Op o;
        auto i = o(*s, &pos, 0);
        if (pos != (*s).length())
          r.set_error(opt + " is not an integer");
        else if (i < _min)
          r.set_error(opt + " must be >= " + std::to_string(_min));
        else if (i > _max)
          r.set_error(opt + " must be <= " + std::to_string(_max));
        else
          {
            r.store((T)i);
            vec->erase(s);
          }
      }
    catch(...)
      {
        r.set_error(opt + " is not an integer");
      }
    return r;
  }

private:
  T _min;
  T _max;
};

using Int8_parser = Int_parser<int8_t, stoll>;
using UInt8_parser = Int_parser<uint8_t, stoull>;
using Int16_parser = Int_parser<int16_t, stoll>;
using UInt16_parser = Int_parser<uint16_t, stoull>;
using Int32_parser = Int_parser<int32_t, stoll>;
using UInt32_parser = Int_parser<uint32_t, stoull>;
using Int64_parser = Int_parser<int64_t, stoll>;
using UInt64_parser = Int_parser<uint64_t, stoull>;

struct String_parser: Parser_with_args
{
  virtual ~String_parser()
  {}

  Result parse(const std::string &, arg_vec *vec, arg_vec_it s) override
  {
    Result r;
    r.store(std::move(*s));
    vec->erase(s);
    return r;
  }
};

template <typename T>
struct Selector_parser: Parser_with_args
{
  Selector_parser(const std::map<std::string, T> &map)
  : _map(map)
  {}

  Selector_parser(std::initializer_list<std::pair<const std::string, T>> &&map)
  : _map(std::move(map))
  {}

  virtual ~Selector_parser()
  {}

  Result parse(const std::string &opt, arg_vec *vec, arg_vec_it s) override
  {
    Result r;
    auto m = _map.find(*s);
    if (m == _map.end())
      {
        std::vector<std::string> keys;
        for (auto const &a: _map)
          keys.emplace_back(a.first);
        r.set_error(opt + " format \"" + *s + "\" is not valid. Must be one of: "
                    + string_list(keys));
      }
    else
      {
        r.store(std::move((*m).second));
        vec->erase(s);
      }
    return r;
  }

  std::map<std::string, T> _map;
};

template <typename T, class... Args>
std::shared_ptr<T>
make_parser(Args&&... args)
{ return std::make_shared<T>(std::forward<Args>(args)...); }

// Fixes a problem where initializer lists do not work with make_shared directly
// because it can't deduce the arguments automatically
template <template <typename> class T, typename U>
std::shared_ptr< T<U> >
make_parser(std::initializer_list<std::pair<std::string const, U>> &&map)
{ return std::make_shared< T<U> >(std::move(map)); }
