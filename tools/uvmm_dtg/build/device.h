/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include "tree.h"
#include "opts.h"
#include "support.h"
#include "config.h"

/*
 * Simple parser which splits the --device argument on colon and pass it to the
 * next parser.
 */
struct Device_list_parser: Parser_with_args
{
  Device_list_parser()
  : _opts("--device", "configures devices (help for list)",
          {Option("help", "show usage", make_parser<Help_parser>(&_opts))})
  {}

  void add_options(Option &&opts)
  { _opts.add_option(std::move(opts)); };

  Result parse(const std::string & /*opt*/, arg_vec *vec, arg_vec_it s) override
  {
    Result r;
    auto w = split(*s, ":");
    auto key = w[0];
    Results e = _opts.parse(&w, w.begin(), true);
    if (e.is_error())
      r.set_error(e);
    else
      // Nothing else to do here
      vec->erase(s);
    return r;
  }

  Options _opts;
};

/*
 * Base class of all devices.
 */
struct Device
{
  Device(const Arch &arch, size_t count, const Results &res)
  : _trg_arch(arch),
    _count(count),
    _res(res)
  {}

  virtual void add(Tree *tree) = 0;

  std::string name(const std::string &s)
  { return s + std::to_string(_count); }

protected:
  Arch _trg_arch;
  size_t _count;
  Results _res;
};

/*
 * Device factory
 *
 * All devices automatically register here. Based on the arch provided on the
 * commandline they will be considered in later processing.
 */
struct Factory
{
  Factory(int arch, const std::string &provides)
  : _avl_archs(arch),
    _provides(provides)
  { facs.push_back(this); }

  bool has_arch(const Arch &arch) const { return _avl_archs & arch.arch; }
  bool has_flag(int flag) const { return flags() & flag; }
  size_t count() const { return _count; }

  void set_arch(const Arch &arch)
  { _trg_arch = arch; }

  void add_results(const Results &res)
  { _results.push_back(res); }

  virtual Option option() = 0;

  static void prepare(const Arch &arch, std::shared_ptr<Device_list_parser> dlp)
  {
    // Filter everything by the target arch and relevant options to the device
    // parser
    for (auto a = facs.begin(); a != facs.end();)
      {
        if ((*a)->has_arch(arch))
          {
            (*a)->set_arch(arch);
            dlp->add_options((*a)->option());
            ++a;
          }
        else
          // Remove devices not targeted for the specified arch
          a = facs.erase(a);
      }
  }

  static void create_all_devices()
  {
    for (auto f: facs)
      f->create_devices();
  }

  static void build_tree(Tree *t)
  {
    for(auto d: _devices)
      d->add(t);
  }

protected:

  virtual int flags() const { return Option::None; };
  virtual std::vector<std::string> requires() const { return {}; };
  virtual std::shared_ptr<Device> create(const Results &res) = 0;

  Factory* find(const std::string &name)
  {
    for (auto a: facs)
      if (a->_provides == name)
        return a;
    throw Exception(std::string("can't find '") + name + "' dependency");
  }

  void create_devices(bool force = false)
  {
    // This adds an result in case of:
    // - it is a default device
    // - it was forced by the caller (it is a requirement for another device)
    // - we haven't already an Results from the command line parsing
    // - it wasn't already created
    if ((has_flag(Option::Default) || force) &&  _results.size() == 0 && !created)
      option().auto_fill(Results());

    // If we are going to create devices, make sure the requirements are fulfilled
    if (_results.size() > 0)
      {
        // We have to make sure that any dependent devices are created before
        // this device
        for (auto a: requires())
          find(a)->create_devices(true);

        // Now create a device for every Result we got from the command line or
        // internally
        for (auto r = _results.begin(); r != _results.end();)
          {
            _devices.push_back(create(*r));
            r = _results.erase(r);
            created = true;
          }
      }
  }

  Arch _trg_arch;
  int _avl_archs;
  std::string _provides;
  size_t _count = 0;
  bool created = false;

  std::vector<Results> _results;
  static std::vector<Factory*> facs;
  static std::vector<std::shared_ptr<Device>> _devices;
};

template <typename T>
struct Device_factory : Factory
{
  using Factory::Factory;

  std::shared_ptr<Device> create(const Results &res) override
  { return std::make_shared<T>(_trg_arch, _count++, res); }
};

/*
 * Parses the options of one specific device and adds the results back to the
 * appropriate factory for later creation.
 */
struct Device_parser: Parser
{
  Device_parser(const std::string &name, const std::string &desc, Factory *f)
  : _opts(name, desc, {Option("help", "show usage",
                              make_parser<Help_parser>(&_opts))}),
    _f(f)
  {}

  Device_parser(const std::string &name, const std::string &desc, Factory *f,
                std::initializer_list<Option> &&opts)
  : Device_parser(name, desc, f)
  { _opts.add_option(std::move(opts)); }

  Device_parser(const std::string &name, const std::string &desc, Factory *f,
                std::vector<Option> &&opts)
  : Device_parser(name, desc, f)
  { _opts.add_option(std::move(opts)); }

  Result parse(const std::string &key, arg_vec *vec, arg_vec_it s) override
  {
    Result r;
    if (_f->count() > 0 && !(_f->has_flag(Option::Multiple)))
      r.set_error(std::string(key + " is only allowed once"));
    else
      {
        // Find all device options
        // e.g. 'num=2', or 'cmdline=earlyprintk=ttyS0 root=/dev/ram rw,kernel=rom/kernel'
        // we split at ',' to receive a vector of Options e.g. "cmdline"
        // "earlyprintk=ttyS0 root=/dev/ram rw", "kernel", "rom/kernel"
        auto w = s != vec->end() ? split(*s, ",") : std::vector<std::string>();
        std::vector<std::string> o;
        for (unsigned i = 0; i < w.size(); ++i)
          {
            // everything until first '=' is the key
            o.push_back(w[i].substr(0, w[i].find_first_of('=')));
            // everything else is the value
            o.push_back(w[i].substr(w[i].find_first_of('=') + 1));
          }
        Results e = _opts.parse(&o, o.begin(), true);
        if (e.is_error())
          r.set_error(e);
        else
          {
            // Store the options in the factory for later use
            _f->add_results(e);
            if (s != vec->end())
              vec->erase(s);
          }
      }

    return r;
  }

  Result auto_fill(const Results &res) override
  {
    Results e = _opts.auto_fill(res);
    _f->add_results(e);
    return Result();
  }

  Options _opts;
  Factory *_f;
};

/*
 * Convenient class to create device options with the Device_parser.
 */
struct Device_option: Option
{
  Device_option(const std::string &name, const std::string& desc, Factory *f)
  : Option(name, desc, std::make_shared<Device_parser>(name, desc, f))
  {}

  Device_option(const std::string &name, const std::string& desc, Factory *f,
               std::initializer_list<Option> &&opts)
  : Option(name, desc, std::make_shared<Device_parser>(name, desc, f,
                                                       std::move(opts)))
  {}

  Device_option(const std::string &name, const std::string& desc, Factory *f,
               std::vector<Option> &&opts)
  : Option(name, desc, std::make_shared<Device_parser>(name, desc, f,
                                                       std::move(opts)))
  {}
};

/*
 * Convenient class for address parsing which automatically sets the correct
 * size limits for the given architecture.
 */
struct Addr_parser: UInt64_parser
{
  Addr_parser(bool is64bit)
  : UInt64_parser(0UL, is64bit ? std::numeric_limits<uint64_t>::max() :
                                 std::numeric_limits<uint32_t>::max())
  {}
};

/*
 * Auto values
 *
 * Try to automatically fill in certain parameters.
 */

/*
 * Automatically distribute mmio addresses in the guest address space.
 */
struct Addr_default: Auto_value<uint64_t>
{
  Addr_default()
  : Auto_value(INVALID_ADDR)
  {}

  std::string to_string() const override
  { return "auto"; }
};

/*
 * Try to automatically figure out the dataspace size when running on the target.
 * This takes cap names given on the command line into account.
 */
struct Ds_auto_value: Auto_value_base
{
  Ds_auto_value(const std::string &dscap, const std::string &defcap = "")
  : _dscap(dscap),
    _defcap(defcap)
  {}

  Result auto_result(const Results &res) const override
  {
    uint64_t size = Support::ds_size(res.as<std::string>(_dscap, _defcap));
    if (size)
      return Result(size);
    return Result();
  }

  std::string to_string() const override
  { return "auto"; }

private:
  std::string _dscap;
  std::string _defcap;
};

/*
 * Try to automatically figure out the amount of cpu cores when running on the
 * target. Otherwise return 1.
 */
struct Cpu_auto_value: Auto_value_base
{
  Result auto_result(const Results & /*res*/) const override
  {
    uint32_t count = Support::cpu_count();
    if (count)
      return Result(count);
    return Result((uint32_t)1);
  }

  std::string to_string() const override
  { return "auto|1"; }
};
