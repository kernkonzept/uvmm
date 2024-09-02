/*
 * Copyright (C) 2018-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cerrno>

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <l4/cxx/minmax>
#include <l4/re/error_helper>

#include "debug.h"
#include "host_dt.h"

static Dbg warn(Dbg::Core, Dbg::Warn, "main");

namespace {

  class Mapped_file
  {
  public:
    explicit Mapped_file(char const *name)
    {
      int fd = open(name, O_RDWR);
      if (fd < 0)
        {
          warn.printf("Unable to open file '%s': %s\n", name, strerror(errno));
          return;
        }

      struct stat buf;
      if (fstat(fd, &buf) < 0)
        {
          warn.printf("Unable to get size of file '%s': %s\n", name,
                       strerror(errno));
          close(fd);
          return;
        }
      _size = buf.st_size;

      _addr = mmap(nullptr, _size, PROT_WRITE | PROT_READ, MAP_PRIVATE, fd, 0);
      if (_addr == MAP_FAILED)
        warn.printf("Unable to mmap file '%s': %s\n", name, strerror(errno));

      close(fd);
    }
    Mapped_file(Mapped_file &&) = delete;
    Mapped_file(Mapped_file const &) = delete;

    ~Mapped_file()
    {
      if (_addr != MAP_FAILED)
        {
          if (munmap(_addr, _size) < 0)
            warn.printf("Unable to unmap file at addr %p: %s\n",
                        _addr, strerror(errno));
        }
    }

    void *get() const { return _addr; }
    bool valid() { return _addr != MAP_FAILED; }

  private:
    size_t _size = 0;
    void *_addr = MAP_FAILED;
  };

}

void
Vdev::Host_dt::add_source(char const *fname)
{
  std::string filename(fname);
  std::size_t pos = filename.find(":limit=");
  if (pos != std::string::npos)
    {
      std::string r = filename.substr(pos + 7, std::string::npos);

      _upper_limit = strtoull(r.c_str(), NULL, 0);
      if (!_upper_limit)
        {
          Err().printf("Failed to parse a valid upper limit for DT placement. "
                       "Found: '%s'. Configuration error. Exit.\n", r.c_str());
          L4Re::chksys(-L4_EINVAL, "Unable to parse configuration for upper "
                                   "limit for DT placement");
        }

      warn.printf("DT location configured to be below 0x%llx\n",
                  _upper_limit);
    }

  Mapped_file mem(filename.substr(0, pos).c_str());
  if (!mem.valid())
    L4Re::chksys(-L4_EINVAL, "Unable to access overlay");

  if (valid())
    {
      get().apply_overlay(mem.get(), filename.substr(0, pos).c_str());
      return;
    }

  Dtb::Fdt fdt(mem.get());
  Device_tree dt(&fdt);

  dt.check_tree();

  // XXX would be nice to expand dynamically
  _fdt = cxx::make_unique<Dtb::Fdt>(fdt, cxx::max(dt.size(), 0x200U));
}

/**
 * Device tree modification.
 *
 * Add/modify the given property before the device tree is parsed. The
 * syntax of the parameter is dt-path/dt-property=type:val where
 * dt-path are the node components delimited by / and type is either
 * str, bool, u32 or u64. The default type is str and if the "=..."
 * part is missing, it defaults to bool.
 *
 * \param[in] opt  Device tree modification parameter (see above).
 */
void
Vdev::Host_dt::modify(std::string const &opt)
{
  enum Val_type
  {
    String,
    Bool,
    UInt32,
    UInt64
  };

  if (!valid() || opt.empty())
    return;

  Val_type vt = String;
  std::string path = opt;
  std::string name;
  std::string val;

  // Find the '=' delimiter between "dt-path/dt-property" and the rest.
  std::size_t pos = opt.find("=");
  if (pos != std::string::npos)
    {
      path = opt.substr(0, pos);
      val = opt.substr(pos + 1);
    }

  // Find the '/' delimiter between "dt-path" and "dt-property".
  pos = path.rfind("/");
  if (pos != std::string::npos)
    {
      name = path.substr(pos + 1);
      path = path.substr(0, pos + 1);
    }

  if (path.empty() || name.empty())
    L4Re::throw_error_fmt(-L4_EINVAL, "Can't find name or path in option: %s",
                          opt.c_str());

  auto node = get().path_offset(path.c_str());
  if (val.empty())
    vt = Bool;
  else
    {
      // Find the ':' delimiter between "type" and "val".
      pos = val.find(":");
      if (pos != std::string::npos)
        {
          std::string type = val.substr(0, pos);
          val = val.substr(pos + 1);
          if (type == "str")
            vt = String;
          else if (type == "bool")
            vt = Bool;
          else if (type == "u32")
            vt = UInt32;
          else if (type == "u64")
            vt = UInt64;
          else
            L4Re::throw_error_fmt(-L4_EINVAL, "Unsupported type in option: %s",
                                  opt.c_str());
        }
    }

  switch(vt)
    {
    case Bool: node.setprop_data(name.c_str(), NULL, 0); break;
    case String: node.setprop_string(name.c_str(), val.c_str()); break;
    case UInt32:
      {
        errno = 0;
        auto i = strtoul(val.c_str(), nullptr, 0);
        if (errno)
            L4Re::throw_error_fmt(-errno, "Can't convert value in option: %s",
                                  opt.c_str());
        node.setprop_u32(name.c_str(), i);
        break;
      }
    case UInt64:
      {
        errno = 0;
        auto i = strtoul(val.c_str(), nullptr, 0);
        if (errno)
            L4Re::throw_error_fmt(-errno, "Can't convert value in option: %s",
                                  opt.c_str());
        node.setprop_u64(name.c_str(), i);
        break;
      }
    }
}

void
Vdev::Host_dt::set_command_line(char const *cmd_line)
{
  if (!valid() || !cmd_line)
    return;

  // assume /choosen is present at this point
  auto node = get().path_offset("/chosen");
  node.setprop_string("bootargs", cmd_line);
}
