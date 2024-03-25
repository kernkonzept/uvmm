/* SPDX-License-Identifier: ((GPL-2.0-only WITH mif-exception) OR LicenseRef-kk-custom) */
/*
 * Copyright (C) 2014-2022 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#pragma once

#include <l4/re/util/cap_alloc>
#include <l4/re/dataspace>
#include <l4/re/rm>
#include <l4/re/env>
#include <l4/cxx/ref_ptr>
#include <l4/re/error_helper>

#include "consts.h"

namespace Vmm {

/**
 * Manager for a unique part of a dataspace, that might be mapped
 * into the VMM.
 *
 * The manager manages and keeps track of a VMM-local mapping of the
 * dataspace if this is needed (requested by using local_addr<>()).
 */
class Ds_manager : public cxx::Ref_obj
{
private:
  /// Debug name
  std::string const _dev_name;
  /// Dataspace capability for the dataspace to be managed
  L4Re::Util::Ref_cap<L4Re::Dataspace>::Cap _ds;
  /// Offset within the dataspace of the managed part
  L4Re::Dataspace::Offset _offset = 0;
  /// Size of the managed dataspace part
  L4Re::Dataspace::Size _size = 0;
  /// Local region if the managed part is locally attached
  L4Re::Rm::Unique_region<void *> _local;
  /// Region flags to be used when locally attaching the dataspace
  L4Re::Rm::Region_flags _local_flags;
  /// Region alignment (log2)
  unsigned char _align;

  /**
   * Get the VMM local address of the managed portion of the dataspace.
   *
   * \note This function might create a local mapping if it does
   * not already exist.
   */
  void *_local_addr()
  {
    if (_local.is_valid())
      return _local.get();

    auto rm = L4Re::Env::env()->rm();

    L4Re::chksys(rm->attach(&_local, _size,
                            _local_flags
                            | L4Re::Rm::F::Search_addr
                            | L4Re::Rm::F::Eager_map,
                            L4::Ipc::make_cap_rw(_ds.get()),
                            _offset, _align),
                 "Attach dataspace to local address space.");
    return _local.get();
  }

public:
  /**
   * Create a manager for the given part of the given dataspace.
   */
  Ds_manager(std::string const &dev_name,
             L4Re::Util::Ref_cap<L4Re::Dataspace>::Cap const &ds,
             L4Re::Dataspace::Offset offset,
             L4Re::Dataspace::Size size,
             L4Re::Rm::Region_flags local_flags = L4Re::Rm::F::RW,
             unsigned char align = L4_SUPERPAGESHIFT)
  : _dev_name(dev_name),
    _ds(ds), _offset(offset), _size(size), _local_flags(local_flags),
    _align(align)
  {}

  Ds_manager(Ds_manager const &) = delete;
  Ds_manager(Ds_manager &&) = default;
  virtual ~Ds_manager() = default;

  /**
   * Get the capability for the managed dataspace.
   */
  L4Re::Util::Ref_cap<L4Re::Dataspace>::Cap dataspace() const
  { return _ds; }

  /**
   * Get the size in bytes of the managed part of the dataspace.
   */
  L4Re::Dataspace::Size size() const
  { return _size; }

  /**
   * Get the offset relative to the start of the dataspace that is
   * represented by this manager.
   */
  L4Re::Dataspace::Offset offset() const
  { return _offset; }

  /**
   * Get the VMM local address of the managed portion of the dataspace.
   *
   * NOTE: this function might create a local mapping if it does
   * not already exist.
   */
  template<typename T>
  T local_addr()
  { return reinterpret_cast<T>(_local_addr()); }

  /**
   * Return true if a VMM local mapping of the managed dataspace
   * part exists.
   */
  bool is_mapped() const
  { return _local.is_valid(); }

  L4Re::Rm::Region_flags local_flags() const
  { return _local_flags; }

  /**
   * Returns the dev name.
   */
  char const *dev_name() const { return _dev_name.c_str(); }
};

}

