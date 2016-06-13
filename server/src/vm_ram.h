/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/l4int.h>

#include <l4/l4virtio/virtqueue>

// This should be moved to l4/l4virtio/virtqueue
inline L4virtio::Ptr<void>
l4_round_size(L4virtio::Ptr<void> p, unsigned char bits)
{ return L4virtio::Ptr<void>((p.get() + (1ULL << bits) - 1) & (~0ULL << bits)); }

namespace Vmm {

class Vm_ram
{
protected:
  Vm_ram() : _vm_start(~0UL), _cont(false), _ident(false) {}

public:
  template<typename T>
  T *access(L4virtio::Ptr<T> p) const { return (T*)(p.get() + _offset); }

  l4_addr_t vm_start() const { return _vm_start; }
  l4_size_t size() const { return _size; }
  l4_addr_t local_start() const { return _local_start; }

protected:
  l4_mword_t _offset;
  l4_addr_t _local_start;
  l4_addr_t _local_end;

  l4_addr_t _vm_start;
  l4_size_t _size;

  bool _cont;
  bool _ident;
};

}
