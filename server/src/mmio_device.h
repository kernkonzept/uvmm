/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once
#include <typeinfo>

#include <l4/cxx/ref_ptr>
#include <l4/sys/task>
#include <l4/sys/l4int.h>
#include <l4/sys/types.h>

#include "device.h"
#include "vcpu.h"

namespace Vmm {

struct Mmio_device : public virtual Vdev::Dev_ref
{
  virtual ~Mmio_device() = 0;

  bool mergable(cxx::Ref_ptr<Mmio_device> other,
                l4_addr_t start_other, l4_addr_t start_this)
  {
    if (typeid (*this) != typeid (*other.get()))
      return false;
    return _mergable(other, start_other, start_this);
  };
  virtual bool access(l4_addr_t pfa, l4_addr_t offset, Cpu vcpu,
                      L4::Cap<L4::Task> vm_task, l4_addr_t s, l4_addr_t e) = 0;
  virtual char const *dev_info(char *buf, size_t size)
  {
    if (size > 0)
      {
        strncpy(buf, typeid(*this).name(), size);
        buf[size - 1] = '\0';
      }
    return buf;
  };

protected:
  l4_umword_t reg_extend_width(l4_umword_t value, char size, bool sign_extend)
  {
    if (sign_extend)
      {
        switch (size)
          {
          case 0: return (l4_mword_t)((l4_int8_t)value);
          case 1: return (l4_mword_t)((l4_int16_t)value);
          case 2: return (l4_mword_t)((l4_int32_t)value);
          default: return value;
          }
      }

    switch (size)
      {
      case 0: return (l4_umword_t)((l4_uint8_t)value);
      case 1: return (l4_umword_t)((l4_uint16_t)value);
      case 2: return (l4_umword_t)((l4_uint32_t)value);
      default: return value;
      }
  }

private:
  virtual bool _mergable(cxx::Ref_ptr<Mmio_device> /* other */,
                         l4_addr_t /* start_other */,
                         l4_addr_t /* start_this */)
  { return false; }
};

inline Mmio_device::~Mmio_device() = default;

}
