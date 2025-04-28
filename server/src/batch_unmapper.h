/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Jan Klötzke <jan.kloetzke@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <l4/re/error_helper>
#include <l4/sys/capability>

namespace Vmm {

template<typename T>
class Batch_unmapper
{
  enum { Batch_size = L4_UTCB_GENERIC_DATA_SIZE - 2 };

  L4::Cap<T> _task;
  l4_fpage_t _fpages[Batch_size];
  unsigned _num = 0;
  l4_umword_t _mask;

  void flush()
  {
    if (_num > 0)
      L4Re::chksys(_task->unmap_batch(_fpages, _num, _mask),
                   "unmap_batch failed");
    _num = 0;
  }

public:
  explicit Batch_unmapper(L4::Cap<T> task, l4_umword_t mask)
  : _task(task), _mask(mask)
  {}

  ~Batch_unmapper()
  { flush(); }

  void unmap(l4_fpage_t fpage)
  {
    if (_num >= Batch_size)
      flush();

    _fpages[_num++] = fpage;
  }
};

} // namespace Vmm
