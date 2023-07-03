/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2013-2020 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#include "debug.h"
#include "gic_iface.h"

namespace Gic {

static Dist_if::Factory const *_factory[Dist_if::Factory::Max_version + 1];

Dist_if::Factory::Factory(unsigned version)
{
  if (version < (Max_version + 1))
    _factory[version] = this;
}

Dist_if::Factory::~Factory()
{
  for (auto &f: _factory)
    if (f == this)
      f = nullptr;
}

cxx::Ref_ptr<Dist_if>
Dist_if::Factory::create(unsigned version, unsigned tnlines)
{
  Dbg(Dbg::Irq, Dbg::Info, "GIC").printf("create ARM GICv%u\n", version);

  if (version <= Max_version && _factory[version])
    return _factory[version]->create(tnlines);

  Err().printf("could not create GIC, unknown version: %u\n", version);

  return nullptr;
}

} // Gic
