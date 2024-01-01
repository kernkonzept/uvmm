/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2019-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once

#include <l4/sys/icu.h>
#include <l4/sys/irq>
#include <l4/re/error_helper>

#include "debug.h"
#include "device.h"
#include "vcpu_obj_registry.h"
#include "msi_controller.h"
#include "msi_allocator.h"
#include "msi_irq_src.h"
#include "pci_device.h"

namespace Vdev { namespace Msi {

/**
 * Source for an MSI to inject into the guest OS.
 */
class Msi_src : public Msi_irq_src<Msi_src>, public virtual Vdev::Dev_ref
{
public:
  /**
   * \param msi_alloc    Pointer to a MSI manager, e.g. vBus.
   * \param msix_dest    MSI controller handling the MSI(X).
   * \param registry     VCPU local object registry.
   * \param msi_cap      MSI capability of the corresponding PCI device.
   * \param msi_index    Vector number offset to inject into guest.
   *
   * Multiple MSIs are defined as consecutive list of MSI data values.
   * `msi_index` defines the entry number in this list.
   */
  Msi_src(cxx::Ref_ptr<Vdev::Msi::Allocator> msi_alloc,
          Gic::Msix_dest const &msix_dest,
          Vcpu_obj_registry *registry,
          Vdev::Pci::Pci_msi_cap const &msi_cap,
          unsigned msi_index)
  : Msi_irq_src<Msi_src>(msi_alloc, msix_dest, registry),
    _msi_cap(msi_cap),
    _msi_index(msi_index)
  {}

  l4_uint64_t msi_vec_addr() const
  { return _msi_cap.addr(); }

  l4_uint64_t msi_vec_data() const
  { return _msi_cap.data + _msi_index; }

private:
  Vdev::Pci::Pci_msi_cap const &_msi_cap;
  unsigned const _msi_index;
};

class Msi_src_factory : public virtual Vdev::Dev_ref
{
public:
  Msi_src_factory(cxx::Ref_ptr<Vdev::Msi::Allocator> msi_alloc,
                  Vcpu_obj_registry *registry)
  : _msi_alloc(msi_alloc), _registry(registry)
  {}

  cxx::Ref_ptr<Msi_src> configure_msi_route(Pci::Pci_msi_cap const &msi_cap,
                                            Gic::Msix_dest const &msix_dest,
                                            l4_uint64_t src_id,
                                            l4_icu_msi_info_t *info)
  {
    // allocate IRQ object and bind it to the ICU
    auto msi_src =
      Vdev::make_device<Msi_src>(_msi_alloc, msix_dest, _registry, msi_cap, 0);

    // get MSI info
    l4_icu_msi_info_t msiinfo;
    msi_src->msi_info(src_id, &msiinfo);

    // unmask the MSI-IRQ
    L4Re::chkipc(msi_src->obj_cap()->unmask(), "Unmask MSI-IRQ.");

    *info = msiinfo;
    return msi_src;
  }

private:
  cxx::Ref_ptr<Vdev::Msi::Allocator> _msi_alloc;
  Vcpu_obj_registry *_registry;
}; // class Msi_src_factory

} } // namespace Vdev::Msi
