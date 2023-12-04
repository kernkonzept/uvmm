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
#include "ipc_registry.h"
#include "msi_controller.h"
#include "msi_allocator.h"
#include "pci_device.h"

namespace Vdev { namespace Msi {

/**
 * Source for an MSI to inject into the guest OS.
 */
class Msi_src : public L4::Irqep_t<Msi_src>, public virtual Vdev::Dev_ref
{
public:
  /**
   * \param msi_cap      MSI capability of the corresponding PCI device.
   * \param io_irq       MSI number allocted from vBus.
   * \param msi_index    Vector number offset to inject into guest.
   * \param ctrl         Controller handling the MSI.
   *
   * Multiple MSIs are defined as consecutive list of MSI data values.
   * `msi_index` defines the entry number in this list.
   */
  Msi_src(Vdev::Pci::Pci_msi_cap const &msi_cap, l4_uint32_t io_irq,
          unsigned msi_index, Gic::Msix_dest const &msix_dest)
  : _msi_cap(msi_cap),
    _msi_index(msi_index),
    _msix_dest(msix_dest),
    _io_irq(io_irq)
  {}

  void handle_irq() const
  { _msix_dest.send_msix(_msi_cap.addr(), _msi_cap.data + _msi_index); }

  l4_uint32_t io_irq() const
  { return _io_irq; }

private:
  Vdev::Pci::Pci_msi_cap const &_msi_cap;
  unsigned const _msi_index;
  Gic::Msix_dest const _msix_dest;
  l4_uint32_t const _io_irq;
};

class Msi_src_factory : public virtual Vdev::Dev_ref
{
public:
  Msi_src_factory(cxx::Ref_ptr<Vdev::Msi::Allocator> msi_alloc,
                  Vcpu_obj_registry *registry)
  : _msi_alloc(msi_alloc), _registry(registry)
  {}

  void reset_msi_route(cxx::Ref_ptr<Msi_src> irq)
  {
    _msi_alloc->icu()->unbind(irq->io_irq() | L4_ICU_FLAG_MSI, irq->obj_cap());
    _msi_alloc->free_msi(irq->io_irq());
    _registry->unregister_obj(irq.get());
  }

  cxx::Ref_ptr<Msi_src> configure_msi_route(Pci::Pci_msi_cap const &msi_cap,
                                            Gic::Msix_dest const &msix_dest,
                                            l4_uint64_t src_id,
                                            l4_icu_msi_info_t *info)
  {
    long msi =
      L4Re::chksys(_msi_alloc->alloc_msi(), "MSI vector allocation failed.");

    auto msi_src =
      Vdev::make_device<Msi_src>(msi_cap, msi, 0, msix_dest);

    _registry->register_irq_obj(msi_src.get());

    long label = L4Re::chksys(_msi_alloc->icu()->bind(msi | L4_ICU_FLAG_MSI,
                                                      msi_src->obj_cap()),
                              "Bind MSI-IRQ to vBUS ICU.");

    // Currently, this doesn't happen for MSIs as IO's ICU doesn't manage them.
    // VMM Failure is not an option, as this is called during guest runtime.
    // What would be the graceful case?
    if (label > 0)
      warn().printf("ICU bind returned %li. Unexpected unmask via vBus ICU "
                    "necessary.\n", label);

    // get MSI info
    l4_icu_msi_info_t msiinfo;
    L4Re::chksys(_msi_alloc->icu()->msi_info(msi | L4_ICU_FLAG_MSI,
                                             src_id, &msiinfo),
                 "Acquire MSI entry from vBus.");

    // unmask the MSI-IRQ
    L4Re::chkipc(msi_src->obj_cap()->unmask(), "Unmask MSI-IRQ.");

    *info = msiinfo;
    return msi_src;
  }

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "MSI FCTRY"); }
  static Dbg warn()  { return Dbg(Dbg::Irq, Dbg::Warn,  "MSI FCTRY"); }

  cxx::Ref_ptr<Vdev::Msi::Allocator> _msi_alloc;
  Vcpu_obj_registry *_registry;
}; // class Msi_src_factory

} } // namespace Vdev::Msi
