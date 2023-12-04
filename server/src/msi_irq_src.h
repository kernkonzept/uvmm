/*
 * Copyright (C) 2019-2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Jan Klötzke <jan.kloetzke@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/re/error_helper>
#include <l4/sys/icu.h>
#include <l4/sys/irq>

#include "debug.h"
#include "ipc_registry.h"
#include "msi_allocator.h"
#include "msi_controller.h"

namespace Vdev {

/**
 * Source for an MSI(X) from a vBus to inject into the guest OS.
 */
template<class DERIVED>
class Msi_irq_src
: public L4::Irqep_t<Msi_irq_src<DERIVED>>,
  public virtual Vdev::Dev_ref
{
public:
  /**
   * Construct an MSI source.
   *
   * \param msi_alloc    Pointer to a MSI manager, e.g. vBus.
   * \param msix_dest    MSI controller handling the MSI(X).
   * \param registry     VCPU local object registry.
   *
   * Allocates an MSI vector on the vBus and registers the IRQ object.
   */
  Msi_irq_src(cxx::Ref_ptr<Vdev::Msi::Allocator> msi_alloc,
              Gic::Msix_dest const &msix_dest,
              Vcpu_obj_registry *registry)
  : _msi_alloc(msi_alloc),
    _msix_dest(msix_dest),
    _registry(registry)
  {
    // Allocate the number with the vBus ICU
    _io_irq = L4Re::chksys(_msi_alloc->alloc_msi(),
                           "MSI-X vector allocation failed. "
                           "Please increase the 'Property.num_msis' on vbus.");

    L4Re::chkcap(registry->register_irq_obj(this), "Register Msi_irq_src");

    long label = L4Re::chksys(_msi_alloc->icu()->bind(_io_irq | L4_ICU_FLAG_MSI,
                                                      this->obj_cap()),
                              "Bind MSI-IRQ to vBUS ICU.");

    // Currently, this doesn't happen for MSIs as IO's ICU doesn't manage them.
    // VMM Failure is not an option, as this is called during guest runtime.
    // What would be the graceful case?
    if (label > 0)
      warn().printf("ICU bind returned %li. Unexpected unmask via vBus ICU "
                    "necessary.\n", label);
  }

  ~Msi_irq_src()
  {
    _msi_alloc->icu()->unbind(_io_irq | L4_ICU_FLAG_MSI, this->obj_cap());
    _msi_alloc->free_msi(_io_irq);
    _registry->unregister_obj(this);
  }

  // get MSI info
  void msi_info(l4_uint64_t src_id, l4_icu_msi_info_t *msiinfo)
  {
    L4Re::chksys(_msi_alloc->icu()->msi_info(_io_irq | L4_ICU_FLAG_MSI, src_id,
                                             msiinfo),
                 "Acquire MSI entry from vBus.");

    trace().printf("msi address: 0x%llx, data 0x%x\n", msiinfo->msi_addr,
                   msiinfo->msi_data);
  }

  // Implements L4::Irqep_t
  void handle_irq()
  {
    Vcpu_obj_registry *reg = _msix_dest.send_msix(msi_vec()->msi_vec_addr(),
                                                  msi_vec()->msi_vec_data());
    if (reg && reg != _registry)
      retarget(reg);
  }

protected:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "MSI-IRQ-src"); }
  static Dbg warn()  { return Dbg(Dbg::Irq, Dbg::Warn,  "MSI-IRQ-src"); }

private:
  DERIVED *msi_vec()
  { return static_cast<DERIVED *>(this); }

  void retarget(Vcpu_obj_registry *reg)
  {
    // Store new registry before moving L4Re interrupt to different thread. The
    // interrupt might immediately fire on the new thread and race with the
    // code here...
    _registry = reg;
    L4Re::chkcap(reg->move_obj(this), "move registry");
  }

  cxx::Ref_ptr<Vdev::Msi::Allocator> _msi_alloc;
  Gic::Msix_dest const _msix_dest;
  Vcpu_obj_registry *_registry;
  l4_uint32_t _io_irq;
};

}
