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
#include "vcpu_obj_registry.h"
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
  /// RAII managed MSI number allocation.
  struct Msi_num
  {
    Msi_num(cxx::Ref_ptr<Msi::Allocator> msi_alloc) : msi_alloc(msi_alloc)
    {
      // Allocate the number with the vBus ICU
      num = L4Re::chksys(msi_alloc->alloc_msi(),
                         "MSI-X vector allocation failed. "
                         "Please increase the 'Property.num_msis' on vbus.");
    };

    ~Msi_num() { msi_alloc->free_msi(num); }

    cxx::Ref_ptr<Msi::Allocator> msi_alloc;
    l4_uint32_t num = -1U;
  };

  /// Managed ICU bind and unbind including MSI number allocation.
  struct Icu_msi
  {
    Icu_msi(cxx::Ref_ptr<Vdev::Msi::Allocator> msi_alloc,
            L4::Cap<L4::Triggerable> icap)
    : msi_num({msi_alloc})
    {
      long label =
        L4Re::chksys(
          msi_num.msi_alloc->icu()->bind(msi_num.num | L4_ICU_FLAG_MSI, icap),
          "Bind MSI-IRQ to vBUS ICU.");

      // Currently, this doesn't happen for MSIs as IO's ICU doesn't manage
      // them. VMM Failure is not an option, as this is called during guest
      // runtime. What would be the graceful case?
      if (label > 0)
        warn().printf("ICU bind returned %li. Unexpected unmask via vBus ICU "
                      "necessary.\n", label);
      irq_cap = icap;
    }

    ~Icu_msi()
    {
      msi_num.msi_alloc->icu()->unbind(msi_num.num | L4_ICU_FLAG_MSI, irq_cap);
    }

    l4_msgtag_t msi_info(l4_uint64_t src_id, l4_icu_msi_info_t *msiinfo)
    {
      return msi_num.msi_alloc->icu()->msi_info(msi_num.num | L4_ICU_FLAG_MSI,
                                                src_id, msiinfo);
    }

    L4::Cap<L4::Triggerable> irq_cap; // Careful, this is non-owning. Check the
                                      // lifetime with user object!
    Msi_num msi_num;
  };

  template <typename T>
  struct Registration
  {
    Registration(Vcpu_obj_registry *reg, T *ep) : registry(reg), irqep(ep)
    { registry->register_irq_obj(irqep); }

    ~Registration()
    { registry->unregister_obj(irqep); }

    void retarget(Vcpu_obj_registry *reg)
    {
      // Store new registry before moving L4Re interrupt to different thread.
      // The interrupt might immediately fire on the new thread and race with
      // the code here...
      registry = reg;
      L4Re::chkcap(reg->move_obj(irqep), "Move Msi_irq_src to new registry.");
  }

    Vcpu_obj_registry *registry;
    T *irqep;
  };

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
  : _msix_dest(msix_dest),
    _registry(registry, this),
    _icu_msi(msi_alloc, this->obj_cap())
  {}

  // get MSI info
  void msi_info(l4_uint64_t src_id, l4_icu_msi_info_t *msiinfo)
  {
    L4Re::chksys(_icu_msi.msi_info(src_id, msiinfo),
                 "Acquire MSI vector information.");

    trace().printf("msi address: 0x%llx, data 0x%x\n", msiinfo->msi_addr,
                   msiinfo->msi_data);
  }

  // Implements L4::Irqep_t
  void handle_irq()
  {
    Vcpu_obj_registry *reg = _msix_dest.send_msix(msi_vec()->msi_vec_addr(),
                                                  msi_vec()->msi_vec_data());
    if (reg && reg != _registry.registry)
      _registry.retarget(reg);
  }

protected:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "MSI-IRQ-src"); }
  static Dbg warn()  { return Dbg(Dbg::Irq, Dbg::Warn,  "MSI-IRQ-src"); }

private:
  DERIVED *msi_vec()
  { return static_cast<DERIVED *>(this); }

  Gic::Msix_dest const _msix_dest;
  Registration<Msi_irq_src<DERIVED>> _registry;
  Icu_msi _icu_msi;
};

}
