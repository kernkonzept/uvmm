/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#pragma once

#include "device.h"
#include "vcpu_ptr.h"

namespace Gic {

/**
 * Abstract GIC interface for the ARM VMM
 */
class Dist_if : public virtual Vdev::Dev_ref
{
public:
  /**
   * Factory for the central GIC Distributor, hanceforth for the whole GIC.
   *
   * This abstract class needs to be implemented to ceate a GIC (Distributor)
   * object for a given GIC version from the vCPU info.
   */
  class Factory
  {
  public:
    enum { Max_version = 3 };
    /// initialize, and register this factory
    explicit Factory(unsigned version);

    /// create a GIC (Distributor)
    virtual cxx::Ref_ptr<Dist_if>
    create(unsigned tnline) const = 0;

    /// destroy and deregister this factory
    virtual ~Factory();

    /// Create a GIC (Distributor) of the given version.
    static cxx::Ref_ptr<Dist_if>
    create(unsigned version, unsigned tnlines);

  private:
    friend class Dist_if;
  };

  /// Create a GIC (Distributor) of the given version.
  static cxx::Ref_ptr<Dist_if>
  create_dist(unsigned version, unsigned tnlines)
  {
    return Factory::create(version, tnlines);
  }

  /// schedule pending IRQs to CPUs (default implementation in Dist_mixin)
  virtual bool schedule_irqs(unsigned current_cpu) = 0;

  /// handle vGIC maintanance IRQs (default implementation in Dist_mixin)
  virtual void handle_maintenance_irq(unsigned current_cpu) = 0;

  /// Setup the GIC when a GIC node is found in the device tree.
  virtual cxx::Ref_ptr<Vdev::Device>
  setup_gic(Vdev::Device_lookup *devs, Vdev::Dt_node const &node) = 0;

  /// Setup the CPU interface for the given `vcpu`.
  virtual void setup_cpu(Vmm::Vcpu_ptr vcpu) = 0;

  /**
   * Signal that CPU came online and is ready to receive IRQs.
   *
   * *Must* be called from target CPU!
   */
  virtual void cpu_online(Vmm::Vcpu_ptr vcpu) = 0;

  /**
   * Signal that CPU goes offline.
   *
   * *Must* be called from target CPU!
   */
  virtual void cpu_offline(Vmm::Vcpu_ptr vcpu) = 0;

  virtual ~Dist_if() = 0;
};

inline Dist_if::~Dist_if() = default;

}
