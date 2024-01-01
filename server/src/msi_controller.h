/*
 * Copyright (C) 2018-2020, 2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "pci_device.h"
#include "device.h"
#include "vcpu_obj_registry.h"

namespace Gic {

enum : l4_uint32_t
{
  Invalid_vsrc_id = 0xffffffffu,
};

struct Msix_controller : virtual Vdev::Dev_ref
{
  virtual ~Msix_controller() = default;

  /// Send MSI-X message to controller.
  virtual Vcpu_obj_registry *send(l4_uint64_t msix_addr, l4_uint64_t msix_data,
                                  l4_uint32_t vsrc_id = Invalid_vsrc_id) const = 0;
};

/**
 * Representation of a virtual source ID and the MSI-X controller at whom the
 * ID is valid.
 *
 * The virtual source ID is added as out-of-band data to each MSI-X message sent
 * to the MSI-X controller.
 */
class Msix_dest
{
public:
  /**
   * \param distr    MSI-X controller at whom the virtual source ID is valid,
   *                 might be nullptr, if the MSI-X source is not assigned to
   *                 an MSI-X controller.
   * \param vsrc_id  Virtual source ID that the MSI-X source uses to identify
   *                 itself to the MSI-X controller.
   */
  Msix_dest(cxx::Ref_ptr<Gic::Msix_controller> const &distr, l4_uint32_t vsrc_id)
  : _distr(distr), _vsrc_id(vsrc_id)
  {}

  /**
   * Send MSI-X message.
   *
   * \pre MSI-X controller is assigned, see `is_present()`
   */
  Vcpu_obj_registry *send_msix(l4_uint64_t msix_addr, l4_uint64_t msix_data) const
  {
    return _distr->send(msix_addr, msix_data, _vsrc_id);
  }

  /**
   * Return whether an MSI-X controller is assigned.
   */
  bool is_present() const
  {
    return _distr != nullptr;
  }

private:
  cxx::Ref_ptr<Gic::Msix_controller> const &_distr;
  l4_uint32_t _vsrc_id;
};

} // namespace Gic
