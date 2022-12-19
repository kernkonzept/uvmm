/*
 * Copyright (C) 2017, 2019, 2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "pci_device.h"

namespace Vdev {

  enum Consts
  {
    Num_pci_connector_ports = 0x50,
  };

  enum Virtio_defaults
  {
   // see Virtio 1.0 cs4 (2016) - Section 4.1
    Virtio_pci_device_vendor_id             = 0x1AF4,
    Virtio_pci_device_id_base               = 0x1040,
    Virtio_pci_legacy_device_id_base        = 0x1000,
    Transitional_device_pci_revision_id     = 0x0,
    Non_transitional_device_pci_revision_id = 0x1,
    Virtio_msix_no_vector                   = 0xffff,
    Virtio_pci_subsystem_id_minimum         = 0x40,
  };

  enum Virtio_cfg_types
  {
    Virtio_pci_cap_common_cfg  = 1,
    Virtio_pci_cap_notify_cfg  = 2,
    Virtio_pci_cap_isr_cfg     = 3,
    Virtio_pci_cap_device_cfg  = 4,
    Virtio_pci_cap_pci_cfg     = 5,
  };

  /// Base class of a VirtIO capability.
  struct Virtio_pci_cap : Pci::Vendor_specific_cap
  {
    explicit Virtio_pci_cap(l4_uint8_t vio_cfg_t, l4_uint8_t len)
    : Vendor_specific_cap(len), cfg_type(vio_cfg_t)
    {}

    /**
     * Perform a cast if the input cap type `c` is of the expected
     * Virtio_pci_cap type.
     *
     * \tparam T  The expected Virtio_pci_cap type.
     * \param  c  The capability to cast.
     *
     * \returns A valid capability pointer if the type is correct; nullptr
     *          otherwise.
     */
    template <typename T>
    static T *
    cast_type(Virtio_pci_cap *c)
    {
      if (auto *x = Pci_cap::cast_type<Virtio_pci_cap>(c))
        return x->cfg_type == T::Virtio_cfg_type ? static_cast<T *>(c) : nullptr;

      return nullptr;
    }

    l4_uint8_t  cfg_type;
    l4_uint8_t  bar;
    l4_uint8_t  padding[3];
    l4_uint32_t offset;
    l4_uint32_t length;
  };
  static_assert(sizeof(Virtio_pci_cap) == 16,
                "Virtio_pci_cap size conforms to specification.");

  struct Virtio_pci_common_cap : Virtio_pci_cap
  {
    enum : l4_uint8_t
    {
      Virtio_cfg_type = Virtio_pci_cap_common_cfg
    };

    Virtio_pci_common_cap()
    : Virtio_pci_cap(Virtio_cfg_type, sizeof(*this))
    {}
  };
  static_assert(sizeof(Virtio_pci_common_cap) == 16,
                "Virtio_pci_common_cap size conforms to specification.");

  struct Virtio_pci_isr_cap : Virtio_pci_cap
  {
    enum : l4_uint8_t
    {
      Virtio_cfg_type = Virtio_pci_cap_isr_cfg
    };

    Virtio_pci_isr_cap()
    : Virtio_pci_cap(Virtio_cfg_type, sizeof(*this))
    {}
  };
  static_assert(sizeof(Virtio_pci_isr_cap) == 16,
                "Virtio_pci_isr_cap size conforms to specification.");

  struct Virtio_pci_notify_cap : Virtio_pci_cap
  {
    enum : l4_uint8_t
    {
      Virtio_cfg_type = Virtio_pci_cap_notify_cfg
    };

    Virtio_pci_notify_cap()
    : Virtio_pci_cap(Virtio_cfg_type, sizeof(*this))
    {}

    l4_uint32_t     notify_off_multiplier;
  };
  static_assert(sizeof(Virtio_pci_notify_cap) == 20,
                "Virtio_pci_notify_cap size conforms to specification.");

  struct Virtio_pci_device_cap : Virtio_pci_cap
  {
    enum : l4_uint8_t
    {
      Virtio_cfg_type = Virtio_pci_cap_device_cfg
    };

    Virtio_pci_device_cap()
    : Virtio_pci_cap(Virtio_cfg_type, sizeof(*this))
    {}
  };
  static_assert(sizeof(Virtio_pci_device_cap) == 16,
                "Virtio_pci_device_cap size conforms to specification.");

  struct Virtio_pci_cfg_cap : Virtio_pci_cap
  {
    enum : l4_uint8_t
    {
      Virtio_cfg_type = Virtio_pci_cap_pci_cfg
    };

    Virtio_pci_cfg_cap()
    : Virtio_pci_cap(Virtio_cfg_type, sizeof(*this))
    {}

    l4_uint8_t      pci_cfg_data[4];
  };
  static_assert(sizeof(Virtio_pci_cfg_cap) == 20,
                "Virtio_pci_cfg_cap size conforms to specification.");

  struct Virtio_pci_common_cfg
  {
    l4_uint32_t device_feature_select;  // 0, 1
    l4_uint32_t device_feature;         // starts at device_features_select * 32
    l4_uint32_t driver_feature_select;  // 0, 1
    l4_uint32_t driver_feature;         // starts at driver_features_select * 32
    l4_uint16_t config_msix_vec;
    l4_uint16_t num_queues;
    l4_uint8_t  device_status;
    l4_uint8_t  config_generation;

    l4_uint16_t queue_select;
    l4_uint16_t queue_size;
    l4_uint16_t queue_msix_vector;
    l4_uint16_t queue_enable;
    l4_uint16_t queue_notify_off;
    l4_uint64_t queue_desc;
    l4_uint64_t queue_avail;
    l4_uint64_t queue_used;
  };
  static_assert(sizeof(Virtio_pci_common_cfg) == 56,
                "Virtio_pci_common_cfg size conforms to specification.");

}; // namespace Vdev
