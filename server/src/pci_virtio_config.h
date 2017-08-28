/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "pci_device.h"

namespace Vdev {

  enum Virtio_defaults
  {
   // see Virtio 1.0 cs4 (2016) - Section 4.1
    Virtio_pci_device_vendor_id             = 0x1AF4,
    Virtio_pci_device_id_base               = 0x1040,
    Virtio_pci_legacy_device_id_base        = 0x1000,
    Transitional_device_pci_revision_id     = 0x0,
    Non_transitional_device_pci_revision_id = 0x1,
    Virtio_pci_cap_vndr                     = 0x9,
    Virtio_msix_no_vector                   = 0xffff,
  };

  enum Virtio_cfg_types
  {
    Virtio_pci_cap_common_cfg  = 1,
    Virtio_pci_cap_notify_cfg  = 2,
    Virtio_pci_cap_isr_cfg     = 3,
    Virtio_pci_cap_device_cfg  = 4,
    Virtio_pci_cap_pci_cfg     = 5,
  };

  struct Virtio_pci_cap_base
  {
    l4_uint8_t  cap_len;
    l4_uint8_t  cfg_type;
    l4_uint8_t  bar;
    l4_uint8_t  padding[3];
    l4_uint32_t offset;
    l4_uint32_t length;
  } __attribute__((__packed__));

  struct Virtio_pci_cap
  {
    Pci_cap_ident id; /// Same field for all caps to enable iterating.
    Virtio_pci_cap_base vio;
  } __attribute__((__packed__));

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
    l4_uint16_t quene_enable;
    l4_uint16_t queue_notify_off;
    l4_uint64_t queue_desc;
    l4_uint64_t queue_avail;
    l4_uint64_t queue_used;
  } __attribute__((__packed__));

  struct Virtio_pci_notify_cap
  {
    Pci_cap_ident id; /// Same field for all caps to enable iterating.
    Virtio_pci_cap_base vio;
    l4_uint32_t     notify_off_multiplier;
  } __attribute__((__packed__));

  struct Virtio_pci_cfg_cap
  {
    Pci_cap_ident id; /// Same field for all caps to enable iterating.
    Virtio_pci_cap_base vio;
    l4_uint8_t      pci_cfg_data[4];
  } __attribute__((__packed__));

}; // namespace Dev
