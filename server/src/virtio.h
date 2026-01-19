/*
 * Copyright (C) 2016-2017, 2024, 2026 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <stddef.h>

#include <l4/l4virtio/virtio.h>

namespace Virtio {

enum
{
  Hdr_off_magic                   = offsetof(l4virtio_config_hdr_t, magic),
  Hdr_off_version                 = offsetof(l4virtio_config_hdr_t, version),
  Hdr_off_device                  = offsetof(l4virtio_config_hdr_t, device),
  Hdr_off_vendor                  = offsetof(l4virtio_config_hdr_t, vendor),
  Hdr_off_dev_features            = offsetof(l4virtio_config_hdr_t,
                                             dev_features),
  Hdr_off_dev_features_sel        = offsetof(l4virtio_config_hdr_t,
                                             dev_features_sel),
  Hdr_off_driver_features         = offsetof(l4virtio_config_hdr_t,
                                             driver_features),
  Hdr_off_driver_features_sel     = offsetof(l4virtio_config_hdr_t,
                                             driver_features_sel),
  Hdr_off_num_queues              = offsetof(l4virtio_config_hdr_t, num_queues),
  Hdr_off_queues_offset           = offsetof(l4virtio_config_hdr_t,
                                             queues_offset),
  Hdr_off_queue_sel               = offsetof(l4virtio_config_hdr_t, queue_sel),
  Hdr_off_queue_num_max           = offsetof(l4virtio_config_hdr_t,
                                             queue_num_max),
  Hdr_off_queue_num               = offsetof(l4virtio_config_hdr_t, queue_num),
  Hdr_off_queue_ready             = offsetof(l4virtio_config_hdr_t,
                                             queue_ready),
  Hdr_off_queue_notify            = offsetof(l4virtio_config_hdr_t,
                                             queue_notify),
  Hdr_off_irq_status              = offsetof(l4virtio_config_hdr_t, irq_status),
  Hdr_off_irq_ack                 = offsetof(l4virtio_config_hdr_t, irq_ack),
  Hdr_off_status                  = offsetof(l4virtio_config_hdr_t, status),
  Hdr_off_cfg_driver_notify_index = offsetof(l4virtio_config_hdr_t,
                                             cfg_driver_notify_index),
  Hdr_off_cfg_device_notify_index = offsetof(l4virtio_config_hdr_t,
                                             cfg_device_notify_index),
  Hdr_off_cmd                     = offsetof(l4virtio_config_hdr_t, cmd),
  Hdr_off_queue_desc_low          = offsetof(l4virtio_config_hdr_t,
                                             queue_desc),
  Hdr_off_queue_desc_high         = offsetof(l4virtio_config_hdr_t,
                                             queue_desc)+4,
  Hdr_off_queue_avail_low         = offsetof(l4virtio_config_hdr_t,
                                             queue_avail),
  Hdr_off_queue_avail_high        = offsetof(l4virtio_config_hdr_t,
                                             queue_avail)+4,
  Hdr_off_queue_used_low          = offsetof(l4virtio_config_hdr_t,
                                             queue_used),
  Hdr_off_queue_used_high         = offsetof(l4virtio_config_hdr_t,
                                             queue_used)+4,
  Hdr_off_shm_sel                 = offsetof(l4virtio_config_hdr_t, shm_sel),
  Hdr_off_shm_len_low             = offsetof(l4virtio_config_hdr_t, shm_len),
  Hdr_off_shm_len_high            = offsetof(l4virtio_config_hdr_t, shm_len)+4,
  Hdr_off_shm_base_low            = offsetof(l4virtio_config_hdr_t, shm_base),
  Hdr_off_shm_base_high           = offsetof(l4virtio_config_hdr_t,
                                             shm_base)+4,
  Hdr_off_dev_features_map        = offsetof(l4virtio_config_hdr_t,
                                             dev_features_map),
  Hdr_off_driver_features_map     = offsetof(l4virtio_config_hdr_t,
                                             driver_features_map),
  Hdr_off_generation              = offsetof(l4virtio_config_hdr_t, generation)
};

union Qword
{
  l4_uint32_t w[2];
  l4_uint64_t q;
};

} // namespace Virtio
