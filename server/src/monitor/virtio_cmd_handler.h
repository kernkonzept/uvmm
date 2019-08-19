/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>
#include <cstring>

#include <l4/l4virtio/virtio.h>

#include "monitor.h"
#include "monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Virtio_cmd_handler {};

template<typename T>
class Virtio_cmd_handler<true, T> : public Cmd
{
public:
  char const *help() const override
  { return "Virtio device state"; }

  void complete(FILE *f, Completion_request *compl_req) const override
  { compl_req->complete(f, {"config", "queues"}); }

  void exec(FILE *f, Arglist *args) override
  {
    auto subcmd = args->pop();

    auto *config = virtio_dev()->virtio_cfg();

    if (subcmd == "config")
      {
        fprintf(f, "# Config Header\n");
        print_config(f, config);
      }
    else if (subcmd == "queues")
      {
        for (auto qn = 0u; qn < config->num_queues; ++qn)
          {
            auto *queue_config = virtio_dev()->get_queue_config(qn);
            if (queue_config->ready)
              {
                fprintf(f, "\n## Queue %d Config\n", qn);
                print_queue_config(f, queue_config);
              }
            else
              fprintf(f, "\n## Queue %d Not Ready\n", qn);
          }
      }
  }

  static void print_config(FILE *f, l4virtio_config_hdr_t const *config)
  {
    auto device_id = config->device;

    char const *device_name = device_id_to_string(config->device);

    fprintf(f, "VIRTIO Version:         0x%08x\n", config->version);
    fprintf(f, "Device ID:              0x%08x (%s)\n", device_id, device_name);
    fprintf(f, "Vendor ID:              0x%08x\n", config->vendor);
    fprintf(f, "Config Array Offset:    0x%08x\n", config->queues_offset);
    fprintf(f, "Device Status Register: 0x%08x\n", config->status);
    fprintf(f, "Cmd:                    0x%08x\n", config->cmd);
    fprintf(f, "Number of Virtqueues:   %x\n", config->num_queues);
    fprintf(f, "Event Index (w):        %x\n", config->cfg_driver_notify_index);
    fprintf(f, "Event Index (r):        %x\n", config->cfg_device_notify_index);
  }

  static char const *device_id_to_string(l4_uint32_t device_id)
  {
    static char const *devices[] = {
      "Network Card", "Block Device", "Console", "Entropy Source",
      "Memory Ballooning", "IO Memory", "RPMSG", "SCSI Host", "9P Transport",
      "MAC802.11 WLAN"
    };

    if (device_id < 1 || device_id > 10)
      return "Unknown";

    return devices[device_id - 1];
  }

  static void print_queue_config(FILE *f, l4virtio_config_queue_t const *config)
  {
    fprintf(f, "Configured Descriptors:   %x\n", config->num);
    fprintf(f, "Maximum Descriptors:      %x\n", config->num_max);
    fprintf(f, "Descriptor Table Address: 0x%016llx\n", config->desc_addr);
    fprintf(f, "Available Ring Address:   0x%016llx\n", config->avail_addr);
    fprintf(f, "Used Ring Address:        0x%016llx\n", config->used_addr);
    fprintf(f, "Event Index (w):          %x\n", config->driver_notify_index);
    fprintf(f, "Event Index (r):          %x\n", config->device_notify_index);
  }

private:
  T *virtio_dev()
  { return static_cast<T *>(this); }
};

template<bool ENABLED, typename T>
struct Virtio_dev_cmd_handler : Virtio_cmd_handler<ENABLED, T>
{
  l4virtio_config_queue_t *get_queue_config(unsigned qn)
  { return &static_cast<T *>(this)->virtqueue(qn)->config; }
};

template<bool ENABLED, typename T>
struct Virtio_proxy_cmd_handler : Virtio_cmd_handler<ENABLED, T>
{
  l4virtio_config_queue_t *get_queue_config(unsigned qn)
  { return l4virtio_config_queues(static_cast<T *>(this)->virtio_cfg()) + qn; }
};

}
