/*
 * Copyright (C) 2018-2019, 2022-2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "pci_virtio_device.h"
#include "mem_access.h"
#include "mmio_device.h"
#include "io_device.h"
#include "virtio_dev.h"
#include "virtio_qword.h"
#include "pci_virtio_config.h"

namespace Virtio {

/**
 * Connecting instance between the Virtio world and the PCI transport world.
 *
 * \tparam DEV  The derived class.
 */
template<typename DEV>
class Pci_layout
{
  void init_queue_sizes()
  {
    auto vcfg = dev()->virtio_cfg();
    for (unsigned i = 0; i < vcfg->num_queues; i++)
      {
        auto *qc = dev()->virtqueue_config(i);
        assert(qc && !qc->ready);
        qc->num = qc->num_max;
      }
  }

public:
  void in(unsigned port, Vmm::Mem_access::Width wd, l4_uint32_t *value)
  {
    auto vcfg = dev()->virtio_cfg();
    l4_uint32_t result = 0;

    if (port >= Vdev::Num_pci_connector_ports)
      {
        read_device_memory(port - Vdev::Num_pci_connector_ports, wd, value);
        trace().printf("DevMem: In port(width) %i(%i) : 0x%x\n", port, wd,
                       *value);
        return;
      }

    switch(port)
      {
      case 0: // device feature select
        result = vcfg->dev_features_sel;
        break;

      case 4: // device feature
        {
          auto sel = vcfg->dev_features_sel;
          if (sel < (sizeof(vcfg->dev_features_map)
                     / sizeof(vcfg->dev_features_map[0])))
            result = vcfg->dev_features_map[sel];
          break;
        }

      case 8: // driver feature select
        result = vcfg->driver_features_sel;
        break;

      case 12: // driver feature
        {
          auto sel = vcfg->driver_features_sel;
          if (sel < (sizeof(vcfg->driver_features_map)
                     / sizeof(vcfg->driver_features_map[0])))
            result = vcfg->driver_features_map[sel];
          break;
        }

      case 16: // config msix vec
        result = _msi_table_idx_config;
        break;

      case 18: // RO num queues (max)
        // set the number of VQs for the virtio_console to 2
        result  = vcfg->num_queues;
        break;

      case 20: // device status
        result = vcfg->status;
        break;

      case 21: // RO config_generation
        result = vcfg->generation;
        break;

      case 22: // queue select
        result = vcfg->queue_sel;
        break;

      case 24: // queue size (max)
        {
          auto *qc = dev()->current_virtqueue_config();
          result = qc ? qc->num : 0;
          trace().printf("read queue size %i\n", result);
          break;
        }

      case 26: // queue_msix_vector
        {
          auto sel = vcfg->queue_sel;
          if (sel < (sizeof(_virtqueue_msix_index)
                     / sizeof(_virtqueue_msix_index[0])))
            result = dev()->msix_enabled() ? _virtqueue_msix_index[sel] : 0;
          break;
        }

      case 28: // queue_enable
        {
          auto *qc = dev()->current_virtqueue_config();
          result = qc ? qc->ready : 0;
          break;
        }

      case 30: // RO queue_notify_off
        // Read as 0.
        break;

      case 32: // queue_desc[31:0]
      case 36: // queue_desc[63:32]
        {
          if (wd == Vmm::Mem_access::Wd32)
            {
              auto *qc = dev()->current_virtqueue_config();
              int i = port == 32 ? 0 : 1;
              result = qc ? ((Virtio::Qword *)(&qc->desc_addr))->w[i] : -1;
            }
          else
            dbg().printf("Invalid width access to port %i with width %i\n",
                         port, wd);
          break;
        }

      case 40: // queue_avail[31:0]
      case 44: // queue_avail[63:32]
        {
          if (wd == Vmm::Mem_access::Wd32)
            {
              auto *qc = dev()->current_virtqueue_config();
              int i = port == 40 ? 0 : 1;
              result = qc ? ((Virtio::Qword *)(&qc->avail_addr))->w[i] : -1;
            }
          else
            dbg().printf("Invalid width access to port %i with width %i\n",
                         port, wd);
          break;
        }

      case 48: // queue_used[31:0]
      case 52: // queue_used[63:32]
        {
          if (wd == Vmm::Mem_access::Wd32)
            {
              auto *qc = dev()->current_virtqueue_config();
              int i = port == 48 ? 0 : 1;
              result = qc ? ((Virtio::Qword *)(&qc->used_addr))->w[i] : -1;
            }
          else
            dbg().printf("Invalid width access to port %i with width %i\n",
                         port, wd);
          break;
        }

      default:
        dbg().printf("unknown port number read: %i\n", port);
      }

    *value = Vmm::Mem_access::read(result, 0, wd);

    trace().printf("In port(width) %i(%i) : 0x%x\n", port, wd, *value);
  }

  void out(unsigned port, Vmm::Mem_access::Width wd, l4_uint32_t value)
  {
    auto vcfg = dev()->virtio_cfg();

    if (port >= Vdev::Num_pci_connector_ports)
      {
        trace().printf("DevMem OUT port(width) %i(%i) = 0x%x\n", port, wd,
                       value);
        write_device_memory(port - Vdev::Num_pci_connector_ports, wd, value);
        return;
      }

    if (port != 56)
      trace().printf("OUT port(width) %i(%i) = 0x%x\n", port, wd, value);

    switch(port)
      {
      case 0: // device feature select
        vcfg->dev_features_sel = value;
        break;

      case 8: // driver feature select
        vcfg->driver_features_sel = value;
        break;

      case 12: // driver feature
        {
          auto sel = vcfg->driver_features_sel;
          if (sel < (sizeof(vcfg->driver_features_map)
                     / sizeof(vcfg->driver_features_map[0])))
            vcfg->driver_features_map[sel] = value;
          break;
        }

      case 16: // config msix vec
        _msi_table_idx_config = value;
        dbg().printf("config_msix_vec set %i\n", value);
        break;

      case 20: // device status
        dev()->virtio_set_status(value);
        if (!value)
          init_queue_sizes();
        break;

      case 22: // queue select
        vcfg->queue_sel = value;
        break;

      case 24: // queue size (max)
        {
          auto *qc = dev()->current_virtqueue_config();
          if (qc)
            qc->num = value;
          break;
        }

      case 26: // queue_msix_vector
        {
          dbg().printf("\tqueue_msix_vector set %i\n", value);
          auto sel = vcfg->queue_sel;
          if (sel < (sizeof(_virtqueue_msix_index)
                     / sizeof(_virtqueue_msix_index[0])))
            _virtqueue_msix_index[sel] = value;
          break;
        }

      case 28: // queue_enable
        {
          auto *qc = dev()->current_virtqueue_config();
          if (value && qc)
            {
              if (dev()->msix_enabled())
                {
                  auto sel = vcfg->queue_sel;
                  if (sel < (sizeof(_virtqueue_msix_index)
                             / sizeof(_virtqueue_msix_index[0])))
                    qc->driver_notify_index = _virtqueue_msix_index[sel];
                }
            }

          dev()->virtio_queue_ready(value);
        }
        break;

      case 32: // queue_desc[31:0]
      case 36: // queue_desc[63:32]
        {
          if (wd == Vmm::Mem_access::Wd32)
            {
              auto *qc = dev()->current_virtqueue_config();
              int i = port == 32 ? 0 : 1;
              if (qc)
                ((Virtio::Qword *)(&qc->desc_addr))->w[i] = value;
            }
          else
            dbg().printf("Invalid width access to port %i with width %i\n",
                         port, wd);
          break;
        }

      case 40: // queue_avail[31:0]
      case 44: // queue_avail[63:32]
        {
          if (wd == Vmm::Mem_access::Wd32)
            {
              auto *qc = dev()->current_virtqueue_config();
              int i = port == 40 ? 0 : 1;
              if (qc)
                ((Virtio::Qword *)(&qc->avail_addr))->w[i] = value;
            }
          else
            dbg().printf("Invalid width access to port %i with width %i\n",
                         port, wd);
          break;
        }

      case 48: // queue_used[31:0]
      case 52: // queue_used[63:32]
        {
          if (wd == Vmm::Mem_access::Wd32)
            {
              auto *qc = dev()->current_virtqueue_config();
              int i = port == 48 ? 0 : 1;
              if (qc)
                ((Virtio::Qword *)(&qc->used_addr))->w[i] = value;
            }
          else
            dbg().printf("Invalid width access to port %i with width %i\n",
                         port, wd);
          break;
        }

      case 56: // queue notify: length depends on cap values set
        dev()->virtio_queue_notify(value);
        break;

      case 58: // ISR status
        if (!dev()->msix_enabled())
          dbg().printf("ISR status access for legacy IRQ -- NOT implemented\n");
        break;

      default: dbg().printf("unknown port number written: %i\n", port);
      }
  }

  void set_irq_status(int val)
  {
    // Only necessary in case of legacy IRQ, but a check if legacy IRQs are
    // used would be more expensive than just setting it either way.
    dev()->virtio_cfg()->irq_status = val;
  }

  enum
  {
    Device_config_start = 0x100,
  };

  template<typename T>
  void writeback_cache(T const *p)
  {
    l4_cache_clean_data((l4_addr_t)p, (l4_addr_t)p + sizeof(T));
  }

  template<typename T>
  T *virtio_device_config()
  {
    return reinterpret_cast<T *>(  (l4_addr_t)dev()->virtio_cfg()
                                 + Device_config_start);
  }

private:
  DEV *dev() { return static_cast<DEV *>(this); }
  DEV const *dev() const { return static_cast<DEV const *>(this); }

  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI con"); }
  static Dbg dbg() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI con"); }

  void read_device_memory(unsigned port, Vmm::Mem_access::Width wd,
                          l4_uint32_t *val)
  {
    l4_addr_t dev_cfg =
      reinterpret_cast<l4_addr_t>(l4virtio_device_config(dev()->virtio_cfg()))
      + port;

    *val = Vmm::Mem_access::read_width(dev_cfg, wd);
  }

  void write_device_memory(unsigned port, Vmm::Mem_access::Width wd,
                           l4_uint32_t val)
  {
    l4_addr_t dev_cfg =
      reinterpret_cast<l4_addr_t>(l4virtio_device_config(dev()->virtio_cfg()))
      + port;

    if (Vmm::Mem_access::write_width(dev_cfg, val, wd) == L4_EOK)
      dev()->virtio_pci_device_config_written();
  }

  unsigned _msi_table_idx_config = ::Vdev::Virtio_msix_no_vector;
  l4_uint16_t _virtqueue_msix_index[sizeof(Virtio::Event_set) * 8];
}; // Pci_layout

template <typename DEV>
class Pci_connector
: public Pci_layout<DEV>,
  public virtual Vmm::Mmio_device,
  public virtual Vmm::Io_device
{
public:
  Pci_connector() {}

  char const *dev_name() const override
  { return "Virtio PCI Device"; }

  int access(l4_addr_t pfa, l4_addr_t offset, Vmm::Vcpu_ptr vcpu,
             L4::Cap<L4::Vm>, l4_addr_t, l4_addr_t) override
  {
    auto insn = vcpu.decode_mmio();

    if (insn.access == Vmm::Mem_access::Other)
      {
        Dbg(Dbg::Mmio, Dbg::Warn, "mmio")
          .printf("MMIO access @ 0x%lx: unknown instruction. Ignored.\n",
                  pfa);
        return -L4_ENXIO;
      }

    Dbg(Dbg::Mmio, Dbg::Trace, "mmio")
      .printf("MMIO access @ 0x%lx (0x%lx) %s, width: %u\n",
              pfa, offset,
              insn.access == Vmm::Mem_access::Load ? "LOAD" : "STORE",
              (unsigned) insn.width);

    if (insn.access == Vmm::Mem_access::Store)
      write(offset, insn.width, insn.value, vcpu.get_vcpu_id());
    else
      {
        insn.value = read(offset, insn.width, vcpu.get_vcpu_id());
        vcpu.writeback_mmio(insn);
      }

    return Vmm::Jump_instr;
  }

  void map_eager(L4::Cap<L4::Vm>, Vmm::Guest_addr, Vmm::Guest_addr) override
  {} // nothing to map

  // MMIO interface
  l4_umword_t read(unsigned reg, char wd, unsigned /*cpu_id*/)
  {
    l4_uint32_t ret;
    Pci_layout<DEV>::in(reg, (Vmm::Mem_access::Width)wd, &ret);
    return ret;
  }

  void write(unsigned reg, char wd, l4_umword_t value, unsigned /*cpu_id*/)
  {
    Pci_layout<DEV>::out(reg, (Vmm::Mem_access::Width)wd, value);
  }

  // IO interface
  void io_in(unsigned port, Vmm::Mem_access::Width wd, l4_uint32_t *value) override
  {
    Pci_layout<DEV>::in(port, wd, value);
  }

  void io_out(unsigned port, Vmm::Mem_access::Width wd, l4_uint32_t value) override
  {
    Pci_layout<DEV>::out(port, wd, value);
  }
}; // Pci_connector
} // namespace Virtio
