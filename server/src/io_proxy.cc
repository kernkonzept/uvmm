/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <algorithm>

#include "device_factory.h"
#include "device_tree.h"
#include "guest.h"
#include "io_proxy.h"
#include "virt_bus.h"

namespace Vdev {

static Dbg info(Dbg::Dev, Dbg::Info, "ioproxy");
static Dbg warn(Dbg::Dev, Dbg::Warn, "ioproxy");

void
Io_proxy::bind_irq(Vmm::Guest *vmm, Vmm::Virt_bus *vbus, Gic::Ic *ic,
                   Dt_node const &self, unsigned dt_idx, unsigned io_irq)
{
  auto dt_irq = ic->dt_get_interrupt(self, dt_idx);

  info.printf("IO device %p:'%s' - registering irq%d=0x%x -> 0x%x\n",
              this, self.get_name(), dt_idx, io_irq, dt_irq);
  if (!ic->get_irq_source(dt_irq))
    {
      auto irq_svr = Vdev::make_device<Vdev::Irq_svr>(io_irq);

      L4Re::chkcap(vmm->registry()->register_irq_obj(irq_svr.get()),
                   "Invalid capability");

      // We have a 1:1 association, so if the irq is not bound yet we
      // should be able to bind the icu irq
      L4Re::chksys(vbus->icu()->bind(io_irq, irq_svr->obj_cap()),
                   "Cannot bind to IRQ");

      // Point irq_svr to ic:dt_irq for upstream events (like
      // interrupt delivery)
      irq_svr->set_sink(ic, dt_irq);

      // Point ic to irq_svr for downstream events (like eoi handling)
      ic->bind_irq_source(dt_irq, irq_svr);

      irq_svr->eoi();
      return;
    }

  warn.printf("IO device '%s': irq%d=0x%x -> 0x%x already registered\n",
              self.get_name(), dt_idx, io_irq, dt_irq);

  // Ensure we have the correct binding of the currently registered
  // source
  auto irq_source = ic->get_irq_source(dt_irq);
  auto other_svr = dynamic_cast<Irq_svr const *>(irq_source.get());
  if (other_svr && (io_irq == other_svr->get_io_irq()))
    return;

  if (other_svr)
    Err().printf("bind_irq: ic:0x%x -> 0x%x -- "
                 "irq already bound to different io irq: 0x%x  \n",
                 dt_irq, io_irq, other_svr->get_io_irq());
  else
    Err().printf("ic:0x%x is bound to a different irq type\n",
                 dt_irq);
  throw L4::Runtime_error(-L4_EEXIST);
}

void
Io_proxy::init_device(Device_lookup const *devs, Dt_node const &self)
{
  if (!self.get_prop<fdt32_t>("interrupts", nullptr))
    return;

  cxx::Ref_ptr<Device> dev;

  auto irq_ctl = self.find_irq_parent();
  if (irq_ctl.is_valid())
    dev = devs->device_from_node(irq_ctl);

  if (!dev)
    {
      Err().printf("virtio proxy - '%s': irq parent %s not found\n",
                   self.get_name(), irq_ctl.is_valid() ? "device" : "node");
      throw L4::Runtime_error(-L4_ENODEV);
    }

  // XXX need dynamic cast for Ref_ptr here
  auto *ic = dynamic_cast<Gic::Ic *>(dev.get());

  if (!ic)
    {
      info.printf("%s: Irqs are handled by %s, ignoring irq assignments\n",
                  self.get_name(), irq_ctl.get_name());
      return;
    }

  auto const *devinfo = devs->vbus()->find_device(this);
  assert (devinfo);

  int numint = ic->dt_get_num_interrupts(self);
  for (unsigned i = 0; i < devinfo->dev_info.num_resources; ++i)
    {
      l4vbus_resource_t res;

      L4Re::chksys(_dev.get_resource(i, &res),
                   "Cannot get resource in device_init()");

      char const *resname = reinterpret_cast<char const *>(&res.id);

      // Interrupts: id must be 'irqX' where X is the index into
      //             the device trees interrupts resource description
      if (res.type != L4VBUS_RESOURCE_IRQ)
        continue;

      if (strncmp(resname, "irq", 3))
        {
          warn.printf("IRQ resource '%s' of device '%.64s' ignored. "
                      "Should be named 'irq[0-9A-Z]'.\n",
                      resname, devinfo->dev_info.name);
          continue;
        }

      int id = decode_resource_id(resname[3]);
      if (id == -1)
        {
          Err().printf("IO device '%.64s' has invalid irq resource id. "
                       "Expected 'irq[0-9A-Z]', got '%.4s'\n",
                       devinfo->dev_info.name, resname);
          L4Re::chksys(-L4_EINVAL);
        }

      auto irq = res.start;
      if (id < numint)
        bind_irq(devs->vmm(), devs->vbus().get(), ic, self, id, irq);
      else
        Err().printf("Error: IO IRQ resource id (%d) is out of bounds\n", id);
    }
}

int Io_proxy::decode_resource_id(char c)
{
  if ('0' <= c && c <= '9')
    return c - '0';
  if ('A' <= c && c <= 'Z')
    return c - 'A' + 10;

  return -1;
}

namespace {

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup const *devs,
                              Dt_node const &node) override
  {
    // we can proxy memory and interrupts, check whether resources are
    // present
    if (!node.needs_vbus_resources())
      return nullptr;

    auto *vbus = devs->vbus().get();

    auto *vd = vbus->find_unassigned_dev(node);
    if (!vd)
      {
        warn.printf("No matching IO device found for device tree entry '%s'\n",
                    node.get_name());
        return nullptr;
      }

    auto proxy = make_device<Io_proxy>(vd->io_dev);
    vd->proxy = proxy;

    for (unsigned i = 0; i < vd->dev_info.num_resources; ++i)
      {
        l4vbus_resource_t res;

        L4Re::chksys(vd->io_dev.get_resource(i, &res),
                     "Cannot get resource in create()");

        char const *resname = reinterpret_cast<char const *>(&res.id);

        // MMIO memory: id must be 'regX' where X is the index into the
        //              device tree's 'reg' resource description
        if (res.type != L4VBUS_RESOURCE_MEM)
          continue;

        if (strncmp(resname, "reg", 3))
          {
            warn.printf("MMIO resource '%s' of device '%.64s' ignored. "
                        "Should be named 'reg[0-9A-Z]'.\n",
                        resname, vd->dev_info.name);
            continue;
          }

        int id = Io_proxy::decode_resource_id(resname[3]);
        if (id == -1)
          {
            Err().printf("IO device '%.64s' has invalid mmio resource id. "
                         "Expected 'reg[0-9A-Z]', got '%.4s'.\n",
                         vd->dev_info.name, resname);
            L4Re::chksys(-L4_EINVAL);
          }

        info.printf("Adding MMIO resource 0x%lx/0x%lx\n",
                    res.start, res.end);

        auto handler = Vdev::make_device<Ds_handler>(vbus->io_ds(), 0,
                                                     res.end - res.start + 1,
                                                     res.start);

        devs->vmm()->register_mmio_device(handler, node, id);
      }

    return proxy;
  }

  F() { pass_thru = this; }
};

static F f;

} // namespace

} // namespace
