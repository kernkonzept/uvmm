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

// default set to false
static bool phys_dev_prepared;

void
Io_proxy::bind_irq(Vmm::Guest *vmm, Vmm::Virt_bus *vbus, Gic::Ic *ic,
                   Dt_node const &self, unsigned dt_idx, unsigned io_irq)
{
  auto dt_irq = ic->dt_get_interrupt(self, dt_idx);

  info.printf("IO device '%s' - registering irq%d=0x%x -> 0x%x\n",
              self.get_name(), dt_idx, io_irq, dt_irq);
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
Io_proxy::prepare_factory(Device_lookup const *devs)
{
  devs->vbus()->collect_resources(devs);
  phys_dev_prepared = true;
}

namespace {

struct F : Factory
{
  static bool check_regs(Device_lookup const *devs,
                         Dt_node const &node)
  {
    if (!node.has_prop("reg"))
      return true;

    auto vmm = devs->vmm();
    l4_uint64_t addr, size;
    for (int index = 0; /* no condition */ ; ++index)
      {
        int res = node.get_reg_val(index, &addr, &size);
        switch (res)
          {
          case 0:
            if (!vmm->mmio_region_valid(addr, size))
              return false;
            break;
          case -Dt_node::ERR_BAD_INDEX:
            // reached end of reg entries
            return true;
          case -Dt_node::ERR_NOT_TRANSLATABLE:
            // region not managed by us
            continue;
          case -Dt_node::ERR_RANGE:
            info.printf("Reg entry too large '%s'.reg[%d]\n",
                        node.get_name(), index);
            return false;
          default:
            Err().printf("Invalid reg entry '%s'.reg[%d]: %s\n",
                         node.get_name(), index, fdt_strerror(res));
            return false;
          }
      }
  }

  bool check_and_bind_irqs(Device_lookup *devs, Dt_node const &node)
  {
    if (!node.has_irqs())
      return true;

    cxx::Ref_ptr<Gic::Ic> ic;
    Device_lookup::Ic_error res = devs->get_or_create_ic(node, &ic);
    if (res != Device_lookup::Ic_ok)
      {
        // We did not get an interrupt parent because
        // * node does not have one or
        // * the interrupt parent device is a hardware device or
        // * one of the interrupt parent devices could not be created and
        //   was/will be disabled
        // We return true if the parent device is not a virtual interrupt
        // controller.
        if (res == Device_lookup::Ic_e_no_virtic)
          {
            Dbg(Dbg::Dev, Dbg::Info).
                printf("%s: Interrupt parent physical device - ignore irqs\n",
                       node.get_name());
            return true;
          }

        Dbg(Dbg::Dev, Dbg::Warn).
            printf("%s: Failed to get interrupt parent: %s\n",
                   node.get_name(), Device_lookup::ic_err_str(res));
        return false;

      }

    auto vbus = devs->vbus().get();
    int numint = ic->dt_get_num_interrupts(node);

    // Check whether all IRQs are available
    for (int i = 0; i < numint; ++i)
      {
        unsigned dt_irq = ic->dt_get_interrupt(node, i);
        if (!vbus->irq_present(dt_irq))
          return false;
      }

    // Bind IRQs
    L4vbus::Device const dummy;
    for (int i = 0; i < numint; ++i)
      {
        unsigned int dt_irq = ic->dt_get_interrupt(node, i);
        Io_proxy::bind_irq(devs->vmm(), vbus, ic.get(), node, i, dt_irq);
        vbus->mark_irq_bound(dt_irq);
      }
    return true;
  }

  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    if (!phys_dev_prepared)
      {
        Err().printf("%s: Io_proxy::create() invoked before prepare_factory()\n"
                     "\tprobably invalid device tree\n", node.get_name());
        return nullptr;
      }

    // Check mmio resources - mmio areas are already established
    if (!check_regs(devs, node))
      return nullptr;

    if (!check_and_bind_irqs(devs, node))
      return nullptr;

    L4vbus::Device io_dev;
    return make_device<Io_proxy>(io_dev);
  }

  F() { pass_thru = this; }
};

static F f;

} // namespace

} // namespace
