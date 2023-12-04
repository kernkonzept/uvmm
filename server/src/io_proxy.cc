/*
 * Copyright (C) 2016-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "device_factory.h"
#include "device_tree.h"
#include "guest.h"
#include "irq_dt.h"
#include "io_proxy.h"
#include "virt_bus.h"

static Dbg trace(Dbg::Dev, Dbg::Trace, "ioproxy");
static Dbg info(Dbg::Dev, Dbg::Info, "ioproxy");
static Dbg warn(Dbg::Dev, Dbg::Warn, "ioproxy");

namespace {

  unsigned num_reg_entries(Vdev::Dt_node const &node)
  {
    if (!node.has_mmio_regs())
      return 0;

    for (unsigned num = 0;; ++num)
      {
        l4_uint64_t dtaddr, dtsize;
        int ret = node.get_reg_val(num, &dtaddr, &dtsize);

        if (ret == -Vdev::Dt_node::ERR_BAD_INDEX)
          return num;

        if (ret < 0)
          L4Re::chksys(-L4_EINVAL, "Check reg descriptor in device tree.");
      }

    // not reached
  }

  unsigned num_interrupts(Vdev::Device_lookup *devs, Vdev::Dt_node const &node)
  {
    if (!node.has_irqs())
      return 0;

    auto it = Vdev::Irq_dt_iterator(devs, node);

    for (unsigned num = 0;; ++num)
      {
        int ret = it.next(devs);

        if (ret == -L4_ERANGE)
          return num;

        if (ret < 0)
          L4Re::chksys(ret, "Check interrupt descriptions in device tree");
      }

    // not reached
  }
}


namespace Vdev {

// default set to false
static bool phys_dev_prepared;

void
Io_proxy::prepare_factory(Device_lookup const *devs)
{
  devs->vbus()->collect_resources(devs);
  phys_dev_prepared = true;
}

bool
Io_proxy::check_and_bind_irqs(Device_lookup *devs, Dt_node const &node)
{
  if (!node.has_irqs())
    return true;

  // Check whether all IRQs are available
  auto vbus = devs->vbus().get();

  Irq_dt_iterator it(devs, node);
  do
    {
      if (it.next(devs) < 0)
        return false;

      // Check that the IRQ is available on the vbus when a
      // virtual interrupt handler needs to be connected.
      if (it.ic_is_virt() && ! vbus->irq_present(it.irq()))
        {
          warn.printf("No corresponding IO resource for '%s' IRQ %d.\n",
                      node.get_name(), it.irq());
          return false;
        }
    }
  while (it.has_next());

  // Now bind the IRQs.
  it = Irq_dt_iterator(devs, node);
  do
    {
      it.next(devs);

      if (it.ic_is_virt())
        {
          int dt_irq = it.irq();
          bind_irq(devs->vmm(), vbus, it.ic(), dt_irq, dt_irq, node.get_name());
          vbus->mark_irq_bound(dt_irq);
        }
    }
  while (it.has_next());

  return true;
}

void
Io_proxy::bind_irq(Vmm::Guest *vmm, Vmm::Virt_bus *vbus,
                   cxx::Ref_ptr<Gic::Ic> const &ic,
                   unsigned dt_irq, unsigned io_irq, char const *dev_name)
{
  info.printf("IO device '%s' - registering irq 0x%x -> 0x%x\n",
      dev_name, io_irq, dt_irq);

  auto *irq_source = ic->get_irq_src_handler(dt_irq);
  if (!irq_source)
    {
      auto irq_svr =
        cxx::make_ref_obj<Io_irq_svr>(vmm->registry(), vbus->icu(),
                                      io_irq, ic, dt_irq);
      irq_svr->eoi();

      _irqs.push_back(std::move(irq_svr));
      return;
    }

  warn.printf("IO device '%s': irq 0x%x -> 0x%x already registered\n",
      dev_name, io_irq, dt_irq);

  // Ensure we have the correct binding of the currently registered
  // source
  auto other_svr = dynamic_cast<Io_irq_svr *>(irq_source);

  if (!other_svr)
    {
      Err().printf("ic:0x%x is bound to a different irq type\n",
                   dt_irq);
      L4Re::chksys(-L4_EEXIST, "Bind IRQ for IO proxy object.");
    }

  if (io_irq != other_svr->get_io_irq())
    {
      Err().printf("bind_irq: ic:0x%x -> 0x%x -- "
                   "irq already bound to different io irq: 0x%x  \n",
                   dt_irq, io_irq, other_svr->get_io_irq());
      L4Re::chksys(-L4_EEXIST, "Bind IRQ for IO proxy object.");
    }

  // Take a reference of the existing IRQ handler.
  _irqs.emplace_back(other_svr);
}



namespace {

static bool
mmio_region_valid(Vmm::Vm_mem const *memmap, l4_uint64_t addr, l4_uint64_t size,
                  Dt_node const &node, int index)
{
  Vmm::Vm_mem::const_iterator f = memmap->find(Vmm::Region(Vmm::Guest_addr(addr)));

  if (f == memmap->end())
    {
      warn.printf("No corresponding IO resource for '%s'.reg[%d] (0x%llx-0x%llx).\n",
                  node.get_name(), index, addr, addr + size - 1);
      return false;
    }

  if (f->first.type != Vmm::Region_type::Vbus)
    {
      if (f->first.type != Vmm::Region_type::Ram)
        {
          warn.printf("Conflicting resource types for '%s'.reg[%d], expected {%d, %d}, got %d\n",
                      node.get_name(), index,
                      static_cast<int>(Vmm::Region_type::Vbus),
                      static_cast<int>(Vmm::Region_type::Ram),
                      static_cast<int>(f->first.type));
          return false;
        }
      info.printf("'%s'.reg[%d] references physical RAM.\n",
                  node.get_name(), index);
    }

  if (Vmm::Guest_addr(addr + size) > f->first.end + 1)
    {
      warn.printf("Reg entry '%s'.reg[%d] exceeds corresponding IO resource.\n",
          node.get_name(), index);
      return false;
    }

  return true;
}


struct F : Factory
{
  static bool check_regs(Device_lookup const *devs,
                         Dt_node const &node)
  {
    if (!node.has_prop("reg"))
      return true;

    Vmm::Vm_mem const *memmap = devs->vmm()->memmap();
    l4_uint64_t addr, size;
    for (int index = 0; /* no condition */ ; ++index)
      {
        int res = node.get_reg_val(index, &addr, &size);
        switch (res)
          {
          case 0:
            if (!mmio_region_valid(memmap, addr, size, node, index))
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

  cxx::Ref_ptr<Device> create_from_vbus_dev(Device_lookup *devs,
                                            Dt_node const &node,
                                            char const *hid)
  {
    auto *vdev = devs->vbus()->find_unassigned_device_by_hid(hid);

    if (!vdev)
      {
        warn.printf("%s: requested vbus device '%s' not available.\n",
                    node.get_name(), hid);
        return nullptr;
      }

    // Count number of expected resources as a cheap means of validation.
    // This also checks that the device tree properties are correctly parsable.
    unsigned todo_regs = num_reg_entries(node);
    unsigned todo_irqs = num_interrupts(devs, node);

    auto device = make_device<Io_proxy>(vdev->io_dev());

    // collect resources directly for device
    auto vbus = devs->vbus().get();
    for (unsigned i = 0; i < vdev->dev_info().num_resources; ++i)
      {
        l4vbus_resource_t res;

        L4Re::chksys(vdev->io_dev().get_resource(i, &res),
                     "Cannot get resource in collect_resources");

        char const *resname = reinterpret_cast<char const *>(&res.id);

        if (res.type == L4VBUS_RESOURCE_MEM)
          {
            if (strncmp(resname, "reg", 3) || resname[3] < '0' || resname[3] > '9')
              {
                warn.printf("%s: Vbus memory resource '%.4s' has no recognisable name.\n",
                            node.get_name(), resname);
                continue;
              }

            unsigned resid = resname[3] - '0';
            l4_uint64_t dtaddr, dtsize;
            L4Re::chksys(node.get_reg_val(resid, &dtaddr, &dtsize),
                         "Match reg entry of device entry with vbus resource.");

            if (res.end - res.start + 1 != dtsize)
              L4Re::chksys(-L4_ENOMEM,
                           "Matching resource size of VBUS resource and device tree entry");

            trace.printf("Adding MMIO resource %s.%.4s : [0x%lx - 0x%lx] -> [0x%llx - 0x%llx]\n",
                      vdev->dev_info().name, resname, res.start, res.end,
                      dtaddr, dtaddr + (dtsize - 1));

            auto handler = Vdev::make_device<Ds_handler>(
                cxx::make_ref_obj<Vmm::Ds_manager>("Io_proxy: vbus",
                                                   vbus->io_ds(), res.start,
                                                   dtsize)
              );

            auto region = Vmm::Region::ss(Vmm::Guest_addr(dtaddr), dtsize,
                                          Vmm::Region_type::Virtual);
            devs->vmm()->add_mmio_device(region, handler);
            --todo_regs;
          }
        else if (res.type == L4VBUS_RESOURCE_IRQ)
          {
            if (strncmp(resname, "irq", 3) || resname[3] < '0' || resname[3] > '9')
              {
                warn.printf("%s: Vbus memory resource '%.4s' has no recognisable name.\n",
                            node.get_name(), resname);
                continue;
              }

            unsigned resid = resname[3] - '0';

            if (resid >= todo_irqs)
              {
                Err().printf("%s: VBUS interrupts resource '%.4s' has no matching device tree entry.\n",
                             node.get_name(), resname);
                L4Re::chksys(-L4_ENOMEM,
                             "Matching VBUS interrupt resources against device tree.");
              }

            auto it = Irq_dt_iterator(devs, node);
            it.next(devs);

            for (unsigned n = 0; n < resid; ++n)
              {
                // Just advance the iterator without error checking. num_interrupts()
                // above already checked that 'todo_irqs' interrupts are well defined.
                it.next(devs);
              }

            if (it.ic_is_virt())
              {
                int dt_irq = it.irq();
                device->bind_irq(devs->vmm(), vbus, it.ic(), dt_irq, res.start,
                                 node.get_name());
              }

            trace.printf("Registering IRQ resource %s.%.4s : 0x%lx\n",
                         vdev->dev_info().name, resname, res.start);
            --todo_irqs;
          }
      }

    if (todo_regs > 0)
      {
        Err().printf("%s: not enough memory resources found in VBUS device '%s'.\n",
                     node.get_name(), hid);
        L4Re::chksys(-L4_EINVAL, "Match memory resources");
      }
    if (todo_irqs > 0)
      {
        Err().printf("%s: not enough interrupt resources found in VBUS device '%s'.\n",
                     node.get_name(), hid);
        L4Re::chksys(-L4_EINVAL, "Match interrupt resources");
      }

    vdev->set_handler(device);

    return device;
  }

  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    char const *prop = node.get_prop<char>("l4vmm,vbus-dev", nullptr);

    if (prop)
      return create_from_vbus_dev(devs, node, prop);

    if (!phys_dev_prepared)
      {
        Err().printf("%s: Io_proxy::create() invoked before prepare_factory()\n"
                     "\tprobably invalid device tree\n", node.get_name());
        return nullptr;
      }

    L4vbus::Device io_dev;
    auto device = make_device<Io_proxy>(io_dev);

    // Check mmio resources - mmio areas are already established
    if (!check_regs(devs, node))
      return nullptr;

    if (!device->check_and_bind_irqs(devs, node))
      return nullptr;

    return device;
  }

  F() { pass_thru = this; }
};

static F f;

} // namespace

} // namespace
