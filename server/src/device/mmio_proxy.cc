/*
 * Copyright (C) 2017-2020, 2022-2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include <l4/re/env>
#include <l4/sys/meta>

#include "device_factory.h"
#include "mmio_space_handler.h"
#include "ds_mmio_mapper.h"
#include "guest.h"

static Dbg warn(Dbg::Dev, Dbg::Warn, "mmio-proxy");

namespace Vdev
{
  /**
   * Device that proxies memory accesses to an external dataspace
   * or mmio space.
   *
   * If the capability supports the dataspace protocol, the memory
   * from the dataspace is mapped directly into the guest address space.
   * The region(s) defined in reg must be aligned to page boundaries.
   *
   * For the mmio space protocol, all accesses are forwarded via IPC.
   * Mmio spaces support arbitrary reg regions.
   *
   * Device tree compatible: l4vmm,l4-mmio
   *
   * Device tree parameters:
   *   l4vmm,mmio-cap    - Capability that provides the dataspace or
   *                       mmio space interface. The capability is probed
   *                       for support of the two interfaces via the meta
   *                       protocol. If both interfaces are available
   *                       the dataspace protocol is used.
   *   reg               - Regions that cover the device.
   *   l4vmm,mmio-offset - Address in the dataspace/mmio space that
   *                       corresponds to the first base address in `reg`.
   *                       Default: 0.
   *   dma-ranges        - When present, uvmm adds the physical memory addresses
   *                       of the dataspace, if required. Allows DMA access
   *                       to the dataspace. Note: ranges are added, so the
   *                       property should be initially empty.
   *   l4vmm,physmap     - When present, export the complete dataspace starting
   *                       from an optional `l4vmm,mmio-offset`. The `reg`
   *                       property will be overwritten with the appropriate
   *                       region. `dma-ranges` must not be set at the same time.
   */
  struct Mmio_proxy : public Device
  {};
}

namespace {

using namespace Vdev;

class F : public Factory
{
public:
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    auto cap = Vdev::get_cap<void>(node, "l4vmm,mmio-cap");
    if (!cap)
      return nullptr;

    auto dscap = L4::cap_dynamic_cast<L4Re::Dataspace>(cap);
    if (dscap)
      {
        L4Re::Dataspace::Size size = dscap->size();
        l4_uint64_t offset = get_offset_from_node(node);

        if (offset > size)
          L4Re::chksys(-L4_EINVAL, "l4vmm,mmio-offset outside dataspace");

        size -= offset;
        auto mgr = cxx::make_ref_obj<Vmm::Ds_manager>("Mmio_proxy", dscap,
                                                      offset, size);


        if (node.has_prop("l4vmm,physmap"))
          register_physmap_region(mgr, devs, node);
        else
          register_mmio_regions(mgr, devs, node, node.has_prop("dma-ranges"));
        return Vdev::make_device<Mmio_proxy>();
      }

    auto mmcap = L4::cap_dynamic_cast<L4Re::Mmio_space>(cap);
    if (mmcap)
      {
        register_mmio_regions(mmcap, devs, node);
        return Vdev::make_device<Mmio_proxy>();
      }

    warn.printf("No known IPC protocol supported.\n");
    return nullptr;
  }

private:
  void register_physmap_region(cxx::Ref_ptr<Vmm::Ds_manager> const &mgr,
                               Device_lookup const *devs,
                               Dt_node const &node)
  {
    auto *as_mgr = devs->ram()->as_mgr();

    l4_uint64_t base, size;
    if (node.get_reg_val(0, &base, &size) < 0)
      L4Re::throw_error(-L4_EINVAL, "reg property not found or invalid");

    if (l4_trunc_page(base) != base)
      L4Re::throw_error(-L4_EINVAL, "reg base must be page aligned");

    size = mgr->size();
    L4Re::chksys(as_mgr->add_ram(mgr->dataspace().get(), mgr->offset(),
                                 &base, &size, -1),
                 "Cannot map l4-mmio to guest RAM");

    node.set_reg_val(base, size, false);

    auto handler = Vdev::make_device<Ds_handler>(mgr, L4_FPAGE_RW, 0);
    devs->vmm()->register_mmio_device(handler, Vmm::Region_type::Ram, node, 0);
  }

  void register_mmio_regions(cxx::Ref_ptr<Vmm::Ds_manager> mgr, Device_lookup const *devs,
                             Dt_node const &node, bool dma_ranges)
  {
    auto *as_mgr = devs->ram()->as_mgr();
    l4_size_t dssize = mgr->size();
    l4_uint64_t regbase, base, size;
    auto parent = node.parent_node();
    size_t addr_cells = node.get_address_cells(parent);
    size_t size_cells = node.get_size_cells(parent);

    if (node.get_reg_val(0, &regbase, &size) < 0)
      L4Re::chksys(-L4_EINVAL, "reg property not found or invalid");

    for (size_t index = 0; node.get_reg_val(index, &base, &size) >= 0; ++index)
      {
        if (base < regbase)
          {
            Err().printf("%s: reg%zd: %llx smaller than base of %llx\n"
                         "Smallest address must come first in 'reg' list.\n",
                         node.get_name(), index, base, regbase);
            L4Re::throw_error(-L4_ERANGE,
                              "Register list sorted in ascending order.");
          }

        l4_uint64_t sz = size;
        l4_uint64_t offs = base - regbase;
        if (offs + sz > dssize)
          {
            sz = offs < dssize ? dssize - offs : 0;
            node.update_reg_size(index, sz);
          }

        if (sz)
          {
            auto handler = Vdev::make_device<Ds_handler>(mgr, L4_FPAGE_RW, offs);
            devs->vmm()->register_mmio_device(handler, Vmm::Region_type::Virtual, node, index);

            if (dma_ranges)
              {
                l4_uint64_t phys = base;
                L4Re::chksys(as_mgr->add_ram(mgr->dataspace().get(),
                                             mgr->offset() + offs,
                                             &phys, &sz, -1),
                             "Cannot map l4-mmio to guest RAM");
                if (phys != base)
                  {
                    node.appendprop("dma-ranges", phys, addr_cells);
                    node.appendprop("dma-ranges", base, addr_cells);
                    node.appendprop("dma-ranges", sz, size_cells);
                  }
              }
          }
      }
  }

  void register_mmio_regions(L4::Cap<L4Re::Mmio_space> cap,
                             Device_lookup const *devs, Dt_node const &node)
  {
    l4_uint64_t regbase, base, size;
    l4_uint64_t offset = get_offset_from_node(node);

    if (node.get_reg_val(0, &regbase, &size) < 0)
      L4Re::chksys(-L4_EINVAL, "reg property not found or invalid");

    for (size_t index = 0; node.get_reg_val(index, &base, &size) >= 0; ++index)
      {
        if (base < regbase)
          {
            Err().printf("%s: reg%zd: %llx smaller than base of %llx\n"
                         "Smallest address must come first in 'reg' list.\n",
                         node.get_name(), index, base, regbase);
            L4Re::throw_error(-L4_ERANGE,
                              "Register list sorted in ascending order.");
          }

        l4_uint64_t offs = offset + (base - regbase);

        if (size)
          {
            auto handler = Vdev::make_device<Mmio_space_handler>(cap, 0, size, offs);
            devs->vmm()->register_mmio_device(handler, Vmm::Region_type::Virtual, node, index);
          }
      }
  }

  static l4_size_t get_offset_from_node(Dt_node const &node)
  {
    int propsz;
    auto *prop = node.get_prop<fdt32_t>("l4vmm,mmio-offset", &propsz);

    if (prop)
      return node.get_prop_val(prop, propsz, true);

    return 0;
  }
};


static F f;
static Device_type t = { "l4vmm,l4-mmio", nullptr, &f };

}
