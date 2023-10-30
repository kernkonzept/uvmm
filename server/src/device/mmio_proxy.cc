/*
 * Copyright (C) 2017-2020, 2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
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
   *                       of the dataspace. If the addresses cannot be determined
   *                       because the dataspace does not have the appropriate
   *                       properties, then startup of uvmm fails with an error.
   *                       Note: ranges are added, so the property should be
   *                       initially empty.
   *   l4vmm,physmap     - When present, export the complete dataspace starting
   *                       from an optional `l4vmm,mmio-offset`. The `reg`
   *                       property will be overwritten with the appropriate
   *                       region. `dma-ranges` must not be set at the same time.
   */
  struct Mmio_proxy : public Device
  {
    friend class F;

    void set_dma_space(L4Re::Util::Unique_cap<L4Re::Dma_space> &&dma)
    { _dma = cxx::move(dma); }

    /// container for DMA mapping, if applicable.
    L4Re::Util::Unique_cap<L4Re::Dma_space> _dma;
  };
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
        L4Re::Util::Unique_cap<L4Re::Dma_space> dma;
        bool physmap = node.has_prop("l4vmm,physmap");

        if (physmap || node.has_prop("dma-ranges"))
          {
            dma = L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dma_space>(),
                               "Create capability for DMA space for memory region.");

            L4Re::chksys(L4Re::Env::env()->user_factory()->create(dma.get()),
                         "Create DMA space for MMIO proxy region");

            L4Re::chksys(dma->associate(L4::Ipc::Cap<L4::Task>(),
                                        L4Re::Dma_space::Phys_space),
                         "Associate with physical address space");
          }

        auto mgr = cxx::make_ref_obj<Vmm::Ds_manager>("Mmio_proxy", dscap, 0,
                                                      dscap->size());

        if (physmap)
          register_physmap_region(mgr, devs, node, dma.get());
        else
          register_mmio_regions(mgr, devs, node, dma.get());
        auto dev = Vdev::make_device<Mmio_proxy>();
        dev->set_dma_space(cxx::move(dma));

        return dev;
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
                               Dt_node const &node, L4::Cap<L4Re::Dma_space> dma)
  {
    l4_size_t sz = mgr->size();
    l4_uint64_t offset = get_offset_from_node(node);

    if (offset > sz)
      L4Re::chksys(-L4_EINVAL, "l4vmm,mmio-offset outside dataspace");

    sz -= offset;

    auto phys = get_phys_mapping(mgr->dataspace().get(), dma,
                                 mgr->offset() + offset,
                                 sz, node.get_name());

    node.set_reg_val(phys, sz, false);

    auto handler = Vdev::make_device<Ds_handler>(mgr, L4_FPAGE_RW, offset);
    devs->vmm()->register_mmio_device(handler, Vmm::Region_type::Ram, node, 0);
  }

  void register_mmio_regions(cxx::Ref_ptr<Vmm::Ds_manager> mgr, Device_lookup const *devs,
                             Dt_node const &node, L4::Cap<L4Re::Dma_space> dma)
  {
    l4_size_t dssize = mgr->size();
    l4_uint64_t regbase, base, size;
    l4_uint64_t offset = get_offset_from_node(node);
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
        l4_uint64_t offs = offset + (base - regbase);
        if (offs + sz > dssize)
          {
            sz = offs < dssize ? dssize - offs : 0;
            node.update_reg_size(index, sz);
          }

        if (sz)
          {
            auto handler = Vdev::make_device<Ds_handler>(mgr, L4_FPAGE_RW, offs);
            devs->vmm()->register_mmio_device(handler, Vmm::Region_type::Virtual, node, index);

            if (dma.is_valid())
              {
                auto phys = get_phys_mapping(mgr->dataspace().get(), dma,
                                             mgr->offset() + offs,
                                             sz, node.get_name());

                node.appendprop("dma-ranges", phys, addr_cells);
                node.appendprop("dma-ranges", base, addr_cells);
                node.appendprop("dma-ranges", sz, size_cells);
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

  static L4Re::Dma_space::Dma_addr get_phys_mapping(L4::Cap<L4Re::Dataspace> cap,
                                                    L4::Cap<L4Re::Dma_space> dma,
                                                    l4_addr_t offset, l4_size_t size,
                                                    char const *node_name)
  {
    L4Re::Dma_space::Dma_addr phys_ram;
    l4_size_t phys_size = size;
    long err = dma->map(L4::Ipc::make_cap(cap, L4_CAP_FPAGE_RW),
                        offset, &phys_size,
                        L4Re::Dma_space::Attributes::None,
                        L4Re::Dma_space::Bidirectional, &phys_ram);

    if (err < 0)
      {
        Err().printf("%s: Cannot resolve physical address of dataspace. "
                     "Dataspace needs to be contiguous.\n",
                     node_name);
        L4Re::chksys(err, "Resolve physical address of dataspace.");
      }
    else if (phys_size < size)
      {
        Err().printf("%s: Cannot resolve physical address of complete area. "
                     "Dataspace not contiguous.\n"
                     "(dataspace size = 0x%zx, contiguous size = 0x%zx).\n",
                     node_name, size, phys_size);
        L4Re::chksys(-L4_ENOMEM, "Resolve dma-range of dataspace.");
      }

    return phys_ram;
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
