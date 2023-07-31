#include <cstring>

#include "virtio_console.h"
#include "device_factory.h"
#include "guest.h"

#include <l4/re/env>

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info).printf("Create virtual console\n");

    /* Deprecation warning, added 2021-08 */
    if (node.has_prop("l4vmm,virtiocap"))
      Dbg(Dbg::Dev, Dbg::Warn).printf("Device tree node for Virtio console"
                                      " contains old property 'l4vmm,virtiocap',"
                                      " which has been renamed to 'l4vmm,vcon_cap'\n");

    auto cap = Vdev::get_cap<L4::Vcon>(node, "l4vmm,vcon_cap",
                                       L4Re::Env::env()->log());
    if (!cap)
      return nullptr;

    auto c = make_device<Virtio_console_mmio>(devs->ram().get(), cap);
    if (c->init_irqs(devs, node) < 0)
      return nullptr;

    c->register_obj<Virtio_console_mmio>(devs->vmm()->registry());
    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);
    return c;
  }
};

static F f;
static Device_type t = { "virtio,mmio", "console", &f };

}
