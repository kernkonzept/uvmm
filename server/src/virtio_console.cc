#include "virtio_console.h"
#include "device_factory.h"
#include "guest.h"

#include <l4/re/env>

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Vmm::Guest *vmm,
                              Vmm::Virt_bus *,
                              Dt_node const &node)
  {
    Dbg().printf("Create virtual console\n");
    auto c = make_device<Virtio_console_mmio>(&vmm->ram(), L4Re::Env::env()->log());
    c->register_obj(vmm->registry());
    vmm->register_mmio_device(c, node);
    printf("Console: %p\n", c.get());
    return c;
  }
};

static F f;
static Device_type t = { "virtio,mmio", "console", &f };

}

