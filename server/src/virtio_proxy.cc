#include "virtio_proxy.h"
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
    int cap_name_len;
    char const *cap_name = node.get_prop<char>("l4vmm,virtiocap", &cap_name_len);
    if (!cap_name)
      {
        Err().printf("'l4vmm,virtiocap' property missing from virtio device.\n");
        return nullptr;
      }

    cap_name_len = strnlen(cap_name, cap_name_len);

    auto cap = L4Re::Env::env()->get_cap<L4virtio::Device>(cap_name, cap_name_len);
    if (!cap)
      {
        Err().printf("'l4vmm,virtiocap' property: capability %.*s is invalid.\n",
                     cap_name_len, cap_name);
        return nullptr;
      }

    auto &ram = vmm->ram();

    auto c = make_device<Virtio_proxy_mmio>(&ram);
    c->register_obj(vmm->registry(), cap, ram.ram(), ram.vm_start());
    vmm->register_mmio_device(c, node);
    return c;
  }
};

static F f;
static Device_type t = { "virtio,mmio", "proxy", &f };

}

