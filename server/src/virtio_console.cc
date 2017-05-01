#include <cstring>

#include "virtio_console.h"
#include "device_factory.h"
#include "guest.h"

#include <l4/re/env>

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup const *devs,
                              Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info).printf("Create virtual console\n");
    int cap_name_len;
    L4::Cap<L4::Vcon> cap = L4Re::Env::env()->log();

    char const *cap_name = node.get_prop<char>("l4vmm,virtiocap", &cap_name_len);
    if (cap_name)
      {
        cap_name_len = strnlen(cap_name, cap_name_len);

        cap = L4Re::Env::env()->get_cap<L4::Vcon>(cap_name, cap_name_len);
        if (!cap)
          {
            Dbg(Dbg::Dev, Dbg::Warn, "virtio")
              .printf("'l4vmm,virtiocap' property: capability %.*s is invalid.\n",
                      cap_name_len, cap_name);
            return nullptr;
          }
      }

    auto c = make_device<Virtio_console_mmio>(devs->ram().get(), cap);
    c->register_obj(devs->vmm()->registry());
    devs->vmm()->register_mmio_device(c, node);
    return c;
  }
};

static F f;
static Device_type t = { "virtio,mmio", "console", &f };

}

