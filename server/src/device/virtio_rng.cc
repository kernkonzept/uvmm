/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 */
#include <l4/re/error_helper>
#include <l4/re/random>

#include "debug.h"
#include "device_factory.h"

namespace {

Dbg warn(Dbg::Dev, Dbg::Warn, "virtio-rnd");
Dbg info(Dbg::Dev, Dbg::Info, "virtio-rnd");
Dbg trace(Dbg::Dev, Dbg::Trace, "virtio-rnd");

/**
 * Provide a MMIO virtio random number generator device.
 *
 * To enable the device, add an entry like this to the device tree:
 *
 *     virtio_rng@20000 {
 *          compatible = "virtio,mmio";
 *          reg = <0x20000 0x100>;
 *          interrupt-parent = <&gic>;
 *          interrupts = <0 122 4>;
 *          l4vmm,vdev = "rng";
 *          l4vmm,virtiocap = "rnd-src";
 *          l4vmm,init-kaslr-seed;
 *      };
 *
 * The device is also able to set the seed for kaslr, required on ARM Linux.
 * If `l4vmm,init-kalr-seed` is set in the device tree, then
 * `/chosen/kaslr-seed` will be seeded with a random number.
 *
 * \todo Only KASLR seed is implemented at the moment.
 */
class Virtio_random_generator : public Vdev::Device_bootable
{
public:
  Virtio_random_generator(L4::Cap<L4Re::Random> cap)
  : _rnd(cap)
  {}

  void boot_device(Vdev::Device_lookup *, Vdev::Device_tree dt,
                   char const *path) override
  {
    auto node = dt.path_offset(path);
    if (!node.is_valid())
      return;

    // TODO We do not implement the virtio part yet, so disable for now.
    node.setprop_string("status", "disabled");

    if (!node.has_prop("l4vmm,init-kaslr-seed"))
      return; // nothing to do

    l4_uint64_t random;
    L4::Ipc::Array<char, unsigned long> msg(sizeof(random),
                                            reinterpret_cast<char *>(&random));
    int ret = _rnd->get_random(sizeof(random), &msg);

    if (ret < (int) sizeof(random))
      L4Re::throw_error(ret < 0 ? ret : -L4_EAGAIN,
                        "Getting random seed for KASLR initialisation.");

    // The chosen node is expected to be always available in the device tree.
    node = dt.path_offset("/chosen");
    node.setprop_u64("kaslr-seed", random);
  }

private:
  L4::Cap<L4Re::Random> _rnd;
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    (void)devs;
    info.printf("Create virtio random number generator device\n");

    auto cap = Vdev::get_cap<L4Re::Random>(node, "l4vmm,virtiocap");
    if (!cap)
      return nullptr;

    auto c = Vdev::make_device<Virtio_random_generator>(cap);

    return c;
  }
};

static F f;
static Vdev::Device_type t = { "virtio,mmio", "rng", &f };

}
