/*
 * Copyright (C) 2015-2022 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "virtio_input_power.h"

namespace Vdev {

//
// Helper functions for monitor interface
//
static L4Re_events_key transtab[] = {
    L4RE_KEY_0,
    L4RE_KEY_1,
    L4RE_KEY_2,
    L4RE_KEY_3,
    L4RE_KEY_4,
    L4RE_KEY_5,
    L4RE_KEY_6,
    L4RE_KEY_7,
    L4RE_KEY_8,
    L4RE_KEY_9,
    L4RE_KEY_A,
    L4RE_KEY_B,
    L4RE_KEY_C,
    L4RE_KEY_D,
    L4RE_KEY_E,
    L4RE_KEY_F,
    L4RE_KEY_G,
    L4RE_KEY_H,
    L4RE_KEY_I,
    L4RE_KEY_J,
    L4RE_KEY_K,
    L4RE_KEY_L,
    L4RE_KEY_M,
    L4RE_KEY_N,
    L4RE_KEY_O,
    L4RE_KEY_P,
    L4RE_KEY_Q,
    L4RE_KEY_R,
    L4RE_KEY_S,
    L4RE_KEY_T,
    L4RE_KEY_U,
    L4RE_KEY_V,
    L4RE_KEY_W,
    L4RE_KEY_X,
    L4RE_KEY_Y,
    L4RE_KEY_Z
};

l4_uint16_t
translate_char(unsigned char c)
{
  l4_uint16_t res;

  if ('0' <= c && c <= '9')
    res = transtab[c - '0'];
  else if ('A' <= c && c <= 'Z')
    res = transtab[c + 10U - 'A' ];
  else if ('a' <= c && c <= 'z')
    res = transtab[c + 10U - 'a'];
  else
    // map everything to space as default
    res = L4RE_KEY_SPACE;

  return res;
}

class Virtio_input_power_mmio
: public Virtio_input_power<Virtio_input_power_mmio>,
  public Virtio_input<Virtio_input_power_mmio>,
  public Vmm::Ro_ds_mapper_t<Virtio_input_power_mmio>,
  public Virtio::Mmio_connector<Virtio_input_power_mmio>
{
public:
  explicit Virtio_input_power_mmio(Vmm::Vm_ram *iommu, L4::Cap<L4::Vcon> con)
  : Virtio_input_power<Virtio_input_power_mmio>(con),
    Virtio_input<Virtio_input_power_mmio>(iommu)
  {}

  Virtio::Event_connector_irq *event_connector() { return &_evcon; }

  int inject_events(l4virtio_input_event_t *events, size_t num)
  { return Virtio_input<Virtio_input_power_mmio>::inject_events(events, num); }

  void virtio_device_config_written(unsigned reg)
  {
    l4virtio_input_config_t *dev_cfg =
      virtio_device_config<l4virtio_input_config_t>();

    switch(reg)
      {
      case 0:
        break;
      case 1:
        virtio_input_cfg_written(dev_cfg);
        break;
      default:
        Dbg(Dbg::Dev, Dbg::Warn, "input")
          .printf("%s: Unexpected reg %d written\n", __func__, reg);
      }
  }

  char const *dev_name() const override { return "Virtio_input_power_mmio"; }

private:
  Virtio::Event_connector_irq _evcon;
};

} // namespace Vdev

namespace {

using namespace Vdev;

struct Mmio_factory : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info).printf("Create virtual input device (Mmio_factory)\n");
    bool monitor = node.has_prop("l4vmm,monitor");

    /* Deprecation warning, added 2021-08 */
    if (node.has_prop("l4vmm,virtiocap"))
      Dbg(Dbg::Dev, Dbg::Warn).printf("Device tree node for Virtio console"
                                      " contains old property 'l4vmm,virtiocap',"
                                      " which has been renamed to 'l4vmm,vcon_cap'\n");

    auto cap = Vdev::get_cap<L4::Vcon>(node, "l4vmm,vcon_cap");
    if (!cap && !monitor)
      return nullptr;

    auto c = make_device<Virtio_input_power_mmio>(devs->ram().get(), cap);
    if (c->init_irqs(devs, node) < 0)
      return nullptr;

    if (cap)
      c->register_obj(devs->vmm()->registry());

    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);

    return c;
  }
};

static Mmio_factory mmio_factory;
static Device_type t = { "virtio,mmio", "input-power", &mmio_factory };
}
