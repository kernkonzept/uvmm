/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 */

#include <l4/re/util/video/goos_fb>
#include <l4/cxx/exceptions>

#include "device.h"
#include "device_factory.h"
#include "device_tree.h"

#include "ds_mmio_mapper.h"
#include "ds_manager.h"
#include "guest.h"

namespace Vdev {
class Framebuffer : public Vmm::Ds_manager
{
public:
  Framebuffer(cxx::unique_ptr<L4Re::Util::Video::Goos_fb> gfb) :
    Ds_manager(gfb->buffer(), 0, gfb->buffer()->size()), _gfb(cxx::move(gfb))
  {
  }
private:
  cxx::unique_ptr<L4Re::Util::Video::Goos_fb> _gfb;
};

class Fb_dev : public Vdev::Device
{
public:
  ~Fb_dev() {}
};
} // namespace Vmm

// Factory section
namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    int psize;
    char const *prop = "l4vmm,cap";
    char const *cap_name = node.get_prop<char>(prop, &psize);
    if (!cap_name)
      {
        Err().printf("%s: Failed to get property '%s': %s\n", node.get_name(),
                     prop, fdt_strerror(psize));
        return 0;
      }

    l4_uint64_t fb_addr;
    int res = node.get_reg_val(0, &fb_addr, nullptr);
    if (res)
      {
        Err().printf("Invalid reg entry '%s'.reg[0]: %s\n",
                     node.get_name(), fdt_strerror(res));
        return 0;
      }

    auto gfb = cxx::make_unique<L4Re::Util::Video::Goos_fb>();
    try
      {
        gfb->setup(cap_name);
      }
    catch (L4::Runtime_error const &e)
      {
        char const *msg = e.extra_str();
        if (msg)
          Err().printf("fbdrv setup failed: %s: %s\n", e.str(), msg);
        else
          Err().printf("fbdrv setup failed: %s\n", e.str());
        return 0;
      }
    catch (...)
      {
        Err().printf("fbdrv setup failed with unknown exception\n");
        return 0;
      }

    L4Re::Video::Goos::Info info;
    if (auto err = gfb->goos()->info(&info))
      {
        Err().printf("Failed to get framebuffer information: %s\n",
                     l4sys_errtostr(err));
        return 0;
      }

    if (!info.auto_refresh())
      {
        Err().printf("fbdrv currently does not support framebuffers without "
                     "the auto-refresh feature\n");
        return 0;
      }

    L4Re::Video::View::Info fb_viewinfo;
    if (auto err = gfb->view_info(&fb_viewinfo))
      {
        Err().printf("Failed to get view information: %s\n",
                     l4sys_errtostr(err));
        return 0;
      }

    l4_uint64_t fb_size = gfb->buffer()->size();
    if (!devs->vmm()->register_framebuffer(fb_addr, fb_size, fb_viewinfo))
      return 0;

    auto handler = Vdev::make_device<Ds_handler>(
                     cxx::make_ref_obj<Vdev::Framebuffer>(cxx::move(gfb)));
    devs->vmm()->add_mmio_device(
                   Vmm::Region::ss(Vmm::Guest_addr(fb_addr), fb_size,
                                   Vmm::Region_type::Vbus), handler);

    return Vdev::make_device<Vdev::Fb_dev>();
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"simple-framebuffer", nullptr, &f};

} // namespace
