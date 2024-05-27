/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021-2023 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 *            Stephan Gerhold <stephan.gerhold@kernkonzept.com>
 */

#include <l4/re/util/video/goos_fb>
#include <l4/cxx/exceptions>

#include "device.h"
#include "device_factory.h"
#include "device_tree.h"

#include "ds_mmio_mapper.h"
#include "ds_manager.h"
#include "guest.h"

#ifdef CONFIG_UVMM_QEMU_FW_IF
#include "qemu_fw_cfg.h"
#endif

namespace Vdev {
class Framebuffer : public Vmm::Ds_manager
{
public:
  Framebuffer(cxx::unique_ptr<L4Re::Util::Video::Goos_fb> gfb) :
    Ds_manager("Framebuffer", gfb->buffer(), 0, gfb->buffer()->size()),
               _gfb(cxx::move(gfb))
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
struct {
  const char *name;
  L4Re::Video::Pixel_info pixel_info;
} simplefb_formats[] = {
  { "r5g6b5", {2, 5, 11, 6, 5, 5, 0} },
  { "r5g5b5a1", {2, 5, 11, 5, 6, 5, 1, 1, 0} },
  { "x1r5g5b5", {2, 5, 10, 5, 5, 5, 0} },
  { "a1r5g5b5", {2, 5, 10, 5, 5, 5, 0, 1, 15} },
  { "r8g8b8", {3, 8, 16, 8, 8, 8, 0} },
  { "x8r8g8b8", {4, 8, 16, 8, 8, 8, 0} },
  { "a8r8g8b8", {4, 8, 16, 8, 8, 8, 0, 8, 24} },
  { "a8b8g8r8", {4, 8, 0, 8, 8, 8, 16, 8, 24} },
  { "x2r10g10b10", {4, 10, 20, 10, 10, 10, 0} },
  { "a2r10g10b10", {4, 10, 20, 10, 10, 10, 0, 2, 30} },
};

const char *find_simplefb_format(const L4Re::Video::Pixel_info &pixel_info)
{
  for (auto &f : simplefb_formats)
    if (f.pixel_info == pixel_info)
      return f.name;
  return nullptr;
}

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    int psize;
    char const *prop = "l4vmm,fbcap";
    char const *cap_name = node.get_prop<char>(prop, &psize);
    auto warn = Dbg(Dbg::Dev, Dbg::Warn, "FB");
    if (!cap_name)
      {
        warn.printf("%s: Failed to get property '%s': %s\n", node.get_name(),
                    prop, fdt_strerror(psize));
        return 0;
      }

    l4_uint64_t fb_addr;
    int res = node.get_reg_val(0, &fb_addr, nullptr);
    if (res)
      {
        warn.printf("Invalid reg entry '%s'.reg[0]: %s\n",
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
          warn.printf("fbdrv setup failed: %s: %s\n", e.str(), msg);
        else
          warn.printf("fbdrv setup failed: %s\n", e.str());
        return 0;
      }
    catch (...)
      {
        warn.printf("fbdrv setup failed with unknown exception\n");
        return 0;
      }

    L4Re::Video::Goos::Info info;
    if (auto err = gfb->goos()->info(&info))
      {
        warn.printf("Failed to get framebuffer information: %s\n",
                    l4sys_errtostr(err));
        return 0;
      }

    if (!info.auto_refresh())
      {
        warn.printf("fbdrv currently does not support framebuffers without "
                    "the auto-refresh feature\n");
        return 0;
      }

    L4Re::Video::View::Info fb_viewinfo = {};
    if (auto err = gfb->view_info(&fb_viewinfo))
      {
        warn.printf("Failed to get view information: %s\n",
                    l4sys_errtostr(err));
        return 0;
      }

    l4_uint64_t fb_size = gfb->buffer()->size();
    if (!devs->vmm()->register_framebuffer(fb_addr, fb_size, fb_viewinfo))
      return 0;

    node.update_reg_size(0, fb_size);
    node.setprop_u32("width", fb_viewinfo.width);
    node.setprop_u32("height", fb_viewinfo.height);
    node.setprop_u32("stride", fb_viewinfo.bytes_per_line);

    auto format = find_simplefb_format(fb_viewinfo.pixel_info);
    if (format)
      node.setprop_string("format", format);
    else
      warn.printf("Framebuffer format is unsupported by simple-framebuffer\n");

    auto handler = Vdev::make_device<Ds_handler>(
                     cxx::make_ref_obj<Vdev::Framebuffer>(cxx::move(gfb)));
    devs->vmm()->add_mmio_device(
                   Vmm::Region::ss(Vmm::Guest_addr(fb_addr), fb_size,
                                   Vmm::Region_type::Vbus), handler);
#ifdef CONFIG_UVMM_QEMU_FW_IF
    struct
    {
      l4_uint64_t    address;
      l4_uint32_t    width;
      l4_uint32_t    height;
      l4_uint32_t    bytes_per_line;
      l4_uint32_t    bytes_per_pixel;
      l4_uint8_t     red_size;
      l4_uint8_t     red_shift;
      l4_uint8_t     green_size;
      l4_uint8_t     green_shift;
      l4_uint8_t     blue_size;
      l4_uint8_t     blue_shift;
      l4_uint8_t     reserved_size;
      l4_uint8_t     reserved_shift;
    } ramfb_config =
      {
        Vmm::Guest_addr(fb_addr).get(),
        (l4_uint32_t)fb_viewinfo.width,
        (l4_uint32_t)fb_viewinfo.height,
        (l4_uint32_t)fb_viewinfo.bytes_per_line,
        fb_viewinfo.pixel_info.bytes_per_pixel(),
        fb_viewinfo.pixel_info.r().size(),
        fb_viewinfo.pixel_info.r().shift(),
        fb_viewinfo.pixel_info.g().size(),
        fb_viewinfo.pixel_info.g().shift(),
        fb_viewinfo.pixel_info.b().size(),
        fb_viewinfo.pixel_info.b().shift(),
        fb_viewinfo.pixel_info.padding().size(),
        fb_viewinfo.pixel_info.padding().shift(),
      };

    static_assert(sizeof(ramfb_config) == 8 * 4,
                  "Size mismatch in e2dk_ramfb_config");
    Qemu_fw_cfg::put_file("etc/ramfb", (const char *)&ramfb_config,
                          sizeof(ramfb_config));
#endif // CONFIG_UVMM_QEMU_FW_IF

    return Vdev::make_device<Vdev::Fb_dev>();
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"simple-framebuffer", nullptr, &f};

} // namespace
