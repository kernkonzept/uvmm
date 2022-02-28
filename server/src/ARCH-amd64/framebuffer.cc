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

static bool fb_present = false;
static l4_uint64_t fb_addr, fb_size;
static L4Re::Video::View::Info fb_viewinfo;

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

// Taken from linux/include/uapi/linux/screen_info.h
struct screen_info {
	l4_uint8_t  orig_x;		/* 0x00 */
	l4_uint8_t  orig_y;		/* 0x01 */
	l4_uint16_t ext_mem_k;	/* 0x02 */
	l4_uint16_t orig_video_page;	/* 0x04 */
	l4_uint8_t  orig_video_mode;	/* 0x06 */
	l4_uint8_t  orig_video_cols;	/* 0x07 */
	l4_uint8_t  flags;		/* 0x08 */
	l4_uint8_t  unused2;		/* 0x09 */
	l4_uint16_t orig_video_ega_bx;/* 0x0a */
	l4_uint16_t unused3;		/* 0x0c */
	l4_uint8_t  orig_video_lines;	/* 0x0e */
	l4_uint8_t  orig_video_isVGA;	/* 0x0f */
	l4_uint16_t orig_video_points;/* 0x10 */

	/* VESA graphic mode -- linear frame buffer */
	l4_uint16_t lfb_width;	/* 0x12 */
	l4_uint16_t lfb_height;	/* 0x14 */
	l4_uint16_t lfb_depth;	/* 0x16 */
	l4_uint32_t lfb_base;		/* 0x18 */
	l4_uint32_t lfb_size;		/* 0x1c */
	l4_uint16_t cl_magic, cl_offset; /* 0x20 */
	l4_uint16_t lfb_linelength;	/* 0x24 */
	l4_uint8_t  red_size;		/* 0x26 */
	l4_uint8_t  red_pos;		/* 0x27 */
	l4_uint8_t  green_size;	/* 0x28 */
	l4_uint8_t  green_pos;	/* 0x29 */
	l4_uint8_t  blue_size;	/* 0x2a */
	l4_uint8_t  blue_pos;		/* 0x2b */
	l4_uint8_t  rsvd_size;	/* 0x2c */
	l4_uint8_t  rsvd_pos;		/* 0x2d */
	l4_uint16_t vesapm_seg;	/* 0x2e */
	l4_uint16_t vesapm_off;	/* 0x30 */
	l4_uint16_t pages;		/* 0x32 */
	l4_uint16_t vesa_attributes;	/* 0x34 */
	l4_uint32_t capabilities;     /* 0x36 */
	l4_uint32_t ext_lfb_base;	/* 0x3a */
	l4_uint8_t  _reserved[2];	/* 0x3e */
} __attribute__((packed));

enum {
  Video_capability_skip_quirks = (1 << 0),
  /* Frame buffer base is 64-bit */
  Video_capability_64bit_base = (1 << 1)
};

static void configure_framebuffer(void *zeropage)
{
  auto *si = reinterpret_cast<struct screen_info *>(zeropage);

  // define framebuffer type
  si->orig_video_isVGA = 0x23;
  si->capabilities = Video_capability_skip_quirks | Video_capability_64bit_base;

  // setup address and size of buffer
  si->lfb_base = fb_addr & 0xffffffff;
  si->ext_lfb_base = fb_addr >> 32;
  si->lfb_size = fb_size;

  // define dimensions
  si->lfb_width  = fb_viewinfo.width;
  si->lfb_height = fb_viewinfo.height;
  si->lfb_linelength = fb_viewinfo.bytes_per_line;

  // define color
  si->lfb_depth  = fb_viewinfo.pixel_info.bits_per_pixel();
  si->red_size   = fb_viewinfo.pixel_info.r().size();
  si->red_pos    = fb_viewinfo.pixel_info.r().shift();;
  si->green_size = fb_viewinfo.pixel_info.g().size();;
  si->green_pos  = fb_viewinfo.pixel_info.g().shift();;;
  si->blue_size  = fb_viewinfo.pixel_info.b().size();;
  si->blue_pos   = fb_viewinfo.pixel_info.b().shift();;;
  si->rsvd_size  = 0;
  si->rsvd_pos   = 0;
}
} // namespace Vmm

// Factory section
namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    if (fb_present)
      {
        Err().printf("%s: Multiple definitions of framebuffer, only one framebuffer is supported\n",
                     node.get_name());
        return 0;
      }

    int psize;
    char const *prop = "l4vmm,cap";
    char const *cap_name = node.get_prop<char>(prop, &psize);
    if (!cap_name)
      {
        Err().printf("%s: Failed to get property '%s': %s\n", node.get_name(),
                     prop, fdt_strerror(psize));
        return 0;
      }

    int res = node.get_reg_val(0, &fb_addr, &fb_size);
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
        Err().printf("fbdrv setup failed: %s", e.str());

        char const *msg = e.extra_str();
        if (msg)
          Err().printf(": %s", msg);
        Err().printf("\n");
        return 0;
      }
    catch (...)
      {
        Err().printf("fbdrv setup failed with unknown exception");
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

    if (auto err = gfb->view_info(&fb_viewinfo))
      {
        Err().printf("Failed to get view information: %s\n",
                     l4sys_errtostr(err));
        return 0;
      }

    size_t size = gfb->buffer()->size();
    if (fb_size < size)
      {
        Err().printf("Invalid reg entry '%s'.reg[%d]: Too small, need 0x%zx bytes\n",
                     node.get_name(), 0, size);
        return 0;

      }
    auto handler = Vdev::make_device<Ds_handler>(
                     cxx::make_ref_obj<Vdev::Framebuffer>(cxx::move(gfb)));
    devs->vmm()->add_mmio_device(
                   Vmm::Region::ss(Vmm::Guest_addr(fb_addr), fb_size,
                                   Vmm::Region_type::Vbus), handler);

    fb_present = true;
    Vmm::Zeropage::set_screen_callback(Vdev::configure_framebuffer);

    return Vdev::make_device<Vdev::Fb_dev>();
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"simple-framebuffer", nullptr, &f};

} // namespace
