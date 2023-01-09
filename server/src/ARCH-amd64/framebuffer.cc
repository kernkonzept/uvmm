/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021-2022 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 */

#include <l4/re/video/goos>

#include "guest.h"

static bool fb_present = false;
static l4_uint64_t fb_addr, fb_size;
static L4Re::Video::View::Info fb_viewinfo;

namespace Vdev {
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
  Video_type_vlfb = 0x23
};

enum {
  Video_capability_skip_quirks = (1 << 0),
  /* Frame buffer base is 64-bit */
  Video_capability_64bit_base = (1 << 1)
};

static void configure_framebuffer(void *zeropage)
{
  auto *si = reinterpret_cast<struct screen_info *>(zeropage);

  // define framebuffer type
  si->orig_video_isVGA = Video_type_vlfb;
  si->capabilities = Video_capability_skip_quirks | Video_capability_64bit_base;

  // setup address and size of buffer
  si->lfb_base = fb_addr & 0xffffffff;
  si->ext_lfb_base = fb_addr >> 32;
  // framebuffer size is in 64 KiB chunks for VLFB per historical convention
  si->lfb_size = l4_round_size(fb_size, 16) >> 16;

  // define dimensions
  si->lfb_width  = fb_viewinfo.width;
  si->lfb_height = fb_viewinfo.height;
  si->lfb_linelength = fb_viewinfo.bytes_per_line;

  // define color
  si->lfb_depth  = fb_viewinfo.pixel_info.bytes_per_pixel() * 8;
  si->red_size   = fb_viewinfo.pixel_info.r().size();
  si->red_pos    = fb_viewinfo.pixel_info.r().shift();
  si->green_size = fb_viewinfo.pixel_info.g().size();
  si->green_pos  = fb_viewinfo.pixel_info.g().shift();
  si->blue_size  = fb_viewinfo.pixel_info.b().size();
  si->blue_pos   = fb_viewinfo.pixel_info.b().shift();
  si->rsvd_size  = fb_viewinfo.pixel_info.padding().size();
  si->rsvd_pos   = fb_viewinfo.pixel_info.padding().shift();
}
} // namespace Vdev

namespace Vmm {
bool
Guest::register_framebuffer(l4_uint64_t addr, l4_uint64_t size,
                            const L4Re::Video::View::Info &info)
{
  if (fb_present)
    {
      Err().printf("0x%llx: Multiple definitions of framebuffer, only one framebuffer is supported\n",
                   addr);
      return false;
    }

  fb_present = true;
  fb_addr = addr;
  fb_size = size;
  fb_viewinfo = info;
  Vmm::Zeropage::set_screen_callback(Vdev::configure_framebuffer);
  return true;
}
} // namespace Vmm
