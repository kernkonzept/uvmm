/*
 * Copyright (C) 2021-2025 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 *            Stephan Gerhold <stephan.gerhold@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <l4/re/util/video/goos_fb>
#include <l4/cxx/exceptions>

#include "device.h"
#include "device_factory.h"
#include "device_tree.h"

#include "ds_mmio_mapper.h"
#include "ds_manager.h"
#include "timer.h"
#include "guest.h"

#ifdef CONFIG_UVMM_QEMU_FW_IF
#include "qemu_fw_cfg.h"
#endif

namespace Vdev {

/**
 * Simple framebuffer device.
 *
 * A device tree entry needs to look like this:
 *
 * \code{.dtb}
 *   simplefb {
 *       compatible = "simple-framebuffer";
 *       reg = <0x0 0xf0000000 0x0 0x1000000>;
 *       l4vmm,fbcap = "fb";
 *   };
 * \endcode
 *
 * The `l4vmm,fbcap` property is mandatory and needs to point to a capability
 * implementing an L4Re::Util::Video::Goos_fb interface. If there is no
 * capability with the given name, then the device will be disabled.
 *
 * The `reg` property is also mandatory and defines the physical address and
 * the size (in bytes) of the linear framebuffer. The size of the framebuffer
 * is updated according to the actual framebuffer properties provided by the
 * capability.
 *
 * Furthermore, the `width`, `height`, `stride` and `format` properties are
 * added to the device tree entry according to the actual framebuffer
 * properties provided by the capability.
 *
 * If the framebuffer capability does not implement the auto-refresh feature,
 * the framebuffer is actively refreshed with a refresh rate of 30 Hz. This
 * default refresh rate can be overrided by the optional `l4vmm,refresh_rate`
 * property.
 */
class Framebuffer : public Vdev::Device,
                    public Vdev::Timer,
                    public L4::Ipc_svr::Timeout_queue::Timeout
{
public:
  /// Default refresh rate of 30 Hz.
  static constexpr unsigned Default_refresh_rate = 30;

  /**
   * Framebuffer device constructor.
   *
   * \param[in] gfb             Goos framebuffer.
   * \param[in] width           Framebuffer width in pixels.
   * \param[in] height          Framebuffer height in pixels.
   * \param[in] active_refresh  If true then the framebuffer requires active
   *                            refresh (it does not have the auto-refresh
   *                            feature).
   * \param[in] refresh_rate    Framebuffer refresh rate (used primarily for
   *                            the active refresh, but could be used for other
   *                            purposes as well). Defaults to
   *                            #Default_refresh_rate if unspecified.
   */
  Framebuffer(cxx::unique_ptr<L4Re::Util::Video::Goos_fb> gfb,
              unsigned long width, unsigned long height,
              bool active_refresh,
              unsigned refresh_rate = Default_refresh_rate) :
    _gfb(cxx::move(gfb)), _width(width), _height(height),
    _active_refresh(active_refresh), _refresh_rate(refresh_rate)
  {
    assert(_refresh_rate > 0);
  }

  ~Framebuffer() {}

  /**
   * Start the active refresh (if necessary) by enqueuing a refresh timeout.
   */
  void ready() override
  {
    if (_active_refresh)
      enqueue_timeout(this, next_timeout_us());
  }

  /**
   * Actively refresh the framebuffer and enqueue the next refresh timeout
   * (if necessary).
   */
  void expired() override
  {
    _gfb->refresh(0, 0, _width, _height);

    if (_active_refresh)
      requeue_timeout(this, next_timeout_us());
  }

private:
  enum
  {
    Microseconds_per_second = 1000000ULL,
  };

  /**
   * Next absolute timeout in microseconds.
   */
  inline l4_kernel_clock_t next_timeout_us() const
  {
    assert(_active_refresh);

    l4_kernel_clock_t clock = l4_kip_clock(l4re_kip());
    l4_kernel_clock_t period = Microseconds_per_second / _refresh_rate;

    return clock + period;
  }

  cxx::unique_ptr<L4Re::Util::Video::Goos_fb> _gfb;
  unsigned long _width;
  unsigned long _height;
  bool _active_refresh;
  unsigned _refresh_rate;
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
    if (auto err = gfb->init(cap_name))
      {
        warn.printf("fbdrv initialization failed: %s\n", l4sys_errtostr(err));
        return 0;
      }

    L4Re::Video::Goos::Info info;
    if (auto err = gfb->goos()->info(&info))
      {
        warn.printf("Failed to get framebuffer information: %s\n",
                    l4sys_errtostr(err));
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

    bool auto_refresh = info.auto_refresh();
    unsigned refresh_rate = Vdev::Framebuffer::Default_refresh_rate;

    // Allow to override the refresh rate by the l4vmm,refresh_rate property.
    int refresh_size;
    auto *refresh_prop = node.get_prop<fdt32_t>("l4vmm,refresh_rate", &refresh_size);
    if (refresh_prop)
      {
        refresh_rate = node.get_prop_val(refresh_prop, refresh_size, 0);
        if (refresh_rate == 0)
          {
            refresh_rate = 1;
            warn.printf("Forcing framebuffer refresh rate to %u Hz.\n",
                        refresh_rate);
          }
      }
    else if (!auto_refresh)
      warn.printf("Using default framebuffer refresh rate of %u Hz.\n",
                  refresh_rate);

    auto mgr = cxx::make_ref_obj<Vmm::Ds_manager>("Framebuffer", gfb->buffer(),
                                                 0, gfb->buffer()->size());
    auto handler = Vdev::make_device<Ds_handler>(mgr);
    auto dev = Vdev::make_device<Vdev::Framebuffer>(cxx::move(gfb), info.width,
                                                    info.height,
                                                    !info.auto_refresh(),
                                                    refresh_rate);

    devs->vmm()->add_mmio_device(
                   Vmm::Region::ss(Vmm::Guest_addr(fb_addr), fb_size,
                                   Vmm::Region_type::Vbus), handler);
    devs->vmm()->register_timer_device(dev);

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

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"simple-framebuffer", nullptr, &f};

} // namespace
