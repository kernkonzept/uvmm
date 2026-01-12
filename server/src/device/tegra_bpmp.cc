/*
 * Copyright (C) 2026 Kernkonzept GmbH.
 * Author(s): Frank Mehnert <frank.mehnert@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <l4/cxx/utils>
#include <l4/drivers/hw_mmio_register_block>
#include <l4/drv/tegra/bpmp/bpmp_if.h>
#include <l4/sys/ktrace.h>

#include <l4/re/mmio_space>

#include "device_factory.h"
#include "guest.h"
#include "irq_dt.h"
#include "irq_svr.h"
#include "mmio_device.h"

namespace {

using namespace Vdev;

/**
 * \file
 * Device for connecting to the NVIDIA Tegra234 BPMP mailbox service.
 * \ingroup uvmm_devices
 *
 * This device emulation proxies guest accesses to an NVIDIA Tegra234 BPMP
 * mailbox device to either
 * - a real device (direct hardware access), or
 * - the 'tegra-bpmp' service performing device multiplexing for multiple
 *   clients.
 *
 * A device tree entry needs to look like this:
 *
 * \code{.dtb}
 *   hsp@3c00000 {
 *       compatible = "nvidia,tegra234-hsp", "nvidia,tegra194-hsp";
 *       reg = <0x03c00000 0xa0000>;
 *       interrupts = <GIC_SPI 176 IRQ_TYPE_LEVEL_HIGH>,
 *                    <GIC_SPI 120 IRQ_TYPE_LEVEL_HIGH>,
 *                    <GIC_SPI 121 IRQ_TYPE_LEVEL_HIGH>,
 *                    <GIC_SPI 122 IRQ_TYPE_LEVEL_HIGH>,
 *                    <GIC_SPI 123 IRQ_TYPE_LEVEL_HIGH>,
 *                    <GIC_SPI 124 IRQ_TYPE_LEVEL_HIGH>,
 *                    <GIC_SPI 125 IRQ_TYPE_LEVEL_HIGH>,
 *                    <GIC_SPI 126 IRQ_TYPE_LEVEL_HIGH>,
 *                    <GIC_SPI 127 IRQ_TYPE_LEVEL_HIGH>;
 *       interrupt-names = "doorbell", "shared0", "shared1", "shared2",
 *                         "shared3", "shared4", "shared5", "shared6",
 *                         "shared7";
 *       #mbox-cells = <2>;
 *   };
 *
 *   sram@40000000 {
 *       compatible = "nvidia,tegra234-sysram\0mmio-sram";
 *       reg = <0x00 0x40000000 0x00 0x80000>;
 *       #address-cells = <0x01>;
 *       #size-cells = <0x01>;
 *       ranges = <0x00 0x00 0x40000000 0x80000>;
 *       no-memory-wc;
 *       sram@70000 {
 *           reg = <0x70000 0x1000>;
 *           label = "cpu-bpmp-tx";
 *       };
 *       sram@71000 {
 *           reg = <0x71000 0x1000>;
 *           label = "cpu-bpmp-rx";
 *           pool;
 *       };
 *   };
 *
 *   bpmp {
 *       compatible = "nvidia,tegra234-bpmp\0nvidia,tegra186-bpmp";
 *           mboxes = <&hsp_top0 TEGRA_HSP_MBOX_TYPE_DB
 *                               TEGRA_HSP_DB_MASTER_BPMP>;
 *           shmem = <&cpu_bpmp_tx>, <&cpu_bpmp_rx>;
 *           #clock-cells = <0x01>;
 *           #reset-cells = <0x01>;
 *           #power-domain-cells = <0x01>;
 *           l4vmm,bpmp = "bpmp";
 *           ...
 *   };
 * \endcode
 *
 * This is the same layout as used by native Linux.
 * The 'hsp' device implements the doorbell interrupt, shared semaphores etc.
 * The 'sram' device implements the shared memory used by the BPMP device.
 */

static Dbg trace(Dbg::Dev, Dbg::Trace, "tegra-bpmp");
static Dbg warn(Dbg::Dev, Dbg::Warn, "tegra-bpmp");
// Log to cons from Uvmm virtual device
static constexpr bool Log_read_write = false;
// Log to kernel tracebuffer
static constexpr bool Trace_read_write = false;

////////////////////////////////////////////////////////////////////////////////
/**
 * Base MMIO proxy device.
 */
class Tegra_ioproxy_dev
{
  // Even on a 32-bit host a 64-bit memory access is possible but for now
  // we ignore this. Such an access would trigger an exception.
  static constexpr unsigned Max_mmio_width = sizeof(long) == 8 ? 64 : 32;

  /** An MMIO block with 64-bit registers and little endian byte order. */
  class Mmio_space_register_block_base
  {
  public:
    explicit Mmio_space_register_block_base(L4::Cap<L4Re::Mmio_space> mmio_space,
                                            l4_uint64_t phys, l4_uint64_t)
    : _mmio_space(mmio_space), _phys(phys) {}

    template< typename T >
    T read(l4_addr_t reg) const
    {
      l4_uint64_t value;
      L4Re::chksys(_mmio_space->mmio_read(_phys + reg, log2_size(T{0}), &value),
                   "Read bpmp Mmio_space register");
      return value;
    }

    template< typename T >
    void write(T value, l4_addr_t reg) const
    {
      L4Re::chksys(_mmio_space->mmio_write(_phys + reg, log2_size(T{0}), value),
                   "Write bpmp MMio_space register");
    }

  private:
    static constexpr char log2_size(l4_uint8_t)  { return 0; }
    static constexpr char log2_size(l4_uint16_t) { return 1; }
    static constexpr char log2_size(l4_uint32_t) { return 2; }
    static constexpr char log2_size(l4_uint64_t) { return 3; }

    L4::Cap<L4Re::Mmio_space> _mmio_space;
    l4_uint64_t _phys;
  };

  struct Mmio_space_register_block
  : L4drivers::Register_block_impl<Mmio_space_register_block, Max_mmio_width>,
    Mmio_space_register_block_base
  {
    using Mmio_space_register_block_base::Mmio_space_register_block_base;
  };

protected:
  void attach_iomem_resource(L4::Cap<L4vbus::Vbus> vbus, Dt_node const &node,
                             char const *devinfo_name,
                             l4vbus_resource_t const res)
  {
    char const *resname = reinterpret_cast<char const *>(&res.id);

    if (strncmp(resname, "reg", 3) || resname[3] < '0' || resname[3] > '9')
      L4Re::throw_error_fmt(
        -L4_EINVAL,
        "tegra-bpmp: Wrong IOMEM resource name (%s.%.4s)",
        devinfo_name, resname);
    unsigned resid = resname[3] - '0';

    l4_uint64_t dtaddr = 0, dtsize = 0;
    L4Re::chksys(
      node.get_reg_val(resid, &dtaddr, &dtsize),
      "tegra-bpmp: Match reg entry of device entry with vbus resource.");

    if (res.end - res.start + 1 != dtsize)
      L4Re::throw_error(
        -L4_ENOMEM,
        "tegra-bpmp: Matching resource size of VBUS resource and device tree entry");

    warn.printf("Adding MMIO for '%s.%.4s' : [0x%lx - 0x%lx]\n",
                devinfo_name, resname, res.start, res.end);
    if (auto mmio_space = L4::cap_dynamic_cast<L4Re::Mmio_space>(vbus))
      _regs = new Mmio_space_register_block(mmio_space, dtaddr, dtsize);
    else
      {
        L4Re::Rm::Flags rm_flags = L4Re::Rm::F::RW;
        if (res.flags & L4VBUS_RESOURCE_F_MEM_CACHEABLE)
          rm_flags |= L4Re::Rm::Region_flags::Cache_normal;
        else if (res.flags & L4VBUS_RESOURCE_F_MEM_PREFETCHABLE)
          rm_flags |= L4Re::Rm::Region_flags::Cache_buffered;
        else
          rm_flags |= L4Re::Rm::Region_flags::Cache_uncached;
        rm_flags |= L4Re::Rm::F::Search_addr;
        rm_flags |= L4Re::Rm::F::Eager_map;

        auto ds = L4::cap_reinterpret_cast<L4Re::Dataspace>(vbus);
        L4Re::chksys(L4Re::Env::env()->rm()->attach(&_regs_region, dtsize,
                                                    rm_flags, ds, dtaddr),
                     "tegra-bpmp: Attach iomem");
        _regs = new L4drivers::Mmio_register_block<Max_mmio_width>(_regs_region.get());
      }

    _regs_phys = dtaddr;
    _regs_size = dtsize;
  }

  l4_uint64_t _regs_phys = 0;
  l4_size_t   _regs_size = 0;
  L4drivers::Register_block<Max_mmio_width> _regs;

private:
  L4Re::Rm::Unique_region<l4_addr_t> _regs_region;
};

////////////////////////////////////////////////////////////////////////////////
template< class BPMP >
class Tegra_sram_dev
: public Vdev::Device,
  public Vmm::Mmio_device_t<Tegra_sram_dev<BPMP>>,
  public Tegra_ioproxy_dev
{
  /**
   * Dummy device for sram channels to provide device emulations for the
   * corresponding sram@70000 and sram@71000 sub devices to prevent the device
   * factory from adding io_proxy devices for them.
   *
   * The actual read/write access is trapped by Tegra_sram_dev.
   */
  class Sysram_channel : public Vdev::Device {};

public:
  Tegra_sram_dev(BPMP *bpmp, L4::Cap<L4vbus::Vbus> vbus,
                   L4vbus::Device const &dev, l4vbus_device_t const &devinfo,
                   Dt_node const &tx_node, Dt_node const &rx_node,
                   Dt_node const &node, Device_lookup *devs)
  : _bpmp(bpmp)
  {
    snprintf(_name, sizeof(_name), "%s", node.get_name());
    assert(tx_node.is_valid());
    assert(rx_node.is_valid());
    assert(node.is_valid());

    for (unsigned i = 0; i < devinfo.num_resources; ++i)
      {
        l4vbus_resource_t res;
        L4Re::chksys(dev.get_resource(i, &res),
                     "tegra-bpmp: Cannot get 'sram' resource");
        if (res.type == L4VBUS_RESOURCE_MEM)
          attach_iomem_resource(vbus, node, devinfo.name, res);
      }

    if (!_regs_size)
      L4Re::throw_error(-L4_EINVAL, "tegra-bpmp/sram: no memory resource found");

    chan_prop(tx_node, "cpu-bpmp-tx", &reg_offs_tx, &reg_size_tx);
    // need to add dummy device to prevent device factory from adding IO proxy
    auto tx_dev = Vdev::make_device<Sysram_channel>();
    devs->add_device(tx_node, tx_dev);

    chan_prop(rx_node, "cpu-bpmp-rx", &reg_offs_rx, &reg_size_rx);
    // need to add dummy device to prevent device factory from adding IO proxy
    auto rx_dev = Vdev::make_device<Sysram_channel>();
    devs->add_device(rx_node, rx_dev);
  }

  char const *dev_name() const override { return _name; }

  /**
   * Read from 'sram' MMIO.
   * Required by Mmio_device_t.
   */
  l4_uint64_t read(unsigned reg, char log2_size, unsigned)
  {
    l4_uint64_t val;
    switch (log2_size)
      {
      case 0: val = _regs.r<8>(reg); break;
      case 1: val = _regs.r<16>(reg); break;
      case 2: val = _regs.r<32>(reg); break;
      case 3:
        if constexpr (sizeof(long) == 8)
          {
            val = _regs.r<64>(reg);
            break;
          }
        [[fallthrough]];
      default: // cannot happen
        L4Re::throw_error_fmt(
          -L4_EINVAL, "tegra-bpmp: Reading '%s' invalid size %u", _name, log2_size);
      }
    if (Log_read_write)
      log_read(reg, log2_size, val);
    if (!access_in_tx_area(reg, log2_size) && !access_in_rx_area(reg, log2_size))
      {
        // The guest is allowed to read/write the full area and we forward
        // everything to the device. But device access was only tested for the
        // TX/RX areas. Warn once.
        static bool do_warn = true;
        if (!do_warn)
          {
            warn.printf("\033[31mread offset=%x => %.*llx\033[m\n",
                        reg, 2 << log2_size, val);
            do_warn = false;
          }
      }
    return val;
  }

  /**
   * Write to 'sram' MMIO.
   * Required by Mmio_device_t.
   */
  void write(unsigned reg, char log2_size, l4_uint64_t val, unsigned)
  {
    if (Log_read_write)
      log_write(reg, log2_size, val);
    if (!access_in_tx_area(reg, log2_size) && !access_in_rx_area(reg, log2_size))
      {
        // The guest is allowed to read/write the full area and we forward
        // everything to the device. But device access was only tested for the
        // TX/RX areas. Warn once.
        static bool do_warn = true;
        if (!do_warn)
          {
            warn.printf("\033[31mwrite offset=%x value=%.*llx\033[m\n",
                        reg, 2 << log2_size, val);
            do_warn = false;
          }
      }
    switch (log2_size)
      {
      case 0: _regs.r<8>(reg) = val; break;
      case 1: _regs.r<16>(reg) = val; break;
      case 2: _regs.r<32>(reg) = val; break;
      case 3:
         if constexpr (sizeof(long) == 8)
           {
             _regs.r<64>(reg) = val;
             break;
           }
         [[fallthrough]];
      default: // cannot happen
        L4Re::throw_error_fmt(
          -L4_EINVAL, "tegra-bpmp: Writing '%s' invalid size %u", _name, log2_size);
      }
  }
private:
  bool access_in_tx_area(unsigned offs, char log2_size) const
  {
    return offs >= reg_offs_tx
           && offs < reg_offs_tx + reg_size_tx - (1U << log2_size);
  }

  bool access_in_rx_area(unsigned offs, char log2_size) const
  {
    return offs >= reg_offs_rx
           && offs < reg_offs_rx + reg_size_rx - (1U << log2_size);
  }

  /**
   * Read channel properties from DT and verify the label.
   */
  void chan_prop(Dt_node const &node, char const *label_str,
                 unsigned *reg_offs, unsigned *reg_size)
  {
    int prop_size;
    char const *label = node.get_prop<char>("label", &prop_size);
    if (!label || strncmp(label, label_str, prop_size))
      L4Re::throw_error_fmt(
        -L4_EINVAL,
        "tegra-bpmp: 'shmem' property '%.*s' shall be 'cpu-bpmp-tx'",
        prop_size, label);
    l4_uint64_t addr, size;
    if (node.get_reg_val(0, &addr, &size) < 0)
      L4Re::throw_error_fmt(
        -L4_EINVAL, "tegra-bpmp: Cannot access reg[0] of '%s'", node.get_name());
    if (addr < _regs_phys || addr - _regs_phys + size > _regs_size)
      L4Re::throw_error(
        -L4_EINVAL, "tegra-bpmp: cpu-bpmp-tx exceeds parent device");
    *reg_offs = addr - _regs_phys;
    *reg_size = size;
  }

  /**
   * Client-side logging for read requests.
   *
   * Only useful under certain circumstances. Use the server-based logging
   * instead. Only active on Log_read_write = true.
   */
  void log_read(unsigned reg, char log2_size, l4_uint64_t val)
  {
    if (access_in_tx_area(reg, log2_size))
      {
        // TX channel
        unsigned offs = reg - reg_offs_tx;
        if (reg == 0x80)
          printf("read  tx: code = %08llx\n", val);
        if (Trace_read_write)
          fiasco_tbuf_log_3val("read  tx", offs + reg_offs_tx, log2_size, val);
      }
    else if (access_in_rx_area(reg, log2_size))
      {
        // RX channel
        if (Trace_read_write)
          fiasco_tbuf_log_3val("read  RX", reg, log2_size, val);
      }
  }

  /**
   * Client-side logging for write requests.
   *
   * Only useful under certain circumstances. Use the server-based logging
   * instead. Only active on Log_read_write = true.
   */
  void log_write(unsigned reg, char log2_size, l4_uint64_t val)
  {
    l4_uint32_t mrq = cxx::access_once(&_mrq);
    if (access_in_tx_area(reg, log2_size))
      {
        // TX channel
        unsigned offs = reg - reg_offs_tx;
        if (Trace_read_write)
          fiasco_tbuf_log_3val("WRITE tx", offs + reg_offs_tx, log2_size, val);
        if (offs == 0x70)
          ; // ignore
        else if (offs == 0x40)
          ; // ignore
        else if (offs == 0x80)
          {
            cxx::write_now(&_mrq, val); // remember for later
            if (   val == Tegra_bpmp_if::Mrq_reset::Mrq
                || val == Tegra_bpmp_if::Mrq_i2c::Mrq
                || val == Tegra_bpmp_if::Mrq_clk::Mrq
                || val == Tegra_bpmp_if::Mrq_thermal::Mrq
                || val == Tegra_bpmp_if::Mrq_pg::Mrq
                || val == Tegra_bpmp_if::Mrq_strap::Mrq
                || val == Tegra_bpmp_if::Mrq_debug::Mrq
               )
              ; // ignore
            else
              warn.printf("WRITE tx: \033[33;1mreq = %llu\033[m\n", val);
          }
        else if (offs == 0x88 && mrq == Tegra_bpmp_if::Mrq_reset::Mrq)
          {
            unsigned fn = val & 0xffffffff;
            char const *s = Tegra_bpmp_if::Mrq_reset::Req::fn_to_str(fn);
            if (log2_size == 3)
              {
                unsigned id = val >> 32;
                printf("WRITE tx: \033[33mreset / cmd=%u (%s), id=%x (%s)\033[m\n",
                       fn, s, id, Tegra_bpmp_if::Mrq_reset::Req::id_to_str(id));
              }
            else
              printf("WRITE tx: \033[33mreset / cmd=%u (%s)\033[m\n", fn, s);

          }
        else if (offs == 0x88 && mrq == Tegra_bpmp_if::Mrq_i2c::Mrq)
          {
            printf("WRITE tx: \033[33mi2c\033[m\n");
          }
        else if (offs == 0x88 && mrq == Tegra_bpmp_if::Mrq_clk::Mrq)
          {
            unsigned fn = (val >> 24) & 0xff;
            unsigned clk_id = val & 0xffffff;
            if (fn != 14)
              printf("WRITE tx: \033[33mclk / cmd=%u (%s), id=%x (%s)\033[m\n",
                     fn, Tegra_bpmp_if::Mrq_clk::Req::fn_to_str(fn), clk_id,
                     Tegra_bpmp_if::Mrq_clk::Req::id_to_str(clk_id));
          }
        else if (offs == 0x88 && mrq == Tegra_bpmp_if::Mrq_thermal::Mrq)
          {
            unsigned fn = val & 0xffffffff;
            char const *s = Tegra_bpmp_if::Mrq_thermal::Req::fn_to_str(fn);
            if (_log_therm)
              {
                printf("WRITE tx: \033[33mtherm / type=%u (%s)\033[m\n", fn, s);
                --_log_therm;
              }
          }
        else if (offs == 0x88 && mrq == Tegra_bpmp_if::Mrq_pg::Mrq)
          {
            unsigned fn = val & 0xffffffff;
            char const *s = Tegra_bpmp_if::Mrq_pg::Req::fn_to_str(fn);
            if (fn != 3)
              {
                if (log2_size == 3)
                  {
                    unsigned id = val >> 32;
                    printf("WRITE tx: \033[33mpg / cmd=%u (%s), id=%x (%s)\033[m\n",
                           fn, s, id, Tegra_bpmp_if::Mrq_pg::Req::id_to_str(id));
                  }
                else
                  printf("WRITE tx: \033[33mpg / cmd=%u (%s)\033[m\n", fn, s);
              }
          }
        else if (offs == 0x88 && mrq == Tegra_bpmp_if::Mrq_strap::Mrq)
          printf("WRITE tx: \033[33mstrap\033[m\n");
      }
    else if (access_in_rx_area(reg, log2_size))
      {
        // RX channel
        unsigned offs = reg - reg_offs_rx;
        if (Trace_read_write)
          fiasco_tbuf_log_3val("WRITE RX", offs + reg_offs_rx, log2_size, val);
        if (offs == 0x00)
          ; // ignore
        else if (offs == 0x40)
          ; // ignore
        else if (offs == 0x80)
          printf("WRITE RX: reg = %02llx\n", val);
      }
  }

  char _name[32];
  unsigned reg_offs_tx = 0;
  unsigned reg_size_tx = 0;
  unsigned reg_offs_rx = 0;
  unsigned reg_size_rx = 0;

  BPMP *_bpmp;

  // XXX logging
  l4_uint32_t _mrq = 0;
  l4_uint32_t _log_therm = 5;
};


////////////////////////////////////////////////////////////////////////////////
template< class BPMP >
class Tegra_hsp_dev
: public Vdev::Device,
  public Vmm::Mmio_device_t<Tegra_hsp_dev<BPMP>>,
  public Tegra_ioproxy_dev
{
  class Io_irq_svr : public Irq_svr
  {
  public:
    using Irq_svr::Irq_svr;
    unsigned get_io_irq() const { return _irq_num; }
  };

public:
  Tegra_hsp_dev(BPMP *bpmp, L4::Cap<L4vbus::Vbus> vbus, L4vbus::Device const &dev,
                l4vbus_device_t const &devinfo, Dt_node const &node,
                Device_lookup *devs)
  : _bpmp(bpmp)
  {
    snprintf(_name, sizeof(_name), "%s", node.get_name());

    L4vbus::Icu icu_dev;
    L4Re::chksys(vbus->root().device_by_hid(&icu_dev, "L40009"), "Request ICU");
    auto icu = L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4::Icu>(),
                            "tegra-bpmp: Allocate ICU cap");
    L4Re::chksys(icu_dev.vicu(icu), "Request ICU cap");

    for (unsigned i = 0; i < devinfo.num_resources; ++i)
      {
        l4vbus_resource_t res;
        L4Re::chksys(dev.get_resource(i, &res),
                     "tegra-bpmp: Cannot get 'hsp' resource");
        if (res.type == L4VBUS_RESOURCE_MEM)
          attach_iomem_resource(vbus, node, devinfo.name, res);
        else if (res.type == L4VBUS_RESOURCE_IRQ)
          bind_irq_resource(node, devinfo.name, icu, devs, res);
      }

    if (!_regs_size)
      L4Re::throw_error(-L4_EINVAL, "tegra-bpmp: no memory resource found");
  }

  char const *dev_name() const override { return _name; }

  /**
   * Read from 'hsp' MMIO.
   *
   * Linux: read 0x100
   *            ...
   *             0x11c:   common:        HSP_INT_{i]_IE (interrupt routing)
   * Linux: read 0x380:   common:        HSP_INT_DIMENSIONING
   * Linux: read 0x90104: HSP_DB_CCPLEX: HSP_DBELL_1_ENABLE
   * Linux: read 0x9010c: HSP_DB_CCPLEX: BPMP_DBELL_1_PENDING
   * Linux: read 0x90304: HSP_DB_BPMP:   HSP_DBELL_1_ENABLE
   */
  l4_uint64_t read(unsigned reg, char size, unsigned /* cpu_id */)
  {
    // Assume the guest does only 32-bit reads. This shall be correct for all
    // HSP registers except the 128-bit shared mailbox registers (Tegra234) but
    // those are apparently not used by Linux (TEGRA_HSP_MBOX_TYPE_SM_128BIT).
    if (size != 2)
      L4Re::throw_error(-L4_EINVAL, "tegra-bpmp: Can only handle 32-bit reads");
    if (reg < _regs_size)
      {
        l4_uint64_t val = _regs.r<32>(reg);
        if (Trace_read_write)
          fiasco_tbuf_log_3val("hsp/read", reg, size, val);
        trace.printf("\033[32mhsp::read offset=%02x size=%u => val=%llx\033[m\n",
                     reg, size, val);

        return val;
      }
    else
      L4Re::throw_error_fmt(-L4_EINVAL,
                            "tegra-bpmp: Reading 'hsp' invalid offset (%x)", reg);
  }

  /**
   * Write to 'hsp' MMIO.
   *
   * Linux: write 0x90104: HSP_DB_CCPLEX: HSP_DBELL_1_ENABLE
   * Linux: write 0x9010c: HSP_DB_CCPLEX: HSP_DBELL_1_PENDING
   * Linux: write 0x90300: HSP_DB_BPMP: HSP_DBELL1_TRIGGER
   */
  void write(unsigned reg, char size, l4_uint64_t val, unsigned /* cpu_id */)
  {
    // Assume the guest does only 32-bit reads. This shall be correct for all
    // HSP registers except the 128-bit shared mailbox registers (Tegra234) but
    // those are apparently not used by Linux (TEGRA_HSP_MBOX_TYPE_SM_128BIT).
    if (size != 2)
      L4Re::throw_error(-L4_EINVAL, "tegra-bpmp: Can only handle 32-bit writes");
    if (reg < _regs_size)
      {
        if (Trace_read_write)
          fiasco_tbuf_log_3val("hsp/writ", reg, size, val);
        trace.printf("\033[32mhsp::write offset=%02x size=%u val=%llx\033[m\n",
                     reg, size, val);
        _regs.r<32>(reg) = val;

      }
    else
      L4Re::throw_error_fmt(-L4_EINVAL,
                            "tegra-bpmp: Writing 'hsp' invalid offset (%x)", reg);
  }

private:
  void bind_irq_resource(Dt_node const &node, char const *devinfo_name,
                         L4::Cap<L4::Icu> icu, Device_lookup *devs,
                         l4vbus_resource_t res)
  {
    char const *resname = reinterpret_cast<char const *>(&res.id);
    if (strncmp(resname, "irq", 3) || resname[3] < '0' || resname[3] > '9')
      L4Re::throw_error_fmt(-L4_ENOMEM,
                            "tegra-bpmp: Wrong IRQ resource name (%s.%.4s)",
                            devinfo_name, resname);
    unsigned resid = resname[3] - '0';

    auto it = Irq_dt_iterator(devs, node);
    it.next(devs);

    for (unsigned n = 0; n < resid; ++n)
      it.next(devs);

    if (it.ic_is_virt())
      {
        warn.printf("Registering IRQ resource %s.%.4s : %lx\n",
                    devinfo_name, resname, res.start);
        int dt_irq = it.irq();
        bind_irq(devs->vmm(), icu, it.ic(), dt_irq, res.start);
      }
  }

  void bind_irq(Vmm::Guest *vmm, L4::Cap<L4::Icu> icu,
                cxx::Ref_ptr<Gic::Ic> const &ic,
                unsigned dt_irq, unsigned io_irq)
  {
    auto *irq_source = ic->get_irq_src_handler(dt_irq);
    if (!irq_source)
      {
        auto irq_svr =
          cxx::make_ref_obj<Io_irq_svr>(vmm->registry(), icu, io_irq, ic, dt_irq);
        irq_svr->eoi();

        _irqs.push_back(std::move(irq_svr));
        return;
      }

    auto other_svr = dynamic_cast<Io_irq_svr *>(irq_source);
    if (!other_svr)
      {
        Err().printf("ic:%u is bound to a different IRQ type\n", dt_irq);
        L4Re::chksys(-L4_EEXIST, "tegra-bpmp: Bind IRQ for IO proxy object.");
      }

    if (io_irq != other_svr->get_io_irq())
      {
        Err().printf("bind_irq: %u -> ic:%u -- "
                     "IRQ already bound to different IO IRQ: %u\n",
                     io_irq, dt_irq, other_svr->get_io_irq());
        L4Re::chksys(-L4_EEXIST, "tegra-bpmp: Bind IRQ for IO proxy object.");
      }

    // Take a reference of the existing IRQ handler.
    _irqs.emplace_back(other_svr);
  }

  char _name[32];
  BPMP *_bpmp;
  std::vector<cxx::Ref_ptr<Io_irq_svr>> _irqs;
};

////////////////////////////////////////////////////////////////////////////////
class Tegra_bpmp_dev
: public Vdev::Device
{
public:
  Tegra_bpmp_dev(L4::Cap<L4vbus::Vbus> vbus, Device_lookup *devs,
                 Dt_node const &bpmp_node)
  {
    int prop_size;

    // Lookup device tree for bpmp { mboxes = <phandle, ... };
    auto *mboxes_prop = bpmp_node.get_prop<fdt32_t>("mboxes", &prop_size);
    if (!mboxes_prop)
      L4Re::throw_error(-L4_ENODEV, "tegra-bpmp: No 'mboxes' property");
    if (prop_size != 3)
      L4Re::throw_error_fmt(
        -L4_ENODEV,
        "tegra-bpmp: 'mboxes' property wrong size (%d != 3)", prop_size);

    // bpmp/mboxes[0]: hsp@3c00000
    Dt_node const hsp_node = bpmp_node.find_phandle(mboxes_prop[0]);
    if (!hsp_node.is_valid())
      L4Re::throw_error(-L4_EINVAL, "tegra-bpmp: couldn't find 'hsp' phandle");

    l4vbus_device_t devinfo;
    L4vbus::Device hsp_dev;
    L4Re::chksys(vbus->root().device_by_hid(&hsp_dev, "tegra234-hsp",
                                            L4VBUS_MAX_DEPTH, &devinfo),
                 "tegra-bpmp: Locate device with hid='tegra234-hsp' on vbus");
    _hsp = Vdev::make_device<Tegra_hsp_dev<Tegra_bpmp_dev>>(
                               this, vbus, hsp_dev, devinfo, hsp_node, devs);
    devs->vmm()->register_mmio_device(_hsp, Vmm::Region_type::Virtual, hsp_node, 0);

    if (L4Re::Env::env()->task()->cap_equal(vbus, devs->vbus()->bus()).label())
      {
        // vbus provided by IO server -- mark device as used on system vbus
        auto *vdev = devs->vbus()->find_unassigned_device_by_hid("tegra234-hsp");
        vdev->set_handler(_hsp);
      }
    devs->add_device(hsp_node, _hsp);

    // Lookup device tree for bpmp { shmem = <cpu_bpmp_tx, cpu_bpmp_rx };
    auto *shmem_prop = bpmp_node.get_prop<fdt32_t>("shmem", &prop_size);
    if (!shmem_prop)
      L4Re::throw_error(-L4_ENODEV, "tegra-bpmp: No 'shmem' property");
    if (prop_size != 2)
      L4Re::throw_error_fmt(
        -L4_ENODEV,
        "tegra-bpmp: 'shmem' property wrong size (%d != 2", prop_size);
    // bpmp/shmem[0]: sram@70000/cpu-bpmp-tx
    Dt_node const sram_tx_node = bpmp_node.find_phandle(shmem_prop[0]);
    if (!sram_tx_node.is_valid())
      L4Re::throw_error(-L4_EINVAL, "tegra-bpmp: couldn't find 'shmem-tx' phandle");
    Dt_node const sram_rx_node = bpmp_node.find_phandle(shmem_prop[1]);
    if (!sram_rx_node.is_valid())
      L4Re::throw_error(-L4_EINVAL, "tegra-bpmp: couldn't find 'shmem-rx' phandle");
    if (sram_tx_node.parent_node() != sram_rx_node.parent_node())
      L4Re::throw_error(-L4_EINVAL, "tegra-bpmp: shmem don't belong to same node");

    // sram@40000000
    Dt_node const sram_node = sram_tx_node.parent_node();

    L4vbus::Device sram_dev;
    L4Re::chksys(vbus->root().device_by_hid(&sram_dev, "tegra234-sysram",
                                            L4VBUS_MAX_DEPTH, &devinfo),
                 "tegra-bpmp: Locate device with hid='tegra234-sysram' on vbus");
    _sram = Vdev::make_device<Tegra_sram_dev<Tegra_bpmp_dev>>(
                                  this, vbus, sram_dev, devinfo,
                                  sram_tx_node, sram_rx_node, sram_node,
                                  devs);
    devs->vmm()->register_mmio_device(_sram, Vmm::Region_type::Virtual,
                                      sram_node, 0);

    if (L4Re::Env::env()->task()->cap_equal(vbus, devs->vbus()->bus()).label())
      {
        // vbus provided by IO server -- mark device as used
        auto *vdev = devs->vbus()->find_unassigned_device_by_hid("tegra234-sysram");
        vdev->set_handler(_sram);
      }
    devs->add_device(sram_node, _sram);
  }

  virtual ~Tegra_bpmp_dev() = default;

private:
  cxx::Ref_ptr<Tegra_hsp_dev<Tegra_bpmp_dev>> _hsp;
  cxx::Ref_ptr<Tegra_sram_dev<Tegra_bpmp_dev>> _sram;
};

struct F_bpmp : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Device_lookup *devs,
                                    Dt_node const &node) override
  {
    /*
     * "Private" vbus for bpmp/hsp/sram as part of 'bpmp' device entry.
     * Either provided by the IO server (then, vbus == devs->vbus) or by a
     * separate driver implementing the L4vbus interface for these devices.
     */
    auto cap = L4Re::chkcap(Vdev::get_cap<L4vbus::Vbus>(node, "l4vmm,bpmp"),
                            "Determine \"bpmp\" capability for BPMP device",
                            -L4_ENOENT);
    return Vdev::make_device<Tegra_bpmp_dev>(cap, devs, node);
  }
};

static F_bpmp f_bpmp;
static Vdev::Device_type t_bpmp = { "nvidia,tegra234-bpmp", nullptr, &f_bpmp };

} // namespace
