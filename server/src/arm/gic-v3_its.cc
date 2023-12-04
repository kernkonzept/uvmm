/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 */

#include <array>

#include <l4/cxx/utils>

#include "device_factory.h"
#include "gic-v3.h"
#include "msi_controller.h"

namespace {
using namespace Gic;

/**
 * In the GICv3 architecture the Interrupt Translation Service (ITS) provides
 * support for message-based interrupts, e.g. Message Signaled Interrupts (MSI).
 *
 * The guest configures the ITS to map the combination of a DeviceID and an
 * EventID to a Locality-specific Peripheral Interrupt (LPI) directed to a
 * redistributor (i.e. to a vCPU).
 *
 * To trigger an LPI, a device has to write the corresponding EventID to the
 * GITS_TRANSLATER register of the ITS. In our virtualized ITS, devices perform
 * this write access via the Msix_controller interface.
 *
 * A device tree entry needs to look like this:
 *
 *  its: msi-controller@f10c0000 {
 *    #msi-cells = <1>;
 *    compatible = "arm,gic-v3-its";
 *    reg = <0x0 0xf10c0000 0x0 0x20000>; // GITS
 *    msi-controller;
 *  };
 */
class Its :
  public Msix_controller,
  public Vdev::Device,
  public Vmm::Mmio_device_t<Its>
{
private:
  using Icid = l4_uint16_t;
  using Dev_id = l4_uint32_t;
  using Event_id = l4_uint32_t;

  enum
  {
    Lpi_base       = Cpu::Lpi_base,
    Num_lpis       = 512,

    /**
     * The GITS_TYPER.HCC (Hardware Collection Count) mechanism for holding
     * collections inside the ITS supports up to 256 collections. This matches
     * the value range of the Irq_info target field, which we use to store for
     * each LPI the collection ID (ICID) of the collection it is assigned to.
     * In order to handle the case where an LPI is not assigned to any
     * collection, we reserve the ICID 255 as the invalid collection.
     */
    Num_cols       = 255,
    Invalid_col    = Num_cols,

    Device_id_bits = 9,
    Num_devices    = 1 << Device_id_bits,
    /**
     * Our ITS model does not use the ITTs provided by the guest, therefore use
     * the minimum possible entry size.
     */
    Itt_entry_size = 1,

    Event_id_bits  = sizeof(l4_uint16_t) * 8,
    Num_events     = 1 << Event_id_bits,
  };

  enum
  {
    IID  = 0x43b,
    IID2 = 3 << 4,
    TYPE =   1 << 0 // ITS supports physical LPIs.
           | (Itt_entry_size - 1) << 4 // Bytes per ITT entry minus one.
           | (Event_id_bits - 1) << 8 // Supported EventID bits minus one.
           | (Device_id_bits - 1) << 13 // Supported DeviceID bits minus one.
           | 0 << 19 // Redist target address corresponds to the PE number.
           | (Num_cols - 1) << 24, // Supported interrupt collections minus one.
  };

  enum
  {
    GITS_CTLR         = 0x0000,
    GITS_IIDR         = 0x0004,
    GITS_TYPER        = 0x0008,
    GITS_CBASER       = 0x0080,
    GITS_CWRITER      = 0x0088,
    GITS_CREADR       = 0x0090,
    GITS_BASER        = 0x0100,
    GITS_PIDR2        = 0xffe8,
    GITS_ITS_BASE     = 0x10000,
    GITS_TRANSLATER   = GITS_ITS_BASE + 0x0040,

    GITS_CTLR_enabled   = 1U << 0,
    GITS_CTLR_quiescent = 1U << 31,

    GITS_cmd_queue_offset_mask = 0xfffe0,
  };

  struct Cbaser
  {
    l4_uint64_t raw = 0;
    CXX_BITFIELD_MEMBER          ( 0,  7, size, raw);
    CXX_BITFIELD_MEMBER          (10, 11, share, raw);
    CXX_BITFIELD_MEMBER_UNSHIFTED(12, 51, pa, raw);
    CXX_BITFIELD_MEMBER          (53, 55, outer_cache, raw);
    CXX_BITFIELD_MEMBER          (59, 61, inner_cache, raw);
    CXX_BITFIELD_MEMBER          (63, 63, valid, raw);

    enum { Ro_mask = 0 };

    unsigned size_bytes()
    { return (size() + 1) * 0x1000; }
  };

  struct Baser
  {
    l4_uint64_t raw = 0;

    CXX_BITFIELD_MEMBER          ( 0,  7, size, raw);
    CXX_BITFIELD_MEMBER          ( 8,  9, page_size, raw);
    CXX_BITFIELD_MEMBER          (10, 11, share, raw);
    CXX_BITFIELD_MEMBER_UNSHIFTED(12, 47, pa, raw);
    CXX_BITFIELD_MEMBER          (48, 52, entry_size, raw);
    CXX_BITFIELD_MEMBER          (53, 55, outer_cache, raw);
    CXX_BITFIELD_MEMBER          (56, 58, type, raw);
    CXX_BITFIELD_MEMBER          (59, 61, inner_cache, raw);
    CXX_BITFIELD_MEMBER          (62, 62, indirect, raw);
    CXX_BITFIELD_MEMBER          (63, 63, valid, raw);

    enum
    {
      Ro_mask = entry_size_bfm_t::Mask | type_bfm_t::Mask | indirect_bfm_t::Mask
    };

    enum Type
    {
      Type_none       = 0,
      Type_device     = 1,
      Type_vpe        = 2,
      Type_collection = 4,
    };

    explicit Baser(Type t)
    {
      type() = t;
      entry_size() = 0;
      indirect() = false;
    }
  };

public:
  explicit Its(Vdev::Device_lookup *devs)
  : _gic(dynamic_cast<Dist_v3 *>(devs->vmm()->gic().get())),
    _ram(devs->ram()),
    _lpis(Num_lpis, Lpi_base)
  {
    if (!_gic)
      L4Re::throw_error(-L4_EINVAL, "ITS requires GICv3");

    // Initially all collections are unmapped.
    _cols.fill(nullptr);

    for (unsigned i = 0; i < _lpis.size(); i++)
      {
        // LPIs have initially no collection or redistributor assigned.
        _lpis[i].target(Invalid_col, nullptr);
        // LPIs are always group 1 interrupts.
        _lpis[i].group(true);
      }

    _gic->register_lpis(&_lpis);
  }

  // Msix_controller interface
  Vcpu_obj_registry *send(l4_uint64_t, l4_uint64_t msix_data, l4_uint32_t src_id) const override
  {
    Dev_id dev_id = src_id;
    Event_id event_id = msix_data;

    Irq *lpi;
    {
      std::lock_guard<std::mutex> lock(_lock);
      // LPI lookup has to be protected with ITS lock.
      lpi = lookup_lpi(dev_id, event_id);
      if (!lpi)
        {
          warn().printf("LPI lookup for DeviceID %u and EventID %u failed!\n",
                        dev_id, event_id);
          return nullptr;
        }
    }

    return trigger_lpi(lpi);
  }

  l4_uint64_t read(unsigned reg, char size, unsigned)
  {
    unsigned r32 = reg & ~3u;

    std::lock_guard<std::mutex> lock(_lock);

    switch (r32)
      {
      case GITS_CTLR:
        return _enabled ? GITS_CTLR_enabled : GITS_CTLR_quiescent;

      case GITS_IIDR:
        return IID;

      case GITS_PIDR2:
        return IID2;

      case GITS_TYPER:
      case GITS_TYPER + 4:
        return Vmm::Mem_access::read((unsigned)TYPE, reg, size);

      case GITS_CBASER:
      case GITS_CBASER + 4:
        return _cmd_queue_baser.read(reg, size);

      case GITS_CWRITER:
        return _cmd_queue_write_off;

      case GITS_CREADR:
        return _cmd_queue_read_off;

      case GITS_BASER:
      case GITS_BASER + 4:
        return _device_table_baser.read(reg, size);

      default:
        return 0;
      }
  }

  void write(unsigned reg, char size, l4_uint64_t value, unsigned)
  {
    unsigned r32 = reg & ~3u;

    std::lock_guard<std::mutex> lock(_lock);

    switch (r32)
      {
      case GITS_CTLR:
        // For now, we do not support disabling the ITS (would require writing
        // all mapping data to the external memory provided by the guest, for
        // example the device table).
        if (!(value & GITS_CTLR_enabled))
          break;

        // Enabling the ITS is UNPREDICTABLE, if device table, collection table
        // or command queue are not valid.
        if (!_device_table_baser.valid() || !_cmd_queue_baser.valid())
          break;

        _enabled = true;
        process_its_cmds();
        break;

      case GITS_CBASER:
      case GITS_CBASER + 4:
        if (_enabled)
          break;

        _cmd_queue_baser.write(value, reg, size);
        // CREADER is reset to 0 when a value is written to GITS_CBASER.
        _cmd_queue_read_off = 0;

        if (_cmd_queue_baser.valid())
          {
            // Cache size and address of command queue
            _cmd_queue_size = _cmd_queue_baser.size_bytes();
            _cmd_queue_base = _ram->guest2host<l4_addr_t>(
              Vmm::Region::ss(Vmm::Guest_addr(_cmd_queue_baser.pa()),
                              _cmd_queue_size, Vmm::Region_type::Ram));
          }
        break;

      case GITS_CWRITER:
        _cmd_queue_write_off = value & GITS_cmd_queue_offset_mask;
        process_its_cmds();
        break;

      case GITS_CREADR:
        if (_enabled)
          break;

        _cmd_queue_read_off = value & GITS_cmd_queue_offset_mask;
        // Ensure command queue read offset is within command queue bounds.
        if (_cmd_queue_size != 0)
          _cmd_queue_read_off %= _cmd_queue_size;
        break;

      // Baser0: Device table
      case GITS_BASER:
      case GITS_BASER + 4:
        if (!_enabled)
          _device_table_baser.write(value, reg, size);
        break;

      // Baser1: Collection table - not present, to store collection mappings we
      // instead use the ITS internal storage mechanism (GITS_TYPER.HCC).

      default:
        break;
      }
  }

  char const *dev_name() const override { return "Its"; }

private:
  class Cmd
  {
  private:
    l4_uint64_t raw0 = 0;
    l4_uint64_t raw1 = 0;
    l4_uint64_t raw2 = 0;
    l4_uint64_t raw3 = 0;

  public:
    enum : unsigned { Size = 32 };

    enum Op
    {
      Op_movi    = 0x01,
      Op_int     = 0x03,
      Op_clear   = 0x04,
      Op_sync    = 0x05,
      Op_mapd    = 0x08,
      Op_mapc    = 0x09,
      Op_mapti   = 0x0a,
      Op_mapi    = 0x0b,
      Op_inv     = 0x0c,
      Op_invall  = 0x0d,
      Op_discard = 0x0f,
    };

    enum Err
    {
      Err_ok                         = 0,

      Err_movi_unmapped_interrupt    = 0x010107,
      Err_movi_unmapped_collection   = 0x010109,
      Err_int_unmapped_interrupt     = 0x010307,
      Err_clear_unmapped_interrupt   = 0x010507,
      Err_mapd_device_oor            = 0x010801,
      Err_mapd_ittsize_oor           = 0x010802,
      Err_mapc_collection_oor        = 0x010903,
      Err_mapti_device_oor           = 0x010A01,
      Err_mapti_collection_oor       = 0x010A03,
      Err_mapti_id_oor               = 0x010A05,
      Err_mapti_physicalid_oor       = 0x010A06,
      Err_inv_unmapped_interrupt     = 0x010C07,
      Err_invall_unmapped_collection = 0x010D09,
      Err_discard_device_oor         = 0x010F01,
      Err_discard_id_oor             = 0x010F05,
      Err_discard_unmapped_interrupt = 0x010F07,
    };

    Cmd() = default;

    CXX_BITFIELD_MEMBER          ( 0,  7, op, raw0);
    CXX_BITFIELD_MEMBER          (32, 63, dev_id, raw0);

    CXX_BITFIELD_MEMBER          ( 0, 31, event_id, raw1);
    CXX_BITFIELD_MEMBER          (32, 63, intid, raw1);
    CXX_BITFIELD_MEMBER          ( 0,  4, itt_size, raw1);

    CXX_BITFIELD_MEMBER          ( 0, 15, icid, raw2);
    CXX_BITFIELD_MEMBER          (16, 50, rd_base, raw2);
    CXX_BITFIELD_MEMBER_UNSHIFTED( 8, 51, itt_addr, raw2);
    CXX_BITFIELD_MEMBER          (63, 63, valid, raw2);
  };
  static_assert(sizeof(Cmd) == Cmd::Size, "Check sizeof(cmd)");

  // FIXME: We have to ensure that pending interrupts already written into a
  // list register are pulled out of it when their pending state or target
  // changes (e.g. movi, mapc, clear, discard, mapd)!

  /**
   * This command retargets an already mapped event to a different
   * redistributor.
   */
  Cmd::Err handle_cmd_movi(Dev_id dev_id, Event_id event_id, Icid icid)
  {
    trace().printf("CMD movi: dev_id=%u event_id=%u icid=%u\n",
                   dev_id, event_id, icid);

    Irq *lpi = lookup_lpi(dev_id, event_id);
    if (!lpi)
      return Cmd::Err_movi_unmapped_interrupt;

    Cpu *cpu = lookup_col(icid);
    if (!cpu)
      return Cmd::Err_movi_unmapped_collection;

    // Change the target ICID and CPU of the LPI to which the event is mapped.
    lpi->target(icid, cpu);
    return Cmd::Err_ok;
  }

  /**
   * This command sets the pending state of the specified LPI.
   */
  Cmd::Err handle_cmd_int(Dev_id dev_id, Event_id event_id)
  {
    trace().printf("CMD int: dev_id=%u event_id=%u\n", dev_id, event_id);

    Irq *lpi = lookup_lpi(dev_id, event_id);
    if (!lpi)
      return Cmd::Err_int_unmapped_interrupt;

    return trigger_lpi(lpi) ? Cmd::Err_ok : Cmd::Err_int_unmapped_interrupt;
  }

  /**
   * This command clears the pending state of the specified LPI.
   */
  Cmd::Err handle_cmd_clear(Dev_id dev_id, Event_id event_id)
  {
    trace().printf("CMD clear: dev_id=%u event_id=%u\n", dev_id, event_id);

    Irq *lpi = lookup_lpi(dev_id, event_id);
    if (!lpi)
      return Cmd::Err_clear_unmapped_interrupt;

    lpi->pending(false);
    return Cmd::Err_ok;
  }

  /**
   * This command ensures that the effects of all previous physical commands
   * associated with the specified redistributor are globally observable.
   */
  Cmd::Err handle_cmd_sync(unsigned rd_base)
  {
    trace().printf("CMD sync: rd_base=%u\n", rd_base);

    // Our ITS model is always in sync, thus we don't have to do anything here.
    return Cmd::Err_ok;
  }

  /**
   * This command maps a DeviceID to an interrupt translation table (ITT).
   */
  Cmd::Err handle_cmd_mapd(Dev_id dev_id, bool valid, l4_uint64_t itt_addr,
                           unsigned itt_size)
  {
    trace().printf("CMD mapd: dev_id=%u valid=%u itt_addr=0x%llx itt_size=%u\n",
                   dev_id, valid, itt_addr, itt_size);

    if (dev_id >= Num_devices)
      return Cmd::Err_mapd_device_oor;

    if (valid)
      {
        if (itt_size >= Event_id_bits)
          return Cmd::Err_mapd_ittsize_oor;

        // We don't have a dedicated per device ITT table, but instead use
        // an ITT table indexed by a composite DeviceID and EventID key.
        // Therefore, we don't have to do anything here.
        return Cmd::Err_ok;
      }
    else
      {
        unmap_device(dev_id);
        return Cmd::Err_ok;
      }
  }

  /**
   * This command maps a collection to a redistributor.
   */
  Cmd::Err handle_cmd_mapc(Icid icid, bool valid, unsigned rd_base)
  {
    trace().printf("CMD mapc: icid=%u valid=%u rd_base=%u\n",
                   icid, valid, rd_base);

    if (icid >= Num_cols)
      return Cmd::Err_mapc_collection_oor;

    if (valid)
      {
        Cpu *cpu = _gic->cpu(rd_base);
        if (!cpu)
          {
            // Mapping an invalid redistributor is UNPREDICTABLE, ignore this
            // mapping attempt!
            warn().printf("RDbase %u does not represent valid redistributor!\n",
                          rd_base);
            return Cmd::Err_ok;
          }

        // Map collection to redistributor (CPU)
        _cols[icid] = cpu;

        // Update target CPU of all LPIs mapped at this collection.
        lpis_for_col(icid, [=](Irq *lpi) { lpi->target(icid, cpu); });
      }
    else
      {
        // Unmap collection
        _cols[icid] = nullptr;

        // Untarget all LPIs that were targeted at this collection.
        lpis_for_col(icid, [=](Irq *lpi) { lpi->target(icid, nullptr); });
      }

    return Cmd::Err_ok;
  }

  /**
   * This command maps an event to an LPI targeted at the specified
   * redistributor.
   */
  Cmd::Err handle_cmd_mapti(Dev_id dev_id, Event_id event_id, unsigned intid,
                            Icid icid)
  {
    trace().printf("CMD mapti: dev_id=%u event_id=%u intid=%u icid=%u\n",
                   dev_id, event_id, intid, icid);

    if (dev_id >= Num_devices)
      return Cmd::Err_mapti_device_oor;

    if (icid >= Num_cols)
      return Cmd::Err_mapti_collection_oor;

    if (event_id >= Num_events)
      return Cmd::Err_mapti_device_oor;

    if (intid < Lpi_base || intid >= (Lpi_base + Num_lpis))
      return Cmd::Err_mapti_physicalid_oor;

    // Mapping an already mapped DeviceID-EventID combination is UNPREDICTABLE,
    // ignore this mapping attempt.
    if (lookup_lpi(dev_id, event_id))
      return Cmd::Err_ok;

    Irq *lpi = &_lpis[intid - Lpi_base];
    // LPI is already mapped for a different DeviceID-EventID
    // combination. Mapping multiple DeviceID-EventID combinations to
    // the same LPI is UNPREDICTABLE, ignore this mapping attempt.
    if (lpi->target() != Invalid_col)
      return Cmd::Err_ok;

    // Target CPU can be nullptr, if the ICID has not yet been mapped to a
    // redistributor.
    Cpu *cpu = lookup_col(icid);
    // First set the new target ICID and CPU.
    lpi->target(icid, cpu);
    // Then update the LPI config (might send a notify IRQ to the target vCPU).
    update_lpi_config(lpi);
    map_lpi(dev_id, event_id, lpi);
    return Cmd::Err_ok;
  }

  /**
   * This command ensures that any caching done by the redistributors
   * associated with the specified event is consistent with the LPI
   * configuration tables held in memory.
   */
  Cmd::Err handle_cmd_inv(Dev_id dev_id, Event_id event_id)
  {
    trace().printf("CMD inv: dev_id=%u event_id=%u\n", dev_id, event_id);

    Irq *lpi = lookup_lpi(dev_id, event_id);
    if (!lpi)
      return Cmd::Err_inv_unmapped_interrupt;

    update_lpi_config(lpi);
    return Cmd::Err_ok;
  }

  /**
   * This command ensures that any caching done by the redistributors
   * associated with the specified collection is consistent with the LPI
   * configuration tables held in memory.
   */
  Cmd::Err handle_cmd_invall(Icid icid)
  {
    trace().printf("CMD invall: icid=%u\n", icid);

    Cpu *cpu = lookup_col(icid);
    if (!cpu)
      return Cmd::Err_invall_unmapped_collection;

    lpis_for_col(icid, [=](Irq *lpi) { update_lpi_config(lpi); });

    return Cmd::Err_ok;
  }

  /**
   * This command removes the mapping for the specified event from the ITT and
   * resets the pending state of the corresponding LPI.
   */
  Cmd::Err handle_cmd_discard(Dev_id dev_id, Event_id event_id)
  {
    trace().printf("CMD discard: dev_id=%u event_id=%u\n", dev_id, event_id);

    if (dev_id >= Num_devices)
      return Cmd::Err_discard_device_oor;

    if (event_id >= Num_events)
      return Cmd::Err_discard_id_oor;

    if (!unmap_lpi(dev_id, event_id))
      return Cmd::Err_discard_unmapped_interrupt;

    return Cmd::Err_ok;
  }

  /**
   * Execute all commands pending in the ITS command queue.
   */
  void process_its_cmds()
  {
    if (!_enabled)
      return;

    while (_cmd_queue_read_off != _cmd_queue_write_off)
      {
        Cmd cmd = cxx::access_once(
          reinterpret_cast<Cmd *>(_cmd_queue_base + _cmd_queue_read_off));

        Cmd::Err res;
        switch(cmd.op())
          {
          case Cmd::Op_movi:
            res = handle_cmd_movi(cmd.dev_id(), cmd.event_id(), cmd.icid());
            break;
          case Cmd::Op_int:
            res = handle_cmd_int(cmd.dev_id(), cmd.event_id());
            break;
          case Cmd::Op_clear:
            res = handle_cmd_clear(cmd.dev_id(), cmd.event_id());
            break;
          case Cmd::Op_sync:
            res = handle_cmd_sync(cmd.rd_base());
            break;
          case Cmd::Op_mapd:
            res = handle_cmd_mapd(cmd.dev_id(), cmd.valid(), cmd.itt_addr(),
                                  cmd.itt_size() + 1);
            break;
          case Cmd::Op_mapc:
            res = handle_cmd_mapc(cmd.icid(), cmd.valid(), cmd.rd_base());
            break;
          case Cmd::Op_mapi:
            res = handle_cmd_mapti(cmd.dev_id(), cmd.event_id(), cmd.event_id(),
                                   cmd.icid());
            break;
          case Cmd::Op_mapti:
            res = handle_cmd_mapti(cmd.dev_id(), cmd.event_id(), cmd.intid(),
                                   cmd.icid());
            break;
          case Cmd::Op_inv:
            res = handle_cmd_inv(cmd.dev_id(), cmd.event_id());
            break;
          case Cmd::Op_invall:
            res = handle_cmd_invall(cmd.icid());
            break;
          case Cmd::Op_discard:
            res = handle_cmd_discard(cmd.dev_id(), cmd.event_id());
            break;
          default:
            warn().printf(
              "Skipped execution of unsupported command %u at offset 0x%x.\n",
              cmd.op().get(), _cmd_queue_read_off);
            res = Cmd::Err_ok;
            break;
          }

        if (res != Cmd::Err_ok)
          warn().printf(
            "Execution of command %u at offset 0x%x failed with error 0x%x.\n",
            cmd.op().get(), _cmd_queue_read_off, res);

        _cmd_queue_read_off = (_cmd_queue_read_off + Cmd::Size) % _cmd_queue_size;
      }
  }

  Cpu *lookup_col(Icid icid)
  {
    return icid < _cols.size() ? _cols[icid] : nullptr;
  }

  Irq *lookup_lpi(Dev_id dev_id, Event_id event_id) const
  {
    if (dev_id >= Num_devices || event_id >= Num_events)
      return nullptr;

    auto ite = _itt.find(Itt_key(dev_id, event_id));
    return ite != _itt.end() ? ite->second : nullptr;
  }

  void map_lpi(Dev_id dev_id, Event_id event_id, Irq *irq)
  {
    _itt[Itt_key(dev_id, event_id)] = irq;
  }

  bool unmap_lpi(Dev_id dev_id, Event_id event_id)
  {
    auto ite = _itt.find(Itt_key(dev_id, event_id));
    if (ite != _itt.end())
      {
        reset_lpi(ite->second);
        _itt.erase(ite);
        return true;
      }
    else
      return false;
  }

  /**
   * Unmap and reset all LPIs mapped for the given device.
   */
  void unmap_device(Dev_id dev_id)
  {
    for (auto ite = _itt.lower_bound(Itt_key(dev_id, 0)); ite != _itt.end();)
    {
        // ITT entries are ordered so that all entries of a device are
        // consecutive.
        if (ite->first.dev_id != dev_id)
          break;

        reset_lpi(ite->second);
        ite = _itt.erase(ite);
    }
  }

  /**
   * Updates the enable state and priority of the LPI from configuration
   * table of the redistributor it is mapped to.
   *
   * If the redistributor does not have LPIs enabled, the LPI is disabled.
   *
   * \pre LPI is mapped to a collection that is mapped to a valid redistributor.
   */
  void update_lpi_config(Irq *lpi)
  {
    assert(lpi->cpu() != Irq::Invalid_cpu);

    auto redist = _gic->redist(lpi->cpu());
    if (!redist || !redist->lpis_enabled())
      {
        lpi->enable(false);
        lpi->pending(false);
        return;
      }

    unsigned lpi_nr = lpi->id() - Lpi_base;

    lpi->prio(redist->lpi_priority(lpi_nr));

    Vcpu_handler *dest_cpu = lpi->enable(redist->lpi_enabled(lpi_nr));
    if (dest_cpu)
      dest_cpu->notify_irq();
  }

  void reset_lpi(Irq *lpi)
  {
    lpi->target(Invalid_col, nullptr);
    lpi->enable(false);
    lpi->pending(false);
  }

  Vcpu_obj_registry *trigger_lpi(Irq *lpi) const
  {
    // If the LPI does not target a valid CPU (e.g. the ICID assigned to the LPI
    // has not been mapped to a redistributor) or if the targeted redistributor
    // has LPIs disabled, ignore this attempt to make the LPI pending.
    auto redist = _gic->redist(lpi->cpu());
    if (!redist || !redist->lpis_enabled())
      return nullptr;

    _gic->set(lpi->id());
    return redist->ipc_registry();
  }

  template<typename C>
  void lpis_for_col(Icid icid, C callback)
  {
    for (auto const &ite : _itt)
    {
      auto lpi = ite.second;
      if (lpi->target() == icid)
        callback(lpi);
    }
  }

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "ITS"); }
  static Dbg info() { return Dbg(Dbg::Irq, Dbg::Info, "ITS"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "ITS"); }

  cxx::Ref_ptr<Dist_v3> _gic;
  cxx::Ref_ptr<Vmm::Vm_ram> _ram;

  /// Protects all operations performed on the ITS (MMIO accesses, command
  /// execution and LPI lookups). Also protects Irq migration, because
  /// Irq::target() relies on the caller to guard against concurrent calls.
  mutable std::mutex _lock;

  /// LPI IRQ array
  /// - Irq::target() stores the ICID to which the LPI is assigned.
  /// - Irq::cpu() refers to the vCPU targeted by the LPI, i.e. the
  ///   redistributor to which the ICID assigned to the LPI is mapped.
  Irq_array _lpis;

  /// Indicates whether the ITS is enabled.
  bool _enabled = false;

  /// BASER for command queue
  Gic_mem_reg<Cbaser> _cmd_queue_baser;
  l4_addr_t _cmd_queue_base = 0;
  l4_uint32_t _cmd_queue_size = 0;
  l4_uint32_t _cmd_queue_read_off = 0;
  l4_uint32_t _cmd_queue_write_off = 0;

  /// BASER for device table
  Gic_mem_reg<Baser> _device_table_baser = { Baser::Type_device };

  /// Internal collection table, maps collection to redistributor (vCPU),
  /// indexed by ICID.
  std::array<Cpu *, Num_cols> _cols;

  /// Orders ITT entries so that all entries of a device are consecutive.
  struct alignas(l4_uint32_t) Itt_key
  {
    Itt_key(Dev_id dev_id, Event_id event_id)
    : event_id(event_id), dev_id(dev_id)
    {
      // DeviceID fits into l4_uint16_t
      assert(dev_id <= 0xffffu);
      // EventID fits into l4_uint16_t
      assert(event_id <= 0xffffu);
    }

    const l4_uint16_t event_id;
    const l4_uint16_t dev_id;

    bool operator < (const Itt_key &o) const
    {
      // Allow the compiler to optimize this into a single comparison instruction.
      return   static_cast<l4_uint32_t>(dev_id << 16 | event_id)
             < static_cast<l4_uint32_t>(o.dev_id << 16 | o.event_id);
    }
  };

  /// Interrupt translation table, maps DeviceID and EventID to LPI.
  /// Invariant: Iff LPI in _itt then Irq:target() != Invalid_col
  std::map<Itt_key, Irq *> _itt;
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    auto its = Vdev::make_device<Its>(devs);
    devs->vmm()->register_mmio_device(its, Vmm::Region_type::Virtual, node);
    return its;
  }
};

static F f;
static Vdev::Device_type e = {"arm,gic-v3-its", nullptr, &f};

}
