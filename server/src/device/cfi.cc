/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Jan Klötzke <jan.kloetzke@kernkonzept.com>
 */

#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <l4/sys/cxx/ipc_epiface>
#include <l4/re/error_helper>

#include "debug.h"
#include "device_factory.h"
#include "guest.h"
#include "mmio_device.h"

namespace {

/**
 * Simple CFI compliant flash with Intel command set.
 *
 * This supports only a bytewide virtual device (x8). Example device tree:
 *
 * flash@ffc00000 {
 *     compatible = "cfi-flash";
 *     reg = <0x0 0xffc00000 0x0 0x84000>;
 *     l4vmm,dscap = "capname";
 * };
 *
 * The optional "read-only" property will make the device read-only. If the
 * dataspace 'capname' is read-only but the 'read-only' property is not set,
 * this emulation will make the flash device read-only as well (but give a
 * warning about it).
 *
 * How to make the dscap writable:
 * 1. Load the bootmodule (modules.list):
 *    module OVMF_VARS.fd :rw
 * 2. Add the bootmodule to the caps table of uvmm:
 *    uvmm_caps = {
 *      capname = L4.Env.rwfs:query("OVMF_VARS.fd", 7),
 *    }
 *    L4.Env.loader:startv(caps=uvmm_caps, "rom/uvmm")
 *
 * Notes about the CFI emulation.
 * - CFI operates in either read or write-mode
 * - in read-mode the flash acts like RAM and Linux will use the full
 *   instruction set to read it(*)
 * - in write mode Linux handles the device like an MMIO device
 * - read-mode is emulated by mapping the DS in read-only fashion to the guest
 * - if switched to write mode, we unmap the DS and emulate individual accesses
 * (*) Full emulation of read-mode would not be very performant and
 *     require a full instruction decoder, which --for x86-- we do not have
 *     and do not want.
 */
class Cfi_flash
: public Vmm::Mmio_device,
  public Vdev::Device
{
  enum
  {
    Cmd_write_byte = 0x10,
    Cmd_block_erase = 0x20,
    Cmd_clear_status = 0x50,
    Cmd_read_status = 0x70,
    Cmd_read_device_id = 0x90,
    Cmd_cfi_query = 0x98,
    Cmd_program_erase_suspend = 0xb0,
    Cmd_block_erase_confirm = 0xd0,
    Cmd_read_array = 0xff,

    Status_ready = 1 << 7,
    Status_erase_error = 1 << 5,
    Status_program_error = 1 << 4,

    Cfi_table_size = 0x38,
  };

public:
  enum
  {
    Erase_block_size = 0x1000, // Must be a power of 2
  };

  Cfi_flash(L4::Cap<L4Re::Dataspace> ds, size_t size, bool ro)
  : _size(size), _ro(ro)
  {
    _mgr = cxx::make_unique<Vmm::Ds_manager>(ds, 0, _size,
                                             ro ? L4Re::Rm::F::R : L4Re::Rm::F::RW);

    // Fill CFI table. See JESD6801...
    _cfi_table[0x10] = 'Q';
    _cfi_table[0x11] = 'R';
    _cfi_table[0x12] = 'Y';
    _cfi_table[0x13] = 0x01; // Intel command set
    _cfi_table[0x27] = 8 * sizeof(unsigned long) - __builtin_clzl(_size - 1U);
    _cfi_table[0x2c] = 1; // one erase block region

    // Erase block region 1 (our only one)
    size_t num_blocks = (_size + Erase_block_size - 1U) / Erase_block_size;
    _cfi_table[0x2d] = num_blocks - 1U;
    _cfi_table[0x2e] = (num_blocks - 1U) >> 8;
    _cfi_table[0x2f] = Erase_block_size >> 8;
    _cfi_table[0x30] = Erase_block_size >> 16;

    info().printf("CFI flash (size %zu, %s)\n", _size,
                  _ro ? "ro" : "rw");
  }

  ~Cfi_flash()
  {}

  int access(l4_addr_t pfa, l4_addr_t offset, Vmm::Vcpu_ptr vcpu,
             L4::Cap<L4::Vm> vm_task, l4_addr_t min, l4_addr_t max) override
  {
    auto insn = vcpu.decode_mmio();

    if (insn.access == Vmm::Mem_access::Store)
      {
        write(vm_task, offset, insn.width, insn.value);
        return Vmm::Jump_instr;
      }
    else if (_cmd == Cmd_read_array)
      {
        if (offset < mapped_size())
          {
            long err = map_page_ro(pfa, offset, vm_task, min, max);
            if (err >= 0)
              return Vmm::Retry;

            warn().printf("MMIO access @ 0x%lx: could not map page: %ld.\n",
                          pfa, err);
            return -L4_ENXIO;
          }
        else
          return Vmm::Jump_instr;
      }
    else if (insn.access == Vmm::Mem_access::Load)
      {
        insn.value = read(offset, insn.width);
        vcpu.writeback_mmio(insn);
        return Vmm::Jump_instr;
      }
    else
      {
        warn().printf("MMIO access @ 0x%lx: unknown instruction. Ignored.\n",
                      pfa);
        return -L4_ENXIO;
      }
  }

  void map_eager(L4::Cap<L4::Vm>, Vmm::Guest_addr, Vmm::Guest_addr) override
  {}


private:
  void set_mode(L4::Cap<L4::Vm> vm_task, uint8_t cmd)
  {
    _cmd = cmd;
    if (cmd != Cmd_read_array && _guest_mapped_min < _guest_mapped_max)
      {
        unmap_guest_range(vm_task, Vmm::Guest_addr(_guest_mapped_min),
                          _guest_mapped_max - _guest_mapped_min + 1U);
        _guest_mapped_min = -1;
        _guest_mapped_max = 0;
      }
  }

  long map_page_ro(l4_addr_t pfa, l4_addr_t offset, L4::Cap<L4::Vm> vm_task,
                   l4_addr_t min, l4_addr_t max)
  {
    if (min < _guest_mapped_min)
      _guest_mapped_min = min;
    if (max > _guest_mapped_max)
      _guest_mapped_max = max;

#ifdef MAP_OTHER
    auto res = dev()->mmio_ds()->map(offset, L4Re::Dataspace::F::RX, pfa,
                                     min, max, vm_task);
#else
    auto local_start = reinterpret_cast<l4_addr_t>(local_addr());

    // Make sure that the page is currently mapped.
    long res = page_in(local_start + offset, false);
    if (res < 0)
      return res;

    unsigned char ps =
      get_page_shift(pfa, min, max, offset, local_start,
                     local_start + mapped_size() - 1U);
    l4_addr_t base = l4_trunc_size(local_start + offset, ps);

    res = l4_error(vm_task->map(L4Re::This_task,
                                l4_fpage(base, ps, L4_FPAGE_RX),
                                l4_trunc_size(pfa, ps)));
#endif

    return res;
  }

  char *local_addr() const
  { return _mgr->local_addr<char *>(); }

  l4_size_t mapped_size() const
  { return _mgr->size(); }

  l4_umword_t read(unsigned reg, char size)
  {
    if (reg + (1U << size) > _size)
      return -1;

    switch (_cmd)
      {
      case Cmd_read_array:
        {
          auto addr = reinterpret_cast<l4_addr_t>(local_addr() + reg);
          return Vmm::Mem_access::read_width(addr, size);
        }
      case Cmd_read_device_id:
        // Currently not implemented. Add once needed.
        return 0;
      case Cmd_cfi_query:
        if (reg < sizeof(_cfi_table))
          {
            auto addr = reinterpret_cast<l4_addr_t>(&_cfi_table[reg]);
            return Vmm::Mem_access::read_width(addr, size);
          }
        else
          return 0;
      default:
        // read status
        return _status;
      }
  }

  void write(L4::Cap<L4::Vm> vm_task, unsigned reg, char size, l4_umword_t value)
  {
    if (reg + (1U << size) > _size)
      return;

    l4_uint8_t cmd = value;
    switch (_cmd)
      {
      case Cmd_write_byte:
        if (_ro)
          _status |= Status_program_error;
        else
          {
            auto addr = reinterpret_cast<l4_addr_t>(local_addr() + reg);
            Vmm::Mem_access::write_width(addr, value, size);
          }
        _status |= Status_ready;
        set_mode(vm_task, Cmd_read_status);
        break;
      case Cmd_block_erase:
        switch (cmd)
          {
            case Cmd_block_erase_confirm:
              _status |= Status_ready;
              if (_ro)
                _status |= Status_erase_error;
              else
                {
                  reg &= ~(Erase_block_size - 1U);
                  memset(local_addr() + reg, 0, Erase_block_size);
                }
              break;
            default:
              info().printf("Invalid command after Cmd_block_erase: 0x%02x\n",
                            cmd);
              _status |= Status_program_error | Status_erase_error;
              return;
          }
        set_mode(vm_task, Cmd_read_status);
        break;

      case Cmd_read_status:
      case Cmd_read_device_id:
      case Cmd_cfi_query:
      case Cmd_read_array:
      case Cmd_program_erase_suspend:
        trace().printf("Command 0x%02x @ %u\n", cmd, reg);
        switch (cmd)
          {
          case Cmd_clear_status:
            _status = 0;
            break;
          case Cmd_program_erase_suspend:
            _status |= Status_ready;
            // FALLTHROUGH
          case Cmd_write_byte:
          case Cmd_block_erase:
          case Cmd_read_status:
          case Cmd_read_device_id:
          case Cmd_cfi_query:
          case Cmd_read_array:
            set_mode(vm_task, cmd);
            break;
          default:
            warn().printf("Unsupported command: %02x\n", cmd);
            break;
          }
        break;
      }
  }

  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "CFI"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "CFI"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "CFI"); }

  cxx::unique_ptr<Vmm::Ds_manager> _mgr;
  size_t _size;
  bool _ro;

  l4_uint8_t _cmd = Cmd_read_array;
  l4_uint8_t _status = 0;

  l4_addr_t _guest_mapped_min = -1;
  l4_addr_t _guest_mapped_max = 0;

  l4_uint8_t _cfi_table[Cfi_table_size] = { 0 };
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    auto dscap = Vdev::get_cap<L4Re::Dataspace>(node, "l4vmm,dscap");
    if (!dscap)
      {
        Err().printf("Missing 'l4vmm,dscap' property!\n");
        return nullptr;
      }

    l4_uint64_t base, size;
    int res = node.get_reg_val(0, &base, &size);
    if (res < 0)
      {
        Err().printf("Missing 'reg' property for node %s\n", node.get_name());
        return nullptr;
      }

    if (size < Cfi_flash::Erase_block_size ||
        size % Cfi_flash::Erase_block_size)
      {
        Err().printf("Wrong device size! Must be a multiple of erase block size.\n");
        return nullptr;
      }

    bool ro = node.has_prop("read-only");

    if (!ro && !dscap->flags().w())
      {
        Dbg(Dbg::Dev, Dbg::Warn, "CFI")
          .printf("DT configures flash to be writable, but dataspace is read-only. "
                  "Defaulting to read-only operation.\n");
        ro = true;
      }

    if (size > dscap->size())
      {
        Err().printf("Dataspace smaller than reg window. Unsupported.\n");
        return nullptr;
      }

    auto c = Vdev::make_device<Cfi_flash>(dscap, size, ro);
    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);

    return c;
  }
};

}

static F f;
static Vdev::Device_type t = { "cfi-flash", nullptr, &f };
