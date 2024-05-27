/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022-2023 Kernkonzept GmbH.
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
 * Example device tree:
 *
 * flash@ffc00000 {
 *     compatible = "cfi-flash";
 *     reg = <0x0 0xffc00000 0x0 0x84000>;
 *     l4vmm,dscap = "capname";
 *     erase-size = <0x10000>; // must be power of two
 *     bank-width = <4>;
 *     device-width = <2>; // optional, equal to bank-width by default
 * };
 *
 * 'bank-width' configures the total bus width of the flash (in bytes).
 * It is typically equal to the 'device-width', unless multiple flash chips
 * share the bus. In this case 'device-width' refers to the width of a single
 * chip. The example above configures a 32-bit wide flash that consists of
 * two 16-bit chips.
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
 * - multiple chips emulated on the same bus (bank-width != device-width)
 *   are not independent: they must always receive the same commands
 */
class Cfi_flash
: public Vmm::Mmio_device,
  public Vdev::Device
{
  enum
  {
    Cmd_write_byte = 0x10,
    Cmd_block_erase = 0x20,
    Cmd_write_byte2 = 0x40,
    Cmd_clear_status = 0x50,
    Cmd_read_status = 0x70,
    Cmd_read_device_id = 0x90,
    Cmd_cfi_query = 0x98,
    Cmd_program_erase_suspend = 0xb0,
    Cmd_block_confirm = 0xd0,
    Cmd_write_block = 0xe8,
    Cmd_read_array = 0xff,

    Status_ready = 1 << 7,
    Status_erase_error = 1 << 5,
    Status_program_error = 1 << 4,

    Cfi_table_size = 0x40,
    Block_buffer_shift = 10, // 1 KiB
    Block_buffer_size = 1 << Block_buffer_shift,
  };

public:
  Cfi_flash(L4::Cap<L4Re::Dataspace> ds, l4_addr_t base, size_t size,
            size_t erase_size, bool ro, unsigned int bank_width,
            unsigned int device_width)
  : _base(base), _size(size), _erase_size(erase_size), _ro(ro),
    _bank_width(bank_width), _device_width(device_width)
  {
    unsigned int chip_shift = 8 * sizeof(unsigned int)
                              - __builtin_clz(bank_width / device_width) - 1;
    _mgr = cxx::make_unique<Vmm::Ds_manager>("Cfi_flash", ds, 0, _size,
                                             ro ? L4Re::Rm::F::R : L4Re::Rm::F::RW);

    // Fill CFI table. See JESD6801...
    _cfi_table[0x10] = 'Q';
    _cfi_table[0x11] = 'R';
    _cfi_table[0x12] = 'Y';
    _cfi_table[0x13] = 0x01; // Intel command set
    _cfi_table[0x15] = 0x31; // Address of "PRI" below
    // Typical/maximum timeout for buffer write in 2^n
    // This must be set because all zero means "not supported"
    _cfi_table[0x20] = 1; // 2us
    _cfi_table[0x24] = 1; // 4us (2^1 multiplied by typical time above)
    _cfi_table[0x27] = 8 * sizeof(unsigned long) - __builtin_clzl(_size - 1U)
                       - chip_shift;
    // Block buffer size in 2^n (divided by number of chips)
    auto block_buf_shift = Block_buffer_shift - chip_shift;
    _cfi_table[0x2a] = cxx::min(block_buf_shift, device_width * 8);
    _cfi_table[0x2c] = 1; // one erase block region

    // Erase block region 1 (our only one)
    size_t num_blocks = (_size + erase_size - 1U) / erase_size;
    _cfi_table[0x2d] = num_blocks - 1U;
    _cfi_table[0x2e] = (num_blocks - 1U) >> 8;
    // Divide erase size by number of chips
    erase_size >>= chip_shift;
    _cfi_table[0x2f] = erase_size >> 8;
    _cfi_table[0x30] = erase_size >> 16;

    // Intel Primary Algorithm Extended Query Table
    _cfi_table[0x31] = 'P';
    _cfi_table[0x32] = 'R';
    _cfi_table[0x33] = 'I';
    _cfi_table[0x34] = '1';
    _cfi_table[0x35] = '0';

    info().printf("CFI flash (size %zu, %s, bank width: %u, device width: %u, erase size = %zu)\n",
                  _size, _ro ? "ro" : "rw", _bank_width, _device_width, _erase_size);
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

  char const *dev_name() const override { return _mgr->dev_name(); }

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

    // Proactively map the flash memory, to avoid instruction decoding on reads.
    if (cmd == Cmd_read_array && _guest_mapped_min >= _guest_mapped_max)
      map_page_ro(_base, 0, vm_task, _base, _base + _size - 1U);
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

  l4_umword_t device_mask() const
  { return ~0UL >> ((sizeof(l4_umword_t) - _device_width) * 8); }

  l4_umword_t chip_shift(l4_umword_t device_val, char size)
  {
    // Duplicate the device value shifted for the other chips on the same bus
    l4_umword_t val = 0;
    for (auto shift = 0U; shift < _bank_width; shift += _device_width)
      val |= device_val << (shift * 8);
    // Clear bits not visible for the access width
    return Vmm::Mem_access::read(val, 0, size);
  }

  bool check_chip_shift(l4_umword_t val)
  {
    auto device_val = val & device_mask();
    for (auto shift = _device_width; shift < _bank_width; shift += _device_width)
      {
        if (device_val != ((val >> (shift * 8)) & device_mask()))
          {
            Err().printf("Invalid command: 0x%lx, must be the same for all chips\n", val);
            return false;
          }
      }
    return true;
  }

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
        {
          if (reg % _bank_width)
            {
              warn().printf("Unaligned read of CFI query: 0x%x\n", reg);
              return 0;
            }
          reg /= _bank_width;

          // Calculate number of elements to be read from the CFI query.
          // Multiple elements are read when the access width is larger than
          // the bank width. Rounding up is necessary in case a smaller access
          // width is used (e.g. 8-bit reads on a 32-bit flash).
          auto nregs = ((1U << size) + _bank_width - 1) / _bank_width;
          if (reg + nregs > sizeof(_cfi_table))
            return 0;

          // Fill the value using the _cfi_table...
          l4_umword_t val = 0;
          for (auto i = 0U; i < nregs; i++)
            val |= _cfi_table[reg + i] << (i * _bank_width * 8);
          // ... and duplicate it for all chips
          return chip_shift(val, size);
        }
      default:
        // read status
        return chip_shift(_status, size);
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
      case Cmd_write_byte2:
        if (_ro)
          _status |= Status_program_error;
        else
          {
            auto addr = reinterpret_cast<l4_addr_t>(local_addr() + reg);
            auto before = Vmm::Mem_access::read_width(addr, size);
            Vmm::Mem_access::write_width(addr, before & value, size);
          }
        _status |= Status_ready;
        set_mode(vm_task, Cmd_read_status);
        break;
      case Cmd_block_erase:
        if (!check_chip_shift(value))
          {
            _status |= Status_program_error | Status_erase_error;
            return;
          }
        switch (cmd)
          {
            case Cmd_block_confirm:
              _status |= Status_ready;
              if (_ro)
                _status |= Status_erase_error;
              else
                {
                  reg &= ~(_erase_size - 1U);
                  memset(local_addr() + reg, 0xff, _erase_size);
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

      case Cmd_write_block:
        if (!write_block(vm_task, reg, size, value))
          {
            _status |= Status_program_error;
            set_mode(vm_task, Cmd_read_status);
          }
        break;

      case Cmd_read_status:
      case Cmd_read_device_id:
      case Cmd_cfi_query:
      case Cmd_read_array:
      case Cmd_program_erase_suspend:
        trace().printf("Command 0x%02x @ %u\n", cmd, reg);
        if (!check_chip_shift(value))
          return;
        switch (cmd)
          {
          case Cmd_clear_status:
            _status = 0;
            break;
          case Cmd_program_erase_suspend:
            _status |= Status_ready;
            // FALLTHROUGH
          case Cmd_write_byte:
          case Cmd_write_byte2:
          case Cmd_block_erase:
          case Cmd_read_status:
          case Cmd_read_device_id:
          case Cmd_cfi_query:
          case Cmd_read_array:
            set_mode(vm_task, cmd);
            break;
          case Cmd_write_block:
            if (_ro)
              {
                _status |= Status_program_error;
                break;
              }
            _buf_len = 0;
            _status |= Status_ready;
            set_mode(vm_task, cmd);
            break;
          default:
            warn().printf("Unsupported command: %02x\n", cmd);
            break;
          }
        break;
      }
  }

  bool write_block(L4::Cap<L4::Vm> vm_task, unsigned reg, char size, l4_umword_t value)
  {
    if (!_buf_len)
      { // start of block write
        if (!check_chip_shift(value))
          return false;

        auto count = (value & device_mask()) + 1; // value = words - 1
        count *= _bank_width; // convert to bytes
        if (count > Block_buffer_size)
          {
            Err().printf("Invalid block write size: %lu val 0x%lx\n", count, value);
            return false;
          }

        _buf_len = count;
        _buf_written = 0;
        return true;
      }

    if (!_buf_written)
      { // set start address on the first write
        trace().printf("Start block write at 0x%x with %u bytes\n", reg, _buf_len);
        if (reg + _buf_len > _size)
          {
            Err().printf("Block write out of bounds: 0x%x + %u\n", reg, _buf_len);
            return false;
          }
        // fill temporary buffer with original values
        // this is necessary because writes can only clear bits (bitwise AND)
        _buf_start = reg;
        memcpy(&_buffer, local_addr() + reg, _buf_len);
      }

    if (_buf_written >= _buf_len)
      { // all words written, write confirmed?
        if (!check_chip_shift(value))
          return false;

        trace().printf("Confirm buffer write with 0x%lx\n", value);

        if ((value & device_mask()) != Cmd_block_confirm)
          return false;

        // write back buffer
        memcpy(local_addr() + _buf_start, _buffer, _buf_len);
        set_mode(vm_task, Cmd_read_status);
        return true;
      }

    if (_buf_start <= reg && (reg + (1 << size)) <= (_buf_start + _buf_len))
      { // write into buffer
        auto addr = reinterpret_cast<l4_addr_t>(&_buffer[reg - _buf_start]);
        auto before = Vmm::Mem_access::read_width(addr, size);
        Vmm::Mem_access::write_width(addr, before & value, size);
        _buf_written += 1 << size;
        return true;
      }

    // write out of bounds
    trace().printf("Out of bounds write to buffer; abort: 0x%x = 0x%lx\n",
                   reg, value);
    return false;
  }

  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "CFI"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "CFI"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "CFI"); }

  cxx::unique_ptr<Vmm::Ds_manager> _mgr;
  l4_addr_t _base;
  size_t _size, _erase_size;
  bool _ro;
  unsigned int _bank_width, _device_width;

  l4_uint8_t _cmd = Cmd_read_array;
  l4_uint8_t _status = 0;

  l4_addr_t _guest_mapped_min = -1;
  l4_addr_t _guest_mapped_max = 0;

  l4_uint8_t _cfi_table[Cfi_table_size] = { 0 };

  l4_uint8_t _buffer[Block_buffer_size];
  unsigned int _buf_start = 0;
  unsigned int _buf_len = 0;
  unsigned int _buf_written = 0;
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    auto warn = Dbg(Dbg::Dev, Dbg::Warn, "CFI");
    auto dscap = Vdev::get_cap<L4Re::Dataspace>(node, "l4vmm,dscap");
    if (!dscap)
      {
        warn.printf("Missing 'l4vmm,dscap' property!\n");
        return nullptr;
      }

    l4_uint64_t base, size;
    int res = node.get_reg_val(0, &base, &size);
    if (res < 0)
      {
        warn.printf("Missing 'reg' property for node %s\n", node.get_name());
        return nullptr;
      }

    auto erase_size = fdt32_to_cpu(*node.check_prop<fdt32_t>("erase-size", 1));
    if (erase_size & (erase_size - 1))
      {
        warn.printf("erase-size must be a power of two: %u\n", erase_size);
        return nullptr;
      }

    if (size < erase_size || size % erase_size)
      {
        warn.printf("Wrong device size! Must be a multiple of erase block size.\n");
        return nullptr;
      }

    bool ro = node.has_prop("read-only");

    if (!ro && !dscap->flags().w())
      {
        warn.printf(
          "DT configures flash to be writable, but dataspace is read-only. "
          "Defaulting to read-only operation.\n");
        ro = true;
      }

    if (size > dscap->size())
      {
        warn.printf("Dataspace smaller than reg window. Unsupported.\n");
        return nullptr;
      }

    auto bank_width = fdt32_to_cpu(*node.check_prop<fdt32_t>("bank-width", 1));
    if (bank_width & (bank_width - 1) || bank_width > sizeof(l4_umword_t))
      {
        warn.printf("Invalid bank-width value: %u\n", bank_width);
        return nullptr;
      }

    int prop_size;
    auto prop = node.get_prop<fdt32_t>("device-width", &prop_size);
    auto device_width = bank_width;
    if (prop)
      {
        if (prop_size != 1)
          {
            warn.printf("Invalid device-width property size: %d\n", prop_size);
            return nullptr;
          }
        device_width = fdt32_to_cpu(*prop);
      }
    if (device_width & (device_width - 1) || device_width > bank_width)
      {
        warn.printf("Invalid device-width value: %u\n", device_width);
        return nullptr;
      }

    auto c = Vdev::make_device<Cfi_flash>(dscap, base, size, erase_size, ro,
                                          bank_width, device_width);
    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);

    return c;
  }
};

}

static F f;
static Vdev::Device_type t = { "cfi-flash", nullptr, &f };
