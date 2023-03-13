/*
 * Copyright (C) 2017-2018, 2021 Kernkonzept GmbH.
 * Author(s): Adam Lackorzynski <adam@l4re.org>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <cstdio>

#include <l4/cxx/bitfield>
#include <l4/cxx/exceptions>
#include <l4/re/error_helper>

#include "mad.h"

namespace L4mad
{

static const char *reg_names_x86_32[] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };

static const char *reg_names_x86_16[] = {
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };

static const char *reg_names_x86_8l[] = {
    "al", "cl", "dl", "bl" };

static const char *reg_names_x86_8h[] = {
    "ah", "ch", "dh", "bh" };

#ifdef ARCH_amd64
enum Reg_names_amd64 { Reg_rax, Reg_rcx, Reg_rdx, Reg_rbx, Reg_rsp, Reg_rbp,
                       Reg_rsi, Reg_rdi, Reg_r8, Reg_r9, Reg_r10, Reg_r11, Reg_r12,
                       Reg_r13, Reg_r14, Reg_r15,
                       Reg_eax = Reg_rax
                     };

static const char *reg_names_x86_64[]
     = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };

#elif defined(ARCH_x86)

enum Reg_names_x86 { Reg_eax, Reg_ecx, Reg_edx, Reg_ebx, Reg_esp, Reg_ebp,
                     Reg_esi, Reg_edi };
#endif

static unsigned width_in_bytes(Width width)
{
  switch (width)
    {
    case Width::Wd8:  return 1;
    case Width::Wd16: return 2;
    case Width::Wd32: return 4;
    case Width::Wd64: return 8;
    }
  L4Re::throw_error(-L4_EINVAL, "Invalid width to convert to bytes.");
}

enum Rex
{
  /// Operand size
  Rex_w = 8,
  /// ModR/M reg field
  Rex_r = 4,
  /// SIB index field
  Rex_x = 2,
  /// ModR/M r/m field
  Rex_b = 1,
};

struct Modrm
{
  unsigned char raw;
  explicit Modrm(unsigned char val) : raw(val) {}

  /// Register (possibly extended by Rex_b) or an addressing mode combined with
  /// the mod field.
  CXX_BITFIELD_MEMBER(0, 2, rm, raw);
  /// Register (possibly extended by Rex_r) or three additional opcode bits.
  CXX_BITFIELD_MEMBER(3, 5, reg, raw);
  /// Controls whether the rm field encodes a register (mod=3) or an addressing
  /// mode.
  CXX_BITFIELD_MEMBER(6, 7, mod, raw);
};

enum Rm
{
  Rm_sib = 4,
  Rm_ripr  = 5,
};

enum Mod
{
  Mod_indirect        = 0,
  Mod_indirect_disp8  = 1,
  Mod_indirect_disp32 = 2,
  Mod_direct          = 3,
};

struct Sib
{
  unsigned char raw;
  explicit Sib(unsigned char val) : raw(val) {}

  /// Base register (possibly extended by Rex_b).
  CXX_BITFIELD_MEMBER(0, 2, base, raw);
  /// Index register (possibly extended by Rex_x).
  CXX_BITFIELD_MEMBER(3, 5, index, raw);
  /// Scale factor of index field.
  CXX_BITFIELD_MEMBER(6, 7, scale, raw);
};

struct Instruction
{
  /// Instruction length, only accurate after decoding of the instruction is
  /// complete.
  unsigned char len = 0;

  /// Operand-size override
  bool op_size_ovr = false;
  /// REX prefix, if present
  unsigned char rex = 0;

  /// Operand size is forced to one byte
  bool op_size_byte = false;

  /// Register operand
  unsigned char op_reg;
  /// Shift to apply to register operand, e.g. used for accessing high byte.
  unsigned char op_reg_shift;
  /// Address operand
  l4_addr_t op_addr;
  /// Address operand is IP relative
  bool op_addr_ripr;
  /// Immediate operand
  l4_umword_t op_imm;

  // Assumption: If in protected mode or long compatibility mode we assume that
  // we are in a 32-bit code segment (CS.d == 1).
  Width op_width() const
  {
    // Operand-size override prefix and Rex.W have no effect on byte-specific
    // operations.
    if (op_size_byte)
      return Width::Wd8;

    if (rex & Rex_w)
      return Width::Wd64;

    return op_size_ovr ? Width::Wd16 : Width::Wd32;
  }

  // Assumption: If in protected mode or long compatibility mode we assume that
  // we are in a 32-bit code segment (CS.d == 1).
  Width imm_width() const
  {
    // Operand-size override prefix has no effect on byte-specific operations.
    if (op_size_byte)
      return Width::Wd8;

    return op_size_ovr ? Width::Wd16 : Width::Wd32;
  }

  unsigned char rex_reg(unsigned char reg, Rex rex_bit) const
  { return rex & rex_bit ? reg + 8 : reg; }
};

/**
 * Truncate value to specified width.
 *
 * \param v      Value to truncate
 * \param width  Width in bytes
 */
static l4_umword_t
truncate(l4_umword_t v, Width width)
{
  if (width_in_bytes(width) >= sizeof(l4_umword_t))
    return v;
  return v & ((1UL << (width * 8)) - 1);
}

/**
 * Sign-extend value from specified width.
 *
 * \param v           Value to sign-extend
 * \param from_width  Width in bytes
 */
static l4_umword_t
sign_extend(l4_umword_t v, Width from_width)
{
  if (width_in_bytes(from_width) >= sizeof(l4_umword_t))
    return v;

  l4_umword_t const msb = 1UL << (from_width * 8 - 1);
  if (v & msb)
    v |= ~0UL << (from_width * 8);
  return v;
}

Decoder::Decoder(l4_exc_regs_t const *regs, l4_addr_t ip,
                 unsigned char const *inst_buf, unsigned inst_buf_len)
: _regs(regs), _ip(ip), _inst_buf(inst_buf), _inst_buf_len(inst_buf_len),
#ifdef ARCH_amd64
  // TODO: Introduce parameter to Decoder or decode(), that signifies whether
  // CPU is in 64-bit mode or in compatibility/protected mode.
  _long_mode_64(true)
#else
  _long_mode_64(false)
#endif
{
}

l4_umword_t
Decoder::regval_arch(unsigned regnr) const
{
  switch (regnr)
    {
#ifdef ARCH_x86
    case Reg_eax: return _regs->eax;
    case Reg_ebx: return _regs->ebx;
    case Reg_ecx: return _regs->ecx;
    case Reg_edx: return _regs->edx;
    case Reg_edi: return _regs->edi;
    case Reg_esi: return _regs->esi;
    case Reg_ebp: return _regs->ebp;
    case Reg_esp: return _regs->sp;
#else
    case Reg_rax: return _regs->rax;
    case Reg_rbx: return _regs->rbx;
    case Reg_rcx: return _regs->rcx;
    case Reg_rdx: return _regs->rdx;
    case Reg_rdi: return _regs->rdi;
    case Reg_rsi: return _regs->rsi;
    case Reg_rbp: return _regs->rbp;
    case Reg_rsp: return _regs->sp;
    case Reg_r8:  return _regs->r8;
    case Reg_r9:  return _regs->r9;
    case Reg_r10: return _regs->r10;
    case Reg_r11: return _regs->r11;
    case Reg_r12: return _regs->r12;
    case Reg_r13: return _regs->r13;
    case Reg_r14: return _regs->r14;
    case Reg_r15: return _regs->r15;
#endif
    default: return 0; // cannot happen but gcc complains
    }
}

l4_umword_t
Decoder::regval(unsigned regnr, unsigned shift, Width aw) const
{
  return truncate(regval_arch(regnr) >> shift, aw);
}

char const *
Decoder::regname(unsigned regnr, unsigned shift, Width aw) const
{
#if defined(ARCH_x86) || defined(ARCH_amd64)
  switch (aw)
    {
    case Width::Wd8:
      return shift == 8 ? reg_names_x86_8h[regnr] : reg_names_x86_8l[regnr];
    case Width::Wd16:
      return reg_names_x86_16[regnr];
    case Width::Wd32:
      return reg_names_x86_32[regnr];
    case Width::Wd64:
#if defined(ARCH_x86)
      return 0;
#else
      return reg_names_x86_64[regnr];
#endif
    }
#endif
  return 0;
}

void
Decoder::regname_bm_snprintf(char *buf, unsigned buflen, unsigned reglist) const
{
  unsigned w = 0;
  for (unsigned i = 0; i < Num_registers; ++i)
    if (reglist & (1 << i))
      w += snprintf(buf + w, buflen - w, "%s[%lx],",
                    regname(i, 0, Width::Wd32), regval(i, 0, Width::Wd32));
  if (reglist)
    buf[w - 1] = 0;
}

char *
Decoder::desc_s(char *buf, unsigned buflen, Desc const &d, Width aw) const
{
  switch (d.dtype)
    {
    case Desc_mem:
      snprintf(buf, buflen, "Mem:%08lx", d.val);
      break;
    case Desc_reg:
      snprintf(buf, buflen, "Reg:%s[%08lx] (s:%d,%ld,%d)",
               regname(d.val, d.shift, aw), regval(d.val, d.shift, aw),
               d.shift, d.val, aw);
      break;
    case Desc_regbitmap:
        {
          unsigned w = snprintf(buf, buflen, "Regs:");
          regname_bm_snprintf(buf + w, buflen - w, d.val);
        }
      break;
    case Desc_imm:
      snprintf(buf, buflen, "Val:%08lx", d.val);
      break;
    }
  buf[buflen - 1] = 0;
  return buf;
}

void
Decoder::print_insn_info(Op const &op, Desc const &tgt, Desc const &src) const
{
  char buf_s[32], buf_t[32];

  warn()
    .printf("0x%lx (%d): %s of %u bytes from %s to %s.\n",
         _ip, op.insn_len, op.atype == Read ? "Read" : "Write",
         op.access_width,
         desc_s(buf_s, sizeof(buf_s), src, op.access_width),
         desc_s(buf_t, sizeof(buf_t), tgt, op.access_width));
}

// Assumption: If in protected mode or long compatibility mode we assume that
// we are in a 32-bit code segment (CS.d == 1).
Width
Decoder::addr_width(Instruction const &) const
{
  // TODO: Add support for address-size override prefix?
  return _long_mode_64 ? Width::Wd64 : Width::Wd32;
}

l4_umword_t
Decoder::peek_inst_bytes(Instruction const &inst, Width sz) const
{
  unsigned new_inst_len = inst.len + width_in_bytes(sz);
  if (new_inst_len > _inst_buf_len || new_inst_len >= Max_instruction_len)
    L4Re::throw_error(-L4_ERANGE, "Instruction out of bounds.");

  unsigned char const *bytes = &_inst_buf[inst.len];
  switch (sz)
    {
    case Width::Wd8: return *bytes;
    case Width::Wd16: return *reinterpret_cast<l4_uint16_t const *>(bytes);
    case Width::Wd32: return *reinterpret_cast<l4_uint32_t const *>(bytes);
    case Width::Wd64: return *reinterpret_cast<l4_uint64_t const *>(bytes);
    }
  L4Re::throw_error(-L4_EINVAL, "Invalid instruction buffer access size.");
}

l4_umword_t
Decoder::read_inst_bytes(Instruction &inst, Width sz) const
{
  l4_umword_t result = peek_inst_bytes(inst, sz);
  inst.len += width_in_bytes(sz);
  return result;
}

void
Decoder::decode_legacy_prefixes(Instruction &inst)
{
  for(;;)
    {
      switch (peek_inst_bytes(inst, Width::Wd8))
        {
        // Group 1
        // Lock and repeat prefixes
        case 0xf0: // lock;
          break;
        case 0xf2:
        case 0xf3:
          trace().printf("Repeat prefix not considered\n");
          break;
        // Group 2
        // Segment-Override Prefixes
        case 0x26: // ES
        case 0x36: // SS
        case 0x64: // FS
        case 0x65: // GS
          trace().printf("Segment override not considered\n");
          break;
        // Branch hints
        case 0x2e: // branch hint or CS segment override
        case 0x3e: // branch hint or DS segment override
          break;
        // Group 3
        // Operand-size override prefix
        case 0x66:
          inst.op_size_ovr = true;
          break;
        // Group 4
        // Address-size override prefix
        case 0x67:
          trace().printf("Address-size override not considered\n");
          break;

        default:
          // Not a prefix, opcode follows.
          return;
        };
      ++inst.len;
    }
}

void
Decoder::decode_rex_prefix(Instruction &inst)
{
  if (!_long_mode_64)
    return;

  unsigned char ib = peek_inst_bytes(inst, Width::Wd8);
  // REX prefix?
  if ((ib & 0xf0) == 0x40)
    {
      inst.rex = ib;
      ++inst.len;
    }
}

bool
Decoder::decode_modrm(Instruction &inst, unsigned char *opcode_ext)
{
  Modrm modrm(read_inst_bytes(inst, Width::Wd8));

  // Writing into or reading from a register cannot raise a page fault,
  // thus not relevant for our use case.
  if (modrm.mod() == Mod_direct)
    return false;

  // Reg field encodes register if the opcode does not expect it to contain
  // additional opcode bits.
  if (!opcode_ext)
    {
      // Register operand
      inst.op_reg = inst.rex_reg(modrm.reg(), Rex_r);

      // AH to DH are only accessible if the instruction does not use a REX
      // prefix. Then instead SPL, BPL, SIL, and DIL, which is the lower
      // byte of the actually referenced register, would be accessed.
      if (!inst.rex && inst.op_size_byte && inst.op_reg > 3)
        {
          inst.op_reg -= 4;
          // Access the high byte (AH to DH)
          inst.op_reg_shift = 8;
        }
    }
  // Reg field encodes additional opcode bits.
  else
    *opcode_ext = modrm.reg();

  // Memory address operand
  if (modrm.rm() == Rm_sib)
    {
      inst.op_addr = decode_sib(inst, modrm);
    }
  else if (modrm.mod() == Mod_indirect && modrm.rm() == Rm_ripr)
    {
      inst.op_addr_ripr = _long_mode_64;
      // Plus 32-bit displacement
      inst.op_addr = sign_extend(read_inst_bytes(inst, Width::Wd32), Width::Wd32);
    }
  else
    {
      inst.op_addr = regval(inst.rex_reg(modrm.rm(), Rex_b), 0,
                            addr_width(inst));
    }

  // Displacement
  if (modrm.mod() == Mod_indirect_disp8 || modrm.mod() == Mod_indirect_disp32)
  {
    Width sz = modrm.mod() == Mod_indirect_disp8 ? Width::Wd8 : Width::Wd32;
    inst.op_addr += sign_extend(read_inst_bytes(inst, sz), sz);
  }

  return true;
}

l4_umword_t
Decoder::decode_sib(Instruction &inst, Modrm const &modrm)
{
  Sib sib(read_inst_bytes(inst, Width::Wd8));

  l4_umword_t base = 0;
  if (modrm.mod() == Mod_indirect && sib.base() == 5)
    {
      // No base register, instead a disp32 is specified.
      base = sign_extend(read_inst_bytes(inst, Width::Wd32), Width::Wd32);
    }
  else
    base = regval(inst.rex_reg(sib.base(), Rex_b), 0, addr_width(inst));

  l4_umword_t index = 0;
  unsigned char rindex = inst.rex_reg(sib.index(), Rex_x);
  if (rindex != 4) // otherwise, no index register specified
    index = regval(rindex, 0, addr_width(inst));

  return base + (index << sib.scale());
}

void
Decoder::decode_imm(Instruction &inst)
{
  Width imm_len = inst.imm_width();
  inst.op_imm = read_inst_bytes(inst, imm_len);

  if (_long_mode_64 && !inst.op_size_byte && (inst.rex & Rex_w))
    // In 64-bit mode all immediates are sign-extended to 64 bits.
    inst.op_imm = sign_extend(inst.op_imm, imm_len);
}

void
Decoder::decode_imm_moffs(Instruction &inst)
{
  inst.op_imm = read_inst_bytes(inst, inst.op_width());
}

Decoder::Result
Decoder::decode(Op *op, Desc *tgt, Desc *src)
{
  try
    {
      Decoder::Result result = decode_unsafe(op, tgt, src);
      if (result != Result::Success)
        warn().printf("Unsupported or invalid instruction at 0x%lx\n", _ip);
      return result;
    }
  catch (L4::Runtime_error const &e)
    {
      warn().printf("Invalid instruction in [0x%lx, 0x%lx]: %s (%ld): %s\n",
                    _ip, _ip + _inst_buf_len, e.str(), e.err_no(), e.extra_str());
      return Result::Invalid;
    }
}

Decoder::Result
Decoder::decode_unsafe(Op *op, Desc *tgt, Desc *src)
{
  Instruction inst{};

  // Instructions consist of the following components in the given order:
  // - Legacy prefixes (optional)
  // - REX prefix (optional)
  // - Opcode (up to three bytes)
  // - ModR/M (1 byte, if required)
  // - SIB (1 byte, if required)
  // - Displacement (1, 2 or 4 bytes, if required)
  // - Immediate (1, 2, 4 or 8 bytes, if required)

  decode_legacy_prefixes(inst);
  decode_rex_prefix(inst);

  // Read first opcode byte
  unsigned char ib = read_inst_bytes(inst, Width::Wd8);
  switch (ib)
    {
    case 0xc6: // mov $, a
    case 0xc7:
      {
        inst.op_size_byte = !(ib & 1);

        unsigned char opcode_ext;
        if (!decode_modrm(inst, &opcode_ext))
          return Result::Unsupported;

        // Opcode extension must be zero.
        if (opcode_ext != 0)
          return Result::Unsupported;

        decode_imm(inst);

        op->set(Write, inst.op_width(), inst.len);
        imm_from_op_imm(src, inst);
        mem_from_op_addr(tgt, inst);
        return Result::Success;
      }

    // read
    case 0xa0: // mov a, %al
    case 0xa1: // mov a, %eax
    // write
    case 0xa2: // mov %al, a
    case 0xa3: // mov %eax, a
      {
        inst.op_size_byte = !(ib & 1);
        bool write = (ib & 2);

        decode_imm_moffs(inst);
        op->set(write ? Write : Read, inst.op_width(), inst.len);
        (write ? src : tgt)->set_reg(Reg_eax);
        mem_from_op_imm(write ? tgt : src, inst);
        return Result::Success;
      }

    // write
    case 0x88: // mov %, a
    case 0x89: // mov %, a
    // read
    case 0x8a: // mov a, %
    case 0x8b: // mov a, %
      {
        inst.op_size_byte = !(ib & 1);
        bool write = !(ib & 2);

        if (!decode_modrm(inst))
          return Result::Unsupported;

        op->set(write ? Write : Read, inst.op_width(), inst.len);
        reg_from_op_reg(write ? src : tgt, inst);
        mem_from_op_addr(write ? tgt : src, inst);
        return Result::Success;
      }

    default:
      warn().printf("Unsupported opcode: 0x%x\n", ib);
      return Result::Unsupported;
    }
}

void
Decoder::reg_from_op_reg(Desc *desc, Instruction const &inst) const
{ desc->set_reg(inst.op_reg, inst.op_reg_shift); }

void
Decoder::imm_from_op_imm(Desc *desc, Instruction const &inst) const
{ desc->set_imm(inst.op_imm); }

void
Decoder::mem_from_op_imm(Desc *desc, Instruction const &inst) const
{ desc->set_mem(inst.op_imm); }

void
Decoder::mem_from_op_addr(Desc *desc, Instruction const &inst) const
{
  l4_addr_t addr = inst.op_addr;
  if (inst.op_addr_ripr)
    addr += _ip + inst.len;
  // Truncate calculated address to current address width.
  addr = truncate(addr, addr_width(inst));
  desc->set_mem(addr);
}

} // namspace L4mad
