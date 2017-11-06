/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Adam Lackorzynski <adam@l4re.org>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <cstdio>

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


inline l4_umword_t
Decoder::regval_arch(l4_exc_regs_t *u, unsigned regnr)
{
  switch (regnr)
    {
#ifdef ARCH_x86
    case Reg_eax: return u->eax;
    case Reg_ebx: return u->ebx;
    case Reg_ecx: return u->ecx;
    case Reg_edx: return u->edx;
    case Reg_edi: return u->edi;
    case Reg_esi: return u->esi;
    case Reg_ebp: return u->ebp;
    case Reg_esp: return u->sp;
#else
    case Reg_rax: return u->rax;
    case Reg_rbx: return u->rbx;
    case Reg_rcx: return u->rcx;
    case Reg_rdx: return u->rdx;
    case Reg_rdi: return u->rdi;
    case Reg_rsi: return u->rsi;
    case Reg_rbp: return u->rbp;
    case Reg_rsp: return u->sp;
    case Reg_r8:  return u->r8;
    case Reg_r9:  return u->r9;
    case Reg_r10: return u->r10;
    case Reg_r11: return u->r11;
    case Reg_r12: return u->r12;
    case Reg_r13: return u->r13;
    case Reg_r14: return u->r14;
    case Reg_r15: return u->r15;
#endif
    default: return 0; // cannot happen but gcc complains
    }
}

inline l4_umword_t
Decoder::regval(l4_exc_regs_t *u, unsigned regnr, unsigned shift, unsigned aw)
{
  l4_umword_t v = regval_arch(u, regnr) >> shift;
  if (aw == sizeof(long))
    return v;
  return v & ((1 << (aw * 8)) - 1);
}

inline const char *
Decoder::regname(unsigned regnr, unsigned shift, unsigned aw)
{
#if defined(ARCH_x86) || defined(ARCH_amd64)
  switch (aw)
    {
    case 1:
      return shift == 8 ? reg_names_x86_8h[regnr] : reg_names_x86_8l[regnr];
    case 2:
      return reg_names_x86_16[regnr];
    case 4:
      return reg_names_x86_32[regnr];
    case 8:
#if defined(ARCH_x86)
      return 0;
#else
      return reg_names_x86_64[regnr];
#endif
    }
#endif
  return 0;
}

inline void
Decoder::regname_bm_snprintf(l4_exc_regs_t *u, char *buf, unsigned buflen,
                             unsigned reglist)
{
  unsigned w = 0;
  for (unsigned i = 0; i < Num_registers; ++i)
    if (reglist & (1 << i))
      w += snprintf(buf + w, buflen - w, "%s[%lx],",
                    regname(i, 0, 4), regval(u, i, 0, 4));
  if (reglist)
    buf[w - 1] = 0;
}

inline char *
Decoder::desc_s(l4_exc_regs_t *u, char *buf, unsigned buflen, Desc *d,
                 unsigned aw)
{
  switch (d->dtype)
    {
    case Desc_mem:
      snprintf(buf, buflen, "Mem:%08lx", d->val);
      break;
    case Desc_reg:
      snprintf(buf, buflen, "Reg:%s[%08lx] (s:%d,%ld,%d)",
               regname(d->val, d->shift, aw), regval(u, d->val, d->shift, aw),
               d->shift, d->val, aw);
      break;
    case Desc_regbitmap:
        {
          unsigned w = snprintf(buf, buflen, "Regs:");
          regname_bm_snprintf(u, buf + w, buflen - w, d->val);
        }
      break;
    case Desc_imm:
      snprintf(buf, buflen, "Val:%08lx", d->val);
      break;
    }
  buf[buflen - 1] = 0;
  return buf;
}

l4_addr_t
Decoder::l4mad_print_insn_info(l4_exc_regs_t *u, l4_addr_t pc)
{
  Op op;
  Desc src, target;

  if (decode(u, pc, &op, &target, &src))
    {
      char buf_s[32], buf_t[32];

      Dbg()
        .printf("%08lx(%d): %s of %u bytes from %s to %s.\n",
             l4_utcb_exc_pc(u), op.insn_len, op.atype == Read ? "Read" : "Write",
             op.access_width,
             desc_s(u, buf_s, sizeof(buf_s), &src, op.access_width),
             desc_s(u, buf_t, sizeof(buf_t), &target, op.access_width));

      return l4_utcb_exc_pc(u) + op.insn_len;
    }

  Dbg().printf("Unknown instruction at %lx\n", l4_utcb_exc_pc(u));
  return 0;
}

bool
Decoder::decode(l4_exc_regs_t *u, l4_addr_t pc, Op *op, Desc *tgt, Desc *src)
{
  enum {
    REX_W = 8,
    REX_R = 4,
    REX_X = 2,
    REX_B = 1,
  };
  unsigned char ib;
  bool size_ovr = false;
  unsigned char pref_len = 0;
  bool segment_warned = false;

  while (1)
    {
      ib = getbyte(pc);
      switch (ib)
        {
        case 0x26:
        case 0x36:
        case 0x64:
        case 0x65:
          pc++;
          pref_len++;
          if (!segment_warned)
            Dbg().printf("Segment override not considered\n");
          segment_warned = true;
          continue;
        case 0x66:
          pc++;
          size_ovr = true;
          pref_len++;
          continue;
        case 0xf0: // lock;
        case 0x2e: // branch
        case 0x3e: // branch
          pc++;
          pref_len++;
          continue;
        };
      break;
    }

  unsigned char rex = 0;
#ifdef ARCH_amd64
  // rex
  if ((ib & 0xf0) == 0x40)
    {
      rex = ib;
      pc++;
      ib = getbyte(pc);
      pref_len++;
    }
#endif

  bool byte = false;
  bool wr = false;
  switch (ib)
    {
    case 0xc6: // mov $, a
      byte = true;
    case 0xc7:
        {
          unsigned char v = readval(pc + 1, 1);
          unsigned char reg = (v >> 3) & 7;
          unsigned char rm  = v & 7;
          unsigned char mod = v >> 6;
          unsigned char len = 2;
          l4_addr_t a = 0;

          if (mod == 3)
            return false;

          if (reg)
            return false;

          if (rm == 4) // sib
            {
              unsigned char sibbyte = readval(pc + 2, 1);
              unsigned char mult = 1 << (sibbyte >> 6);
              if (rex & REX_R)
                reg |= 8;
              a = regval(u, (sibbyte & 7) | (rex & REX_B ? 8 : 0) , 0, 4)
                  + mult * regval(u, ((sibbyte >> 3) & 7) | (rex & REX_X ? 8 : 0), 0, 4);
              len += 1;
            }
          else if (rex & REX_B)
            rm |= 8;


          trace().printf("reg=%d rm=%d mod=%d\n", reg, rm, mod);

          if (mod == 0)
            {
              switch (rm)
                {
                case 4: break; // sib
                case 5: len += 4;
#ifdef ARCH_amd64
                  // FIXME! RIP-relative addressing uses the next RIP not the
                  // current one!
                  // a = u->ip + (l4_mword_t)readval(pc + 2, 4);
                  trace().printf("RIP-relative addressing not supported\n");
                  return false;
#else
                  a = readval(pc + 2, 4);
#endif
                  break;
                default: a = regval(u, rm, 0, 4); break;
                }
            }
          else if (mod == 1 || mod == 2)
            {
              if (rm != 4)
                a += regval(u, rm, 0, 4);

              unsigned s = mod == 1 ? 1 : 4;
              a += readval(pc + 2 + (rm == 4), s);
              len += s;
            }


          unsigned char immlen = byte ? 1 : (size_ovr ? 2 : 4);
          trace().printf("len=%d imml=%d\n", len, immlen);
          l4_umword_t imm = readval(pc + len, immlen);
          len += immlen;
          op->set(Write, (rex & REX_W) ? 8 : immlen, len + pref_len);
#ifdef ARCH_amd64
          if (rex & REX_W && imm & (1 << 31))
            imm |= 0xffffffffULL << 32;
#endif
          src->set_imm(imm);
          tgt->set_mem(a);


          return true;
        }
      break;
    case 0xa0: // mov a, %al
      byte = true;
    case 0xa1: // mov a, %eax
        {
          char l = 5 + pref_len;
#ifdef ARCH_amd64
          l += 4;
#endif
          op->set(Read, (rex & REX_W) ? 8 : (byte ? 1 : (size_ovr ? 2 : 4)), l);
          src->set_mem(readval(pc + 1, 4));
          tgt->set_reg(Reg_eax);
        }
      return true;
    case 0xa2: // mov %al, a
      byte = true;
    case 0xa3: // mov %eax, a
        {
          char l = 5 + pref_len;
#ifdef ARCH_amd64
          l += 4;
#endif
          op->set(Write, (rex & REX_W) ? 8 : (byte ? 1 : (size_ovr ? 2 : 4)), l);
          src->set_reg(Reg_eax);
          tgt->set_mem(readval(pc + 1, 4));
        }
      return true;

    // write
    case 0x88: // mov %, a
    case 0x89: // mov %, a
      wr = true;
    // read
    case 0x8a: // mov a, %
    case 0x8b: // mov a, %
        {
          unsigned char v = readval(pc + 1, 1);
          unsigned char reg = (v >> 3) & 7;
          unsigned char rm  = v & 7;
          unsigned char mod = v >> 6;
          unsigned char len = 2;

          if (!(ib & 1))
            byte = true;

          //trace().printf("%08lx: reg=%d rm=%d mod=%d\n", pc, reg, rm, mod);

          l4_addr_t a = 0;

          if (mod == 3)
            return false;

          if (rm == 4) // sib
            {
              unsigned char sibbyte = readval(pc + 2, 1);
              unsigned char mult = 1 << (sibbyte >> 6);
              a = regval(u, sibbyte & 7, 0, 4)
                  + mult * regval(u, (sibbyte >> 3) & 7, 0, 4);;
              len += 1;
            }

          if (mod == 0)
            {
              switch (rm)
                {
                case 4: break; // sib
                case 5: len += 4; a = readval(pc + 2, 4); break;
                default: a = regval(u, rm, 0, 4); break;
                }
            }
          else if (mod == 1 || mod == 2)
            {
              if (rm != 4)
                a += regval(u, rm, 0, 4);

              unsigned s = mod == 1 ? 1 : 4;
              unsigned tmp = readval(pc + 2 + (rm == 4), s);
              a += s == 1 ? (signed char)tmp : (signed int)tmp;
              len += s;
            }

          op->set(wr ? Write : Read,
                  (rex & REX_W) ? 8 : (byte ? 1 : (size_ovr ? 2 : 4)),
                  len + pref_len);
          unsigned shift = 0;
          if (!rex && byte && reg > 3)
            {
              // If REX is used in the instruction, AH to DH are not accessible.
              // Use SPL, BPL, SIL, and DIL, which is the lower byte of the
              // actually referenced register.
              reg -= 4;
              shift = 8;
            }

          if (wr)
            {
              src->set_reg(reg, shift);
              tgt->set_mem(a);
            }
          else
            {
              src->set_mem(a);
              tgt->set_reg(reg, shift);
            }
        }
      return true;
      break;
    default:
      Dbg().printf("No valid 'ib': 0x%x\n", ib);
      break;
    }

  return false;
}

} // namspace L4mad
