/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <string>
#include <sstream>

struct Arch
{
  enum
  {
    X86_32 = 1UL << 0,
    X86_64 = 1UL << 1,
    Arm32  = 1UL << 2,
    Arm64  = 1UL << 3,
    Mips32 = 1UL << 4,
    Mips64 = 1UL << 5,

    X86 = X86_32 | X86_64,
    Arm = Arm32 | Arm64,
    Mips = Mips32 | Mips64,
    All = X86 | Arm | Mips,
  };

  Arch() = default;
  constexpr Arch(const Arch&) = default;
  constexpr Arch(Arch&&) = default;
  constexpr Arch(int a, bool i64, uint32_t ac, uint32_t sc, const char *ictl)
  : arch(a),
    is64bit(i64),
    acells(ac),
    scells(sc),
    ic(ictl)
  {}

  Arch& operator=(const Arch&) = default;
  Arch& operator=(Arch&&) = default;

  bool is(int a) const
  { return arch & a; }

  int arch;
  bool is64bit;
  uint32_t acells;
  uint32_t scells;
  const char *ic;
};

inline std::ostream &operator<<(std::ostream &os, const Arch &arch)
{
  switch (arch.arch)
    {
    case Arch::X86_32: os << "x86"; break;
    case Arch::X86_64: os << "x86_64"; break;
    case Arch::Arm32: os << "arm32"; break;
    case Arch::Arm64: os << "arm64"; break;
    case Arch::Mips32: os << "mips32"; break;
    case Arch::Mips64: os << "mips64"; break;
    default: os << "unknown"; break;
    }

  return os;
}

struct X86_32: Arch
{ constexpr X86_32() : Arch(Arch::X86_32, false, 1, 1, "pic") {} };

struct X86_64: Arch
{ constexpr X86_64() : Arch(Arch::X86_64, true, 2, 2, "pic") {} };

struct Arm32: Arch
{ constexpr Arm32() : Arch(Arch::Arm32, false, 1, 1, "gic") {} };

struct Arm64: Arch
{ constexpr Arm64() : Arch(Arch::Arm64, true, 2, 2, "gic") {} };

struct Mips32: Arch
{ constexpr Mips32() : Arch(Arch::Mips32, false, 1, 1, "gic") {} };

struct Mips64: Arch
{ constexpr Mips64() : Arch(Arch::Mips64, true, 2, 2, "gic") {} };

enum OutFormat
{
  Txt,
  Bin
};

inline std::ostream &operator<<(std::ostream &os, const OutFormat &fmt)
{
  switch (fmt)
    {
    case Txt: os << "txt"; break;
    case Bin: os << "bin"; break;
    default: os << "unknown"; break;
    }

  return os;
}

struct Exception
{
  Exception(const std::string &e)
  : error(e)
  {}

  Exception(std::string &&e)
  : error(std::move(e))
  {}

  std::string error;
};
