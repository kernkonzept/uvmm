/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <iterator>

inline uint64_t round_size(uint64_t addr, unsigned char bits)
{ return (addr + (1UL << bits) - 1) & (~0UL << bits); };

template <class T>
inline std::string to_string(const T &t, std::ios_base & (*f)(std::ios_base&))
{
  std::ostringstream oss;
  oss << f << t;
  return oss.str();
}

inline std::string string_list(const std::vector<std::string> &vec)
{
  std::ostringstream oss;
  oss << "\"";
  for (auto i = vec.begin(); i != vec.end(); i++)
    oss << (i != vec.begin() ? "\", \"" : "") << *i;
  oss << "\"";
  return oss.str();
}

inline std::string int_list(const std::vector<unsigned> &vec)
{
  std::ostringstream oss;
  oss << "<";
  for (auto i = vec.begin(); i != vec.end(); i++)
    oss << (i != vec.begin() ? " " : "") << "0x" << std::hex << *i;
  oss << ">";
  return oss.str();
}

inline std::string int_list(const std::vector<std::string> &vec)
{
  std::ostringstream oss;
  oss << "<";
  for (auto i = vec.begin(); i != vec.end(); i++)
    oss << (i != vec.begin() ? " " : "") << *i;
  oss << ">";
  return oss.str();
}

inline std::vector<std::string> split(const std::string &s,
                                      const std::string &c = " ")
{
  std::vector<std::string> res;
  std::size_t prev = 0, pos;
  while ((pos = s.find_first_of(c, prev)) != std::string::npos)
    {
      if (pos > prev)
        res.push_back(s.substr(prev, pos - prev));
      prev = pos + 1;
    }
  if (prev < s.length())
    res.push_back(s.substr(prev, std::string::npos));
  return res;
}
