/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <string>

#include <l4/cxx/exceptions>
#include <l4/re/error_helper>
#include <l4/sys/l4int.h>

namespace Monitor {

namespace Detail {
  template<typename T, typename U>
  struct Equality_comparable
  {
     friend bool operator == (U const &lhs, T const &rhs) noexcept
     { return rhs == lhs; }
     friend bool operator != (T const &lhs, U const &rhs) noexcept
     { return !(lhs == rhs); }
     friend bool operator != (U const &lhs, T const &rhs) noexcept
     { return !(lhs == rhs); }
  };
}

class Arglist;

/**
 * Helper class encapsulating a monitor command argument.
 */
class Arg
: private Detail::Equality_comparable<Arg, char const *>,
  private Detail::Equality_comparable<Arg, std::string>
{
  friend class Arglist;

  union Type_cache {
    unsigned u;
    l4_addr_t addr;
  };

  enum Cached_type {
    Cached_none,
    Cached_unsigned,
    Cached_addr
  };

public:
  /**
   * Compare this argument to a C-string.
   *
   * \param rhs  C-string to compare to this argument.
   *
   * \return  `true` in case of equality, else `false`.
   *
   * \note  It is also possible to evaluate `str == arg`, `arg != str` and
   *        `str != arg` where `str` is a C-string and `arg` is an object of
   *        type `Arg`.
   */
  bool operator == (char const *rhs) const noexcept
  { return _arg == rhs; }

  /**
   * Compare this argument to a String.
   *
   * \param rhs  String to compare to this argument.
   *
   * \return  `true` in case of equality, else `false`.
   *
   * \see `operator == (char const *)`.
   */
  bool operator == (std::string const &rhs) const noexcept
  { return _arg == rhs; }

  /**
   * Check if this is a valid argument.
   *
   * \return  `true` if this is a valid argument, else `false`.
   *
   * 'Invalid' arguments are arguments which have been popped from an empty
   * argument list, calling `get<T>()` without a default argument on an invalid
   * argument will cause an exception to be thrown.
   */
  bool valid() const
  { return !_arg.empty(); }

  /**
   * Check if this argument can be converted to a certain type.
   *
   * \tparam T  Type to which to convert this argument.
   *
   * \return  `true` if a conversion to `T` is possible for this argument,
   *          else `false`.
   */
  template<typename T>
  bool check()
  {
    if (!valid())
      return false;

    return do_check<T>();
  }

  /**
   * Convert this argument to a certain type.
   *
   * \tparam T  Type to which to convert this argument.
   *
   * \param msg  Optional conversion failure error message.
   *
   * \return  This argument converted to `T`.
   *
   * \throws L4::Runtime_error  If this is an invalid argument or if this is a
   *                            valid argument but the requested conversion is
   *                            not well defined, i.e. `check<T>() == false`.
   */
  template<typename T = char const *>
  T get(char const *msg = nullptr)
  {
    if (!check<T>())
      conversion_error(msg);

    return do_get<T>();
  }

  /**
   * Convert this argument to a certain type.
   *
   * \tparam T  Type to which to convert this argument.
   *
   * \param def  Default value.
   * \param msg  Optional conversion failure error message.
   *
   * \return  If `valid() == true` this argument converted to `T`, else `def`.
   *
   * \throws L4::Runtime_error  If this is a valid argument but the requested
   *                            conversion is not well defined, i.e.
   *                            `check<T>() == false`.
   */
  template<typename T = char const *>
  T get(T def, char const *msg = nullptr)
  {
    if (!valid())
      return def;

    if (!check<T>())
      conversion_error(msg);

    return do_get<T>();
  }

private:
  Arg(char const *arg, size_t arglen)
  : _arg(arg, arglen),
    _cached_type(Cached_none)
  {}

  static bool stoull(char const *str, unsigned long long *ull, int base)
  {
    errno = 0;

    char *endptr;
    *ull = strtoull(str, &endptr, base);

    return errno == 0 && !*endptr;
  }

  static void conversion_error(char const *msg)
  { L4Re::chksys(-L4_EINVAL, msg ? msg : "Parameter conversion"); }

  template<typename T>
  bool do_check()
  { return T::Unimplemented; }

  template<typename T>
  T do_get()
  { return T::Unimplemented; }

  std::string _arg;

  Type_cache _cache;
  Cached_type _cached_type;
};

template<>
inline bool
Arg::do_check<char const *>()
{ return true; }

template<>
inline bool
Arg::do_check<std::string>()
{ return true; }

template<>
inline bool
Arg::do_check<char>()
{ return _arg.size() == 1; }

template<>
inline bool
Arg::do_check<unsigned>()
{
  if (_cached_type == Cached_unsigned)
    return true;

  unsigned long long ull;
  if (!stoull(_arg.c_str(), &ull, 10) || ull > UINT_MAX)
    return false;

  _cache.u = static_cast<unsigned>(ull);
  _cached_type = Cached_unsigned;

  return true;
}

template<>
inline bool
Arg::do_check<l4_addr_t>()
{
  if (_cached_type == Cached_addr)
    return true;

  unsigned long long ull;
  if (!stoull(_arg.c_str(), &ull, 16))
    return false;

  l4_addr_t addr = static_cast<l4_addr_t>(ull);

  if (addr != ull)
    // the value returned by stoull is too large to be represented by l4_addr_t
    return false;

  _cache.addr = addr;
  _cached_type = Cached_addr;

  return true;
}

template<>
inline char const *
Arg::do_get<char const *>()
{ return _arg.c_str(); }

template<>
inline std::string
Arg::do_get<std::string>()
{ return _arg; }

template<>
inline char
Arg::do_get<char>()
{ return _arg[0]; }

template<>
inline unsigned
Arg::do_get<unsigned>()
{ return _cache.u; }

template<>
inline l4_addr_t
Arg::do_get<l4_addr_t>()
{ return _cache.addr; }

/**
 * Encapsulates a monitor commands argument list.
 */
class Arglist
: private Detail::Equality_comparable<Arglist, char const *>,
  private Detail::Equality_comparable<Arglist, std::string>
{
public:
  /**
   * Constructor.
   *
   * \param args  A C-string containing a list of arguments in the form of zero
   *              one or several words separated by single whitespace
   *              characters. Anything else causes the behaviour of the
   *              resulting object to be undefined.
   */
  explicit Arglist(char const *args)
  : _args(args),
    _argc(0)
  {
    assert(_args);

    if (empty())
      return;

    _argc = 1;

    char const *tmp = _args;
    while ((tmp = strchr(tmp, ' ')))
      {
        while (*tmp == ' ')
          ++tmp;

        if (*tmp != '\0')
          ++_argc;
      }
  }

  /**
   * Compare the complete argument list to a C-string.
   *
   * \param rhs  C-string to compare to the raw argument list.
   *
   * \return  `true` in case of equality, else `false`.
   *
   * The raw argument list is also a C-string containing all arguments
   * separated by single space characters.
   *
   * \note  It is also possible to evaluate `str == arglist`, `arglist != str`
   *        and `str != arglist` where `str` is a C-string and `arglist` is an
   *        object of type `Arglist`.
   */
  bool operator == (char const *rhs) const noexcept
  { return strcmp(_args, rhs) == 0; }

  /**
   * Compare the complete argument list to a String.
   *
   * \param rhs  String to compare to the raw argument list.
   *
   * \return  `true` in case of equality, else `false`.
   *
   * \see `operator == (char const *)`.
   */
  bool operator == (std::string const &rhs) const noexcept
  { return _args == rhs; }

  /**
   * Check whether the argument list contains no arguments.
   *
   * \return  `true` if the argument list contains no arguments, else `false`.
   */
  bool empty() const
  { return *_args == '\0'; }

  /**
   * Obtain the number of arguments in the argument list.
   *
   * \return  Number of arguments in the argument list.
   */
  unsigned count() const
  { return _argc; }

  /**
   * Non-destructively retrieve the next argument.
   *
   * \return  The next argument, if there are no more arguments (i.e.
   *          `empty() == true`) this function will still succeed, but calling
   *          `Arg::check<T>()` on the returned argument will return `false` for
   *          any `T`.
   *
   * This retrieves the first (i.e. leftmost) argument from the list of
   * arguments.
   */
  Arg peek() const
  {
    char const *delim = strchr(_args, ' ');

    if (!delim)
      return Arg(_args, strlen(_args));

    return Arg(_args, delim - _args);
  }

  /**
   * Non-destructively retrieve and convert the next argument.
   *
   * \tparam T  Type to convert the argument to.
   *
   * \param msg  Optional conversion failure error message.
   *
   * \return  The next argument converted to `T`.
   *
   * This is a convencience method whose result is equal to `peek().get<T>()`.
   */
  template<typename T>
  Arg peek(char const *msg = nullptr) const
  { return peek().get<T>(msg); }

  /**
   * Retrieve the next argument.
   *
   * \return  The next argument, if there are no more arguments (i.e.
   *          `empty() == true`) this function will still success, but calling
   *          `Arg::check<T>()` on the returned argument will return `false` for
   *          any `T`.
   *
   * This retrieves and removes the first (i.e. leftmost) argument from the
   * list of arguments.
   */
  Arg pop()
  {
    if (empty())
      return Arg("", 0);

    char const *arg = _args;
    size_t arglen;

    char const *delim = strchr(_args, ' ');

    if (delim)
      {
        arglen = delim - _args;
        _args = delim + 1;
      }
    else
      {
        arglen = strlen(_args);
        _args += arglen;
      }

    --_argc;

    return Arg(arg, arglen);
  }

  /**
   * Retrieve and convert the next argument.
   *
   * \tparam T  Type to convert the argument to.
   *
   * \param msg  Optional conversion failure error message.
   *
   * \return  The next argument converted to `T`.
   *
   * \throws L4::Runtime_error  If there are no more arguments or the conversion
   *                            fails.
   *
   * This is a convencience method whose result is equal to `pop().get<T>()`.
   */
  template<typename T>
  T pop(char const *msg = nullptr)
  { return pop().get<T>(msg); }

protected:
  char const *_args;
  unsigned _argc;
};

// Converting arguments to `char const *` is well defined but directly popping
// `char const *` must be disallowed since the temporary argument object which
// owns the memory backing the string is immediately destroyed once
// `pop<char const *>()` returns.
template<>
inline char const *
Arglist::pop<char const *>(char const *) = delete;

/**
 * Encapsulates a monitor command completion request.
 */
class Completion_request : public Arglist
{
public:
  using Arglist::Arglist;

  /**
   * Check whether this completion request contains trailing whitespace.
   *
   * \return  `true` if this completion request contains trailing whitespace,
   *          else `false`.
   *
   * This returns `true` if and only if the cursor was not positioned in the
   * middle or directly after the end of a word when this completion request
   * was created, else `false`.
   */
  bool trailing_space() const
  { return _args[strlen(_args) - 1] == ' '; }

  /**
   * Complete some word.
   *
   * \param f           Stream to which to write output
   * \param completion  Potential completion.
   *
   * If the completion request constitutes a prefix of `completion`, this will
   * print `completion` followed by a single newline to `f`.
   */
  void complete(FILE *f, char const *completion) const
  {
    if (strncmp(_args, completion, strlen(_args)) == 0)
      fprintf(f, "%s\n", completion);
  }

  /**
   * Apply `completion(FILE *, char const *)` to several potential completions
   * at once.
   *
   * \param f            Stream to which to write output
   * \param completions  List of potential completions.
   *
   * \see `complete(FILE *, char const *)`.
   */
  void complete(FILE *f, std::initializer_list<char const *> completions) const
  {
    for (char const *completion : completions)
      complete(f, completion);
  }
};

/**
 * Produce a command specific argument error.
 *
 * \param msg  Human readable error message.
 *
 * \throws L4::Runtime_error  Unconditionally.
 */
inline void
argument_error(char const *msg)
{ L4Re::chksys(-L4_EINVAL, msg); }

}
