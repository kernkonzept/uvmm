/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <sstream>

// Base value class
struct Generic_value: std::enable_shared_from_this<Generic_value>
{ virtual ~Generic_value() = default; };

// Specialized value
template <typename T>
struct Value: Generic_value
{
  explicit Value(const T &val)
  : _val(val)
  {}

  explicit Value(T &&val)
  : _val(std::move(val))
  {}

  std::shared_ptr<Generic_value> base()
  { return shared_from_this(); }

  const T &value() const { return _val; }

private:
  T _val;
};

// Shared value
struct Shared_value
{
  Shared_value() = default;

  template <typename T>
  Shared_value(const T &val)
  : _val(std::make_shared<Value<T>>(val)->base())
  {}

  template <typename T>
  Shared_value(T &&val)
  : _val(std::make_shared<Value<T>>(std::move(val))->base())
  {}

  template <typename T>
  void store(const T &val)
  { _val = std::make_shared<Value<T>>(val)->base(); }

  template <typename T>
  void store(T &&val)
  { _val = std::make_shared<Value<T>>(std::move(val))->base(); }

  template<typename T>
  const T &as() const
  { return dynamic_cast<const Value<T> *>(_val.get())->value(); }

  bool has_value() const
  { return (bool)_val; }

private:
  std::shared_ptr<Generic_value> _val;
};
