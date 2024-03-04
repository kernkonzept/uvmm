/*
 * Copyright (C) 2022,2024 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <vector>

#include <l4/cxx/unique_ptr>
#include "device.h"

namespace Vdev
{

struct Pm_device;

/**
 * Registry for all devices requesting notification for power management events.
 */
class Pm_device_registry
{
public:
  /// Register a device for power management event notifications.
  static void register_device(Pm_device *dev)
  { Pm_device_registry::get()->add(dev); }

  /// Remove a device from power management event notifications.
  static void remove_device(Pm_device *dev)
  { Pm_device_registry::get()->remove(dev); }

  /// Notify all registered devices of a suspend event.
  static void suspend_devices()
  { Pm_device_registry::get()->suspend(); }

  /// Notify all registered devices of a resume event.
  static void resume_devices()
  { Pm_device_registry::get()->resume(); }

private:
  Pm_device_registry() = default;
  Pm_device_registry(Pm_device_registry &) = delete;
  Pm_device_registry(Pm_device_registry &&) = delete;

  static Pm_device_registry *get()
  {
    if (!_self)
      _self = cxx::make_unique_ptr(new Pm_device_registry());

    return _self.get();
  }

  void add(Pm_device *dev);
  void remove(Pm_device *dev);

  void suspend() const;
  void resume() const;

  static cxx::unique_ptr<Pm_device_registry> _self;
  std::vector<Pm_device *> _devices;
}; // class Pm_device_registry

/**
 * Interface for devices which need to act on power management events.
 *
 * This interface provides functions that will be called on power management
 * actions emitting from the guest or events affecting the guest.
 */
struct Pm_device
{
  /// The constructor registers the device for power management events.
  Pm_device()
  { Pm_device_registry::register_device(this); }

  /**
   * The destructor removes the device from power management event
   * notifications.
   */
  ~Pm_device()
  { Pm_device_registry::remove_device(this); }

  /**
   * Actions a device needs to perform during the process to suspend the guest.
   */
  virtual void pm_suspend() = 0;

  /**
   * Actions a device needs to perform during the process to resume the guest.
   */
  virtual void pm_resume() = 0;
}; // struct Pm_device

} // namespace Vdev
