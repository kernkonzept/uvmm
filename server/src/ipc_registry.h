/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Jan Klötzke <jan.kloetzke@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <l4/re/util/object_registry>

/**
 * IPC object registry with the capability to move objects between threads.
 *
 * The plain L4Re Object_registry does not allow to move ownership of objects
 * between registries.
 */
class Vcpu_obj_registry : public L4Re::Util::Object_registry
{
public:
  explicit Vcpu_obj_registry(L4::Ipc_svr::Server_iface *sif)
  : L4Re::Util::Object_registry(sif) {}

  L4::Cap<L4::Thread> server() const
  { return _server; }

  void set_server(L4::Cap<L4::Thread> server)
  { _server = server; }

  /**
   * Move registered object `o` to this registry.
   *
   * The object must already be registered at another Object_registry.
   *
   * \param o Pointer to the Epiface object that shall be moved. The object
   *          must have been registered previously.
   *
   * \retval L4::Cap<L4::Rcv_endpoint>           Capability `o->obj_cap()` on success.
   * \retval L4::Cap<L4::Rcv_endpoint>::Invalid  The object could not be moved.
   *
   * After the call succeeded newly arriving IPCs will be dispatched at this
   * registry. Note that concurrent dispatching at the old registry could lead
   * to IPC calls being delivered there even *after* this call returned if they
   * are already in flight! It is the responsibility of the caller to
   * synchronize with the old thread if this is of concern.
   */
  L4::Cap<L4::Rcv_endpoint>
  move_obj(L4::Epiface *o)
  {
    if (!o->obj_cap().is_valid())
      return L4::Cap<L4::Rcv_endpoint>(-L4_EINVAL | L4_INVALID_CAP_BIT);

    int err = _sif->alloc_buffer_demand(o->get_buffer_demand());
    if (err < 0)
      return L4::Cap<L4::Rcv_endpoint>(err | L4_INVALID_CAP_BIT);

    L4::Epiface::Stored_cap c = o->obj_cap();
    auto ep = L4::cap_cast<L4::Rcv_endpoint>(c);
    l4_umword_t id = l4_umword_t(o);
    err = l4_error(ep->bind_thread(_server, id));
    if (err < 0)
      return L4::Cap<L4::Rcv_endpoint>(err | L4_INVALID_CAP_BIT);

    err = o->set_server(_sif, ep, c.managed());
    if (err < 0)
      return L4::Cap<L4::Rcv_endpoint>(err | L4_INVALID_CAP_BIT);

    return ep;
  }
};
