/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include "cpu_dev.h"

namespace Vmm {

struct Sbi_ret
{
  long error;
  long value;
};

enum Sbi_error : long
{
  Sbi_success               =  0,
  Sbi_err_failed            = -1,
  Sbi_err_not_supported     = -2,
  Sbi_err_invalid_param     = -3,
  Sbi_err_denied            = -4,
  Sbi_err_invalid_address   = -5,
  Sbi_err_already_available = -6,
  // Custom internal error codes
  Sbi_err_unsupported_func  = -64,
  Sbi_err_v1_spec           = -65,
};

/**
 * Base class for all SBI extensions implemented in uvmm.
 */
class Sbi_ext : public Vdev::Device
{
public:
  /**
   * Dispatch method, which is overriden by the SBI extension implementations
   * derived from this base class. The method receives SBI calls targeted at
   * the SBI extension. Usually it is implemented as a switch-case that
   * delegates handling the SBI call to the method corresponding to the given
   * SBI function id.
   */
  virtual Sbi_ret handle(l4_int32_t ext_id, l4_int32_t func_id, Vcpu_ptr vcpu) = 0;

  /**
   * Extract argument from vCPU state and cast it to the expected type.
   */
  template<typename A>
  static inline A map_arg(l4_umword_t **args)
  {
    static_assert(
      sizeof(A) <= sizeof(l4_umword_t) || sizeof(A) == sizeof(l4_uint64_t),
      "Unexpected argument size");

    if constexpr (sizeof(A) <= sizeof(l4_umword_t))
      {
        return *(*args)++;
      }
    // 64-bit integers on 32-bit architecture
    else if constexpr (sizeof(A) == sizeof(l4_uint64_t))
      {
        A arg = *(*args)++;
        arg += static_cast<A>(*(*args)++) << 32;
        return arg;
      }
  }

  template<typename R, typename C>
  inline Sbi_ret call(Vcpu_ptr vcpu, R(C::*f)(Vcpu_ptr))
  {
    return (static_cast<C *>(this)->*f)(vcpu);
  }

  template<typename R, typename C, typename... Args>
  inline Sbi_ret call(Vcpu_ptr vcpu, R(C::*f)(Vcpu_ptr, Args ...))
  {
    l4_umword_t *args = &vcpu->r.a0;
    return (static_cast<C *>(this)->*f)(vcpu, map_arg<Args>(&args)...);
  }

  template<typename R, typename C>
  inline Sbi_ret call(Vcpu_ptr, R(C::*f)())
  {
    return (static_cast<C *>(this)->*f)();
  }

  template<typename R, typename C, typename... Args>
  inline Sbi_ret call(Vcpu_ptr vcpu, R(C::*f)(Args ...))
  {
    l4_umword_t *args = &vcpu->r.a0;
    return (static_cast<C *>(this)->*f)(map_arg<Args>(&args)...);
  }

  static Sbi_ret sbi_error(Sbi_error error)
  {
    return { error, 0 };
  }

  static Sbi_ret sbi_value(long value)
  {
    return { Sbi_success, value };
  }

  static Sbi_ret sbi_void()
  {
    return sbi_value(0);
  }
};

class Sbi
{
public:
  static Sbi *create_instance(Guest *guest);

  Sbi(Guest *guest);

  /**
   * Register the given SBI extension for the given range of extension ids.
   */
  void register_ext(l4_int32_t ext_id_start, l4_int32_t ext_id_end,
                    cxx::Ref_ptr<Sbi_ext> handler);

  /**
   * Register the given SBI extension for the given extension id.
   */
  void register_ext(l4_int32_t ext_id, cxx::Ref_ptr<Sbi_ext> handler)
  { register_ext(ext_id, ext_id, handler); }

  /**
   * Find SBI extension registered for the given extension id.
   */
  Sbi_ext *find_ext(l4_int32_t ext_id) const;

  /**
   * Handle SBI call from the guest.
   */
  bool handle(Vcpu_ptr vcpu);

  Guest *guest()
  { return _guest; }

private:
  Guest * _guest;

  struct Extension
  {
    l4_int32_t ext_id_start;
    l4_int32_t ext_id_end;
    cxx::Ref_ptr<Sbi_ext> handler;
  };
  std::vector<Extension> _extensions;
};

class Sbi_base : public Sbi_ext
{
public:
  Sbi_ret handle(l4_int32_t, l4_int32_t func_id, Vcpu_ptr vcpu) override;

private:
  enum : long
  {
    Sbi_fid_get_sbi_spec_version = 0,
    Sbi_fid_get_sbi_impl_id      = 1,
    Sbi_fid_get_sbi_impl_version = 2,
    Sbi_fid_probe_extension      = 3,
    Sbi_fid_get_mvendorid        = 4,
    Sbi_fid_get_marchid          = 5,
    Sbi_fid_get_mimpid           = 6,
  };

  Sbi_ret get_spec_version();
  Sbi_ret get_impl_id();
  Sbi_ret get_impl_version();
  Sbi_ret probe_extension(long ext_id);
  Sbi_ret get_mvendorid();
  Sbi_ret get_marchid();
  Sbi_ret get_mimpid();
};

class Sbi_time : public Sbi_ext
{
public:
  Sbi_ret handle(l4_int32_t, l4_int32_t func_id, Vcpu_ptr vcpu) override;

private:
  enum : long
  {
    Sbi_fid_set_timer = 0,
  };

  Sbi_ret set_timer(Vcpu_ptr vcpu, l4_uint64_t stime_value);
};

class Sbi_ipi : public Sbi_ext
{
public:
  Sbi_ret handle(l4_int32_t, l4_int32_t func_id, Vcpu_ptr vcpu) override;

private:
  enum : long
  {
    Sbi_fid_send_ipi = 0,
  };

  Sbi_ret send_ipi(Vcpu_ptr vcpu, l4_umword_t hart_mask,
                   l4_umword_t hart_mask_base);
};

class Sbi_rfnc : public Sbi_ext
{
public:
  Sbi_ret handle(l4_int32_t, l4_int32_t func_id, Vcpu_ptr vcpu) override;

private:
  enum : long
  {
    Sbi_fid_remote_fence_i         = 0,
    Sbi_fid_remote_sfence_vma      = 1,
    Sbi_fid_remote_sfence_vma_asid = 2,
  };

  Sbi_ret remote_fence_i(
    Vcpu_ptr vcpu, l4_umword_t hart_mask, l4_umword_t hart_mask_base);

  Sbi_ret remote_sfence_vma(
    Vcpu_ptr vcpu, l4_umword_t hart_mask, l4_umword_t hart_mask_base,
    l4_umword_t start_addr, l4_umword_t size);

  Sbi_ret remote_sfence_vma_asid(
    Vcpu_ptr vcpu, l4_umword_t hart_mask, l4_umword_t hart_mask_base,
    l4_umword_t start_addr, l4_umword_t size, l4_umword_t asid);

  Sbi_ret remote_fence(
    Vcpu_ptr vcpu, L4_vm_rfnc remote_fence,
    l4_umword_t hart_mask, l4_umword_t hart_mask_base,
    l4_umword_t start_addr = 0, l4_umword_t size = 0, l4_umword_t asid = 0);
};

class Sbi_hsm : public Sbi_ext
{
public:
  Sbi_ret handle(l4_int32_t, l4_int32_t func_id, Vcpu_ptr vcpu) override;

private:
  enum : long
  {
    Sbi_fid_hart_start      = 0,
    Sbi_fid_hart_stop       = 1,
    Sbi_fid_hart_get_status = 2,
    Sbi_fid_hart_suspend    = 3,
  };

  Sbi_ret hart_start(l4_umword_t hartid, l4_umword_t start_addr,
                     l4_umword_t priv);

  Sbi_ret hart_stop(Vcpu_ptr vcpu);

  enum Hart_status
  {
    Hart_started               = 0,
    Hart_stopped               = 1,
    Hart_start_request_pending = 2,
    Hart_stop_request_pending  = 3,
    Hart_suspended             = 4,
  };

  Sbi_ret hart_status(l4_umword_t hartid);

  Sbi_ret hart_suspend(Vcpu_ptr vcpu, l4_uint32_t suspend_type,
                       l4_umword_t resume_addr, l4_umword_t opaque);
};

class Sbi_legacy : public Sbi_ext
{
public:
  Sbi_legacy();
  Sbi_ret handle(l4_int32_t ext_id, l4_int32_t, Vcpu_ptr vcpu) override;

private:
  Sbi_ret console_putchar(int ch);
  Sbi_ret console_getchar();
  Sbi_ret shutdown();

  L4::Cap<L4::Vcon> _con;
};

} //namespace Vmm
