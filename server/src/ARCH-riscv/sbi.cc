/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <l4/cxx/static_container>

#include "debug.h"
#include "guest.h"
#include "sbi.h"

static Dbg warn(Dbg::Core, Dbg::Warn, "sbi");
static Dbg info(Dbg::Core, Dbg::Info, "sbi");
static Dbg trace(Dbg::Core, Dbg::Trace, "sbi");

namespace Vmm {

namespace {

enum : l4_int32_t
{
  Sbi_ext_legacy_set_timer              = 0,
  Sbi_ext_legacy_console_putchar        = 1,
  Sbi_ext_legacy_console_getchar        = 2,
  Sbi_ext_legacy_clear_ipi              = 3,
  Sbi_ext_legacy_send_ipi               = 4,
  Sbi_ext_legacy_remote_fence_i         = 5,
  Sbi_ext_legacy_remote_sfence_vma      = 6,
  Sbi_ext_legacy_remote_sfence_vma_asid = 7,
  Sbi_ext_legacy_shutdown               = 8,
};

enum : l4_int32_t
{
  Sbi_ext_base    = 0x10,
  Sbi_ext_time    = 0x54494D45,
  Sbi_ext_ipi     = 0x735049,
  Sbi_ext_rfnc    = 0x52464E43,
  Sbi_ext_hsm     = 0x48534D,
};

}

// The singleton instance of the VMM.
static cxx::Static_container<Sbi> sbi;

Sbi *
Sbi::create_instance(Guest *guest)
{
  sbi.construct(guest);
  return sbi;
}

Sbi::Sbi(Guest *guest)
: _guest(guest)
{
  register_ext(Sbi_ext_legacy_set_timer, Sbi_ext_legacy_shutdown,
               Vdev::make_device<Sbi_legacy>());
  register_ext(Sbi_ext_base, Vdev::make_device<Sbi_base>());
  register_ext(Sbi_ext_time, Vdev::make_device<Sbi_time>());
  register_ext(Sbi_ext_ipi, Vdev::make_device<Sbi_ipi>());
  register_ext(Sbi_ext_rfnc, Vdev::make_device<Sbi_rfnc>());
  register_ext(Sbi_ext_hsm, Vdev::make_device<Sbi_hsm>());
}

void
Sbi::register_ext(l4_int32_t ext_id_start, l4_int32_t ext_id_end,
                  cxx::Ref_ptr<Sbi_ext> handler)
{
  if (ext_id_start > ext_id_end)
    {
      Err().printf("Invalid extension ID range [0x%x, 0x%x].\n",
                     ext_id_start, ext_id_end);
      L4Re::throw_error(-L4_EINVAL, "Register SBI extension");
    }

  for (auto const &ext : _extensions)
    {
      if (ext_id_start <= ext.ext_id_end && ext_id_end >= ext.ext_id_start)
      {
        Err().printf("Extension ID range [0x%x, 0x%x] overlaps with [0x%x, 0x%x].\n",
                     ext_id_start, ext_id_end, ext.ext_id_start, ext.ext_id_end);
        L4Re::throw_error(-L4_EINVAL, "Register SBI extension");
      }
    }

  _extensions.push_back({ext_id_start, ext_id_end, handler});
}

bool
Sbi::handle(Vcpu_ptr vcpu)
{
  l4_int32_t sbi_ext = vcpu->r.a7;
  l4_int32_t sbi_func = vcpu->r.a6;
  Sbi_ext *ext = find_ext(sbi_ext);
  if (ext)
    {
      Sbi_ret ret = ext->handle(sbi_ext, sbi_func, vcpu);
      if(ret.error == Sbi_err_v1_spec)
        {
          // Return value is passed in a0
          vcpu->r.a0 = ret.value;
          return true;
        }
      else if(ret.error != Sbi_err_unsupported_func)
        {
          // Sbi_ret is passed in a0/a1
          vcpu->r.a0 = ret.error;
          vcpu->r.a1 = ret.value;
          return true;
        }
    }

  warn.printf("Unsupported SBI call: ext=0x%x, func=0x%x, ip=0x%lx -> %s\n",
              sbi_ext, sbi_func, vcpu->r.ip,
              ext ? "function unknown" : "extension unknown");

  return false;
}

Sbi_ext *
Sbi::find_ext(l4_int32_t ext_id) const
{
  for (auto const &ext : _extensions)
    {
      if (ext_id >= ext.ext_id_start && ext_id <= ext.ext_id_end)
        return ext.handler.get();
    }

  return nullptr;
}

Sbi_ret Sbi_base::get_spec_version()
{
  // SBI specification v0.3
  return sbi_value(3);
}

Sbi_ret Sbi_base::get_impl_id()
{
  // "uvmm" = 0x75766d6d
  return sbi_value(0x75766d6d);
}

Sbi_ret Sbi_base::get_impl_version()
{
  return sbi_value(1);
}

Sbi_ret Sbi_base::probe_extension(long ext_id)
{
  bool present = sbi->find_ext(ext_id) != nullptr;
  return sbi_value(present);
}

Sbi_ret Sbi_base::get_mvendorid()
{
  return sbi_value(0);
}

Sbi_ret Sbi_base::get_marchid()
{
  return sbi_value(0);
}

Sbi_ret Sbi_base::get_mimpid()
{
  return sbi_value(0);
}

Sbi_ret Sbi_base::handle(l4_int32_t, l4_int32_t func_id, Vcpu_ptr vcpu)
{
  switch(func_id)
    {
      case Sbi_fid_get_sbi_spec_version:
        return call(vcpu, &Sbi_base::get_spec_version);
      case Sbi_fid_get_sbi_impl_id:
        return call(vcpu, &Sbi_base::get_impl_id);
      case Sbi_fid_get_sbi_impl_version:
        return call(vcpu, &Sbi_base::get_impl_version);
      case Sbi_fid_probe_extension:
        return call(vcpu, &Sbi_base::probe_extension);
      case Sbi_fid_get_mvendorid:
        return call(vcpu, &Sbi_base::get_mvendorid);
      case Sbi_fid_get_marchid:
        return call(vcpu, &Sbi_base::get_marchid);
      case Sbi_fid_get_mimpid:
        return call(vcpu, &Sbi_base::get_mimpid);
      default:
        return sbi_error(Sbi_err_unsupported_func);
    }
}

Sbi_ret Sbi_time::set_timer(Vcpu_ptr vcpu, l4_uint64_t stime_value)
{
  if (sbi->guest()->has_vstimecmp())
    {
      vcpu.vm_state()->vstimecmp = stime_value;
    }
  else
    {
      // Clear pending timer interrupt
      sbi->guest()->get_vcpu_ic(vcpu)->clear_timer();

      // Set next timer interrup
      sbi->guest()->get_timer(vcpu)->set_next_event(stime_value);
    }

  return sbi_void();
}

Sbi_ret Sbi_time::handle(l4_int32_t, l4_int32_t func_id, Vcpu_ptr vcpu)
{
  switch(func_id)
    {
      case Sbi_fid_set_timer:
        return call(vcpu, &Sbi_time::set_timer);
      default:
        return sbi_error(Sbi_err_unsupported_func);
    }
}

Sbi_ret Sbi_ipi::send_ipi(Vcpu_ptr vcpu, l4_umword_t hart_mask,
                          l4_umword_t hart_mask_base)
{
  if (hart_mask_base == -1UL)
    {
      trace.printf("Sending IPI from %u to all vCPUs\n", vcpu.get_vcpu_id());
      for (auto const &target : *sbi->guest()->cpus().get())
        {
          sbi->guest()->get_vcpu_ic(target->vcpu())->notify_ipi(vcpu);
        }
    }
  else
    {
      for (unsigned i = 0; i < sizeof(hart_mask) * 8; i++)
        {
          if (hart_mask & (1UL << i))
            {
              unsigned hartid = hart_mask_base + i;
              Cpu_dev *target = sbi->guest()->lookup_cpu(hartid);
              if (!target)
                return sbi_error(Sbi_err_invalid_param);

              trace.printf("Sending IPI from %u to vCPU %u\n",
                           vcpu.get_vcpu_id(), hartid);
              sbi->guest()->get_vcpu_ic(target->vcpu())->notify_ipi(vcpu);
            }
        }
    }

  return sbi_void();
}

Sbi_ret Sbi_ipi::handle(l4_int32_t, l4_int32_t func_id, Vcpu_ptr vcpu)
{
  switch(func_id)
    {
      case Sbi_fid_send_ipi:
        return call(vcpu, &Sbi_ipi::send_ipi);
      default:
        return sbi_error(Sbi_err_unsupported_func);
    }
}

Sbi_ret Sbi_rfnc::remote_fence_i(Vcpu_ptr vcpu,
  l4_umword_t hart_mask, l4_umword_t hart_mask_base)
{
  return remote_fence(vcpu, L4_vm_rfnc_fence_i, hart_mask, hart_mask_base);
}

Sbi_ret Sbi_rfnc::remote_sfence_vma(Vcpu_ptr vcpu,
  l4_umword_t hart_mask, l4_umword_t hart_mask_base,
  l4_umword_t start_addr, l4_umword_t size)
{
  return remote_fence(vcpu, L4_vm_rfnc_fence_i, hart_mask, hart_mask_base,
                      start_addr, size);
}

Sbi_ret Sbi_rfnc::remote_sfence_vma_asid(Vcpu_ptr vcpu,
  l4_umword_t hart_mask, l4_umword_t hart_mask_base,
  l4_umword_t start_addr, l4_umword_t size, l4_umword_t asid)
{
  return remote_fence(vcpu, L4_vm_rfnc_fence_i, hart_mask, hart_mask_base,
                      start_addr, size, asid);
}

Sbi_ret Sbi_rfnc::remote_fence(
    Vcpu_ptr vcpu, L4_vm_rfnc remote_fence,
    l4_umword_t hart_mask, l4_umword_t hart_mask_base,
    l4_umword_t start_addr, l4_umword_t size, l4_umword_t asid)
{
  auto vm_state = vcpu.vm_state();

  // Translate vCPU mask into physical cpu mask
  l4_umword_t host_hart_mask = 0;
  if (hart_mask_base == -1UL)
    {
      for (auto const &target : *sbi->guest()->cpus().get())
        {
          host_hart_mask |= 1UL << target->get_phys_cpu_id();
        }
    }
  else
    {
      for (unsigned i = 0; i < sizeof(hart_mask) * 8; i++)
        {
          if (hart_mask & (1UL << i))
            {
              unsigned hartid = hart_mask_base + i;
              Cpu_dev *target = sbi->guest()->lookup_cpu(hartid);
              if (!target)
                return sbi_error(Sbi_err_invalid_param);

              host_hart_mask |= 1UL << target->get_phys_cpu_id();
            }
        }
    }

  trace.printf("Sending remote fence %u to harts 0x%lx (0x%lx) from %u\n",
             remote_fence, host_hart_mask, hart_mask, vcpu.get_vcpu_id());
  vm_state->remote_fence = remote_fence;
  vm_state->remote_fence_hart_mask = host_hart_mask;
  vm_state->remote_fence_start_addr = start_addr;
  vm_state->remote_fence_size = size;
  vm_state->remote_fence_asid = asid;

  return sbi_void();
}

Sbi_ret Sbi_rfnc::handle(l4_int32_t, l4_int32_t func_id, Vcpu_ptr vcpu)
{
  switch(func_id)
    {
      case Sbi_fid_remote_fence_i:
        return call(vcpu, &Sbi_rfnc::remote_fence_i);
      case Sbi_fid_remote_sfence_vma:
        return call(vcpu, &Sbi_rfnc::remote_sfence_vma);
      case Sbi_fid_remote_sfence_vma_asid:
        return call(vcpu, &Sbi_rfnc::remote_sfence_vma_asid);
      default:
        return sbi_error(Sbi_err_unsupported_func);
    }
}

Sbi_ret Sbi_hsm::hart_start(l4_umword_t hartid, l4_umword_t start_addr,
                            l4_umword_t priv)
{
  Cpu_dev *hart = sbi->guest()->lookup_cpu(hartid);
  if (!hart)
    return sbi_error(Sbi_err_invalid_param);

  if (!hart->online() && hart->mark_on_pending())
    {
      Vcpu_ptr vcpu = hart->vcpu();
      vcpu->r.ip = start_addr;
      vcpu->r.a0 = vcpu.get_vcpu_id();
      vcpu->r.a1 = priv;

      // Prepare_vcpu_startup
      if (hart->start_vcpu())
        return sbi_error(Sbi_success);
      else
        return sbi_error(Sbi_err_failed);
    }
  else
    return sbi_error(Sbi_err_already_available);
}

Sbi_ret Sbi_hsm::hart_stop(Vcpu_ptr vcpu)
{
  sbi->guest()->lookup_cpu(vcpu.get_vcpu_id())->stop_vcpu();
  __builtin_unreachable();
}

Sbi_ret Sbi_hsm::hart_status(l4_umword_t hartid)
{
  Cpu_dev *hart = sbi->guest()->lookup_cpu(hartid);
  if (!hart)
    return sbi_error(Sbi_err_invalid_param);

  switch (hart->online_state())
    {
      case Cpu_dev::Cpu_state::Off:
        return sbi_value(Hart_stopped);
      case Cpu_dev::Cpu_state::On_pending:
      case Cpu_dev::Cpu_state::On_prepared:
        return sbi_value(Hart_start_request_pending);
      case Cpu_dev::Cpu_state::On:
        return sbi_value(Hart_started);
      case Cpu_dev::Cpu_state::Suspended:
        return sbi_value(Hart_suspended);
    }

  __builtin_unreachable();
}

Sbi_ret Sbi_hsm::hart_suspend(Vcpu_ptr vcpu, l4_uint32_t suspend_type,
                              l4_umword_t, l4_umword_t)
{
  if (suspend_type == 0) // Default retentive suspend
    {
      auto guest = sbi.get()->guest();
      Cpu_dev *hart = guest->lookup_cpu(vcpu.get_vcpu_id());
      hart->mark_suspended();
      guest->wfi(vcpu);
      hart->mark_on();
      return sbi_void();
    }

  if (suspend_type == 0x80000000) // Default non-retentive suspend
    return sbi_error(Sbi_err_not_supported);

  return sbi_error(Sbi_err_invalid_param);
}

Sbi_ret Sbi_hsm::handle(l4_int32_t, l4_int32_t func_id, Vcpu_ptr vcpu)
{
  switch(func_id)
    {
      case Sbi_fid_hart_start:
        return call(vcpu, &Sbi_hsm::hart_start);
      case Sbi_fid_hart_stop:
        return call(vcpu, &Sbi_hsm::hart_stop);
      case Sbi_fid_hart_get_status:
        return call(vcpu, &Sbi_hsm::hart_status);
      case Sbi_fid_hart_suspend:
        return call(vcpu, &Sbi_hsm::hart_suspend);
      default:
        return sbi_error(Sbi_err_unsupported_func);
    }
}

Sbi_legacy::Sbi_legacy()
: _con(L4Re::Env::env()->log())
{
}

Sbi_ret Sbi_legacy::console_putchar(int ch)
{
  char const c = ch;
  _con->write(&c, 1);

  return sbi_void();
}

Sbi_ret Sbi_legacy::console_getchar()
{
  char buf;
  int err = _con->read(&buf, 1);
  return sbi_value(err < 0 ? -1 : buf);
}

Sbi_ret Sbi_legacy::shutdown()
{
  info.printf("Received request to shutdown the guest.\n");
  sbi->guest()->shutdown(Guest::Shutdown);
  return sbi_void();
}

Sbi_ret Sbi_legacy::handle(l4_int32_t ext_id, l4_int32_t, Vcpu_ptr vcpu)
{
  Sbi_ret ret;
  switch(ext_id)
    {
      case Sbi_ext_legacy_console_putchar:
        ret = call(vcpu, &Sbi_legacy::console_putchar);
        break;
      case Sbi_ext_legacy_console_getchar:
        ret = call(vcpu, &Sbi_legacy::console_getchar);
        break;
      case Sbi_ext_legacy_shutdown:
        ret = call(vcpu, &Sbi_legacy::shutdown);
        break;
      default:
        return sbi_error(Sbi_err_unsupported_func);
    }
  return {Sbi_err_v1_spec, ret.value};
}

} //namespace Vmm
