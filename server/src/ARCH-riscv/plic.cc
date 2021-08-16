/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "debug.h"
#include "device_factory.h"
#include "guest.h"
#include "plic.h"

static Dbg warn(Dbg::Irq, Dbg::Warn, "plic");
static Dbg info(Dbg::Irq, Dbg::Info, "plic");
static Dbg trace(Dbg::Irq, Dbg::Trace, "plic");

namespace Gic {

Plic::Plic_target::Plic_target(Plic *plic, Vmm::Vcpu_ptr vcpu,
                               cxx::Ref_ptr<Vcpu_ic> vcpu_ic)
: _plic(plic),
  _vcpu(vcpu),
  _vcpu_ic(vcpu_ic),
  _threshold(0)
{
}

void Plic::Plic_target::enable(l4_uint32_t offset, l4_uint32_t value,
                               Vmm::Vcpu_ptr current_vcpu)
{
  assert(offset < Num_irqs / 32);
  _enable.set_word32(offset, value);
  update_ext_int_pending(pending_irq(), current_vcpu);
}

l4_uint32_t Plic::Plic_target::enabled(l4_uint32_t offset) const
{
  assert(offset < Num_irqs / 32);
  return _enable.word32(offset);
}

l4_uint32_t Plic::Plic_target::claim(Vmm::Vcpu_ptr current_vcpu)
{
  for (;;)
    {
      unsigned best_irq = 0;
      unsigned nr_pending = 0;
      if (!find_best_irq(best_irq, nr_pending))
        {
          // No pending interrupt.
          update_ext_int_pending(false, current_vcpu);
          return 0;
        }

      if (_plic->claim_irq(best_irq))
        {
          // Update the external interrupt pending state of this target
          update_ext_int_pending(nr_pending > 1, current_vcpu);
          return best_irq;
        }
      // Already claimed, retry with next interrupt.
    }
}

void Plic::Plic_target::complete(l4_uint32_t irq, Vmm::Vcpu_ptr current_vcpu)
{
  assert(irq < Num_irqs);

  // Interrupt has to be enabled, otherwise complete has no effect.
  if (_enable[irq])
    {
      if (auto handler = _plic->get_irq_src_handler(irq))
        handler->eoi();

      if (_plic->_gateways[irq].complete())
        // Interrupt still pending, update for all targets.
        _plic->set_irq(irq, current_vcpu);
    }
}

l4_uint32_t Plic::Plic_target::threshold() const
{
  return _threshold;
}

void Plic::Plic_target::threshold(l4_uint32_t threshold,
                                  Vmm::Vcpu_ptr current_vcpu)
{
  _threshold = threshold;
  update_ext_int_pending(pending_irq(), current_vcpu);
}

void Plic::Plic_target::update_ext_int_pending(bool pending,
                                               Vmm::Vcpu_ptr current_vcpu)
{
  _vcpu_ic->set_external_pending(pending, current_vcpu);
}

bool Plic::Plic_target::find_best_irq(unsigned &best_irq,
                                      unsigned &nr_pending) const
{
  nr_pending = 0;
  best_irq = 0;
  unsigned best_irq_priority = 0;
  Per_irq_bitmap::for_set_bits([&](unsigned irq)
    {
      unsigned irq_priority = _plic->_priorities[irq];
      if (irq_priority > _threshold)
        {
          ++nr_pending;
          // Smaller interrupts identifiers take precedence over larger ones,
          // if both have the same priority assigned.
          if (irq_priority > best_irq_priority)
            {
              best_irq = irq;
              best_irq_priority = irq_priority;
            }
        }
    }, _plic->_pending, _enable);

  return best_irq != 0;
}

bool Plic::Plic_target::pending_irq() const
{
  bool pending = false;
  Per_irq_bitmap::for_set_bits([&](unsigned irq)
    {
      if (_plic->_priorities[irq] > _threshold)
        {
          pending = true;
          // Found pending interrupt, stop iteration.
          return Per_irq_bitmap::Break;
        }
      else
        return Per_irq_bitmap::Continue;
    }, _plic->_pending, _enable);
  return pending;
}

Plic::Plic(Vdev::Dt_node const &node, unsigned num_dt_interrupt_targets)
: _num_dt_interrupt_targets(num_dt_interrupt_targets)
{
  node.setprop_u32("riscv,ndev", Num_irqs);
}

void Plic::setup_target(Vmm::Vcpu_ptr vcpu, cxx::Ref_ptr<Vcpu_ic> vcpu_ic)
{
  if (_num_dt_interrupt_targets == _num_targets_created)
    L4Re::throw_error(-L4_EINVAL,
                      "The interrupts-extended property in the device tree refers "
                      "to fewer interrupt targets than there are vCPUs.\n");

  if(vcpu.get_vcpu_id() >= _targets.size())
    _targets.resize(vcpu.get_vcpu_id() + 1);

  _targets[vcpu.get_vcpu_id()] = cxx::make_unique<Plic_target>(this, vcpu,
                                                               vcpu_ic);
  ++_num_targets_created;
}

Vmm::Vcpu_ptr Plic::get_vcpu(unsigned cpu_id)
{
  assert(cpu_id < _targets.size());
  return _targets[cpu_id]->vcpu();
}

bool Plic::check_access(unsigned reg, char size, char const *operation)
{
  if (size != Vmm::Mem_access::Wd32)
    {
      warn.printf("%s @0x%x with unsupported width %d ignored\n",
                  operation, reg, 8 << size);
      return false;
    }

  if (reg % 4 != 0)
    {
      warn.printf("misaligned %s @0x%x with width %d ignored\n",
                  operation, reg, 8 << size);
      return false;
    }

  return true;
}

bool Plic::check_irq(unsigned irq, char const *operation)
{
  if (irq < 1 || irq >= Num_irqs)
    {
      warn.printf("attempt to %s of not implemented irq %u ignored\n",
                  operation, irq);
      return false;
    }

  return true;
}

bool Plic::check_irq_range(unsigned offset, char const *operation)
{
  unsigned first_irq = offset * 32;
  unsigned last_irq = first_irq + 31;
  if (last_irq >= Num_irqs)
    {
      warn.printf("attempt to %s of not implemented irq range [%u, %u] ignored\n",
                  operation, first_irq, last_irq);
      return false;
    }

  return true;
}

bool Plic::check_target(unsigned target_id)
{
  if (target_id >= _targets.size() || !get_target(target_id))
    {
      warn.printf("attempt to access non existing target %u ignored\n",
                  target_id);
      return false;
    }

  return true;
}

bool Plic::claim_irq(unsigned irq)
{
  if (_gateways[irq].claim())
    {
      _pending.clear_bit(irq);
      return true;
    }
  else
    return false;
}

void Plic::set_irq(unsigned irq, Vmm::Vcpu_ptr current_vcpu)
{
  _pending.set_bit(irq);

  for(auto &target : _targets)
    if (target)
      target->update_ext_int_pending(target->pending_irq(), current_vcpu);
}

l4_umword_t Plic::read(unsigned reg, char size, unsigned cpu_id)
{
  if (!check_access(reg, size, "read"))
    return 0;

  // TODO: More fine grained locking?
  std::lock_guard<std::mutex> lock(_lock);

  if (/*reg >= Priority_base && */ reg < Pending_base)
    {
      unsigned irq = (reg - Priority_base) / 4;
      if (check_irq(irq, "read priority register"))
        return _priorities[irq];
    }
  else if (reg >= Pending_base && reg < Enable_base)
    {
      unsigned offset = (reg - Pending_base) / 4;
      if (check_irq_range(offset, "read pending register"))
        return _pending.word32(offset);
    }
  else if (reg >= Enable_base && reg < Context_base)
    {
      unsigned target_id = (reg - Enable_base) / Enable_per_hart;
      unsigned offset = (reg & Enable_mask) / 4;
      if (   check_target(target_id)
          && check_irq_range(offset, "read enable register"))
        return get_target(target_id)->enabled(offset);
    }
  else if (reg >= Context_base)
    {
      unsigned target_id = (reg - Context_base) / Context_per_hart;
      unsigned offset = (reg & Context_mask);
      if (check_target(target_id))
        {
          if (offset == Context_threshold)
            return get_target(target_id)->threshold();
          else if (offset == Context_claim)
            return get_target(target_id)->claim(get_vcpu(cpu_id));
          else
              warn.printf("attempt to read non existing target offset 0x%x ignored\n",
                          offset);
        }
    }
  else
    {
      info.printf("Reading unknown register @ 0x%x (%d)\n", reg, size);
    }

  return 0;
}

void Plic::write(unsigned reg, char size, l4_umword_t value, unsigned cpu_id)
{
  if (!check_access(reg, size, "write"))
    return;

  // TODO: More fine grained locking?
  std::lock_guard<std::mutex> lock(_lock);

  if (/*reg >= Priority_base && */ reg < Pending_base)
    {
      unsigned irq = (reg - Priority_base) / 4;
      if (check_irq(irq, "write priority register"))
        _priorities[irq] = value;
    }
  else if (reg >= Enable_base && reg < Context_base)
    {
      unsigned target_id = (reg - Enable_base) / Enable_per_hart;
      unsigned offset = (reg & Enable_mask) / 4;
      if (   check_target(target_id)
          && check_irq_range(offset, "write enable register"))
        get_target(target_id)->enable(offset, value, get_vcpu(cpu_id));
    }
  else if (reg >= Context_base)
    {
      unsigned target_id = (reg - Context_base) / Context_per_hart;
      unsigned offset = (reg & Context_mask);
      if (check_target(target_id))
        {
          if (offset == Context_threshold)
            get_target(target_id)->threshold(value, get_vcpu(cpu_id));
          else if (offset == Context_claim)
            get_target(target_id)->complete(value, get_vcpu(cpu_id));
          else
            warn.printf("attempt to write non existing target offset 0x%x ignored\n",
                        offset);
        }
    }
  else
    info.printf("Writing ignored 0x%lx @ 0x%x (%d)\n", value, reg, size);
}

void Plic::set(unsigned irq)
{
  assert(irq >= 1);
  trace.printf("Set irq %u\n", irq);
  if (_gateways[irq].set())
    {
      std::lock_guard<std::mutex> lock(_lock);
      set_irq(irq, get_vcpu(Vmm::vmm_current_cpu_id));
    }
}

void Plic::clear(unsigned)
{
  // Interrupt request cannot be retracted once forwarded to PLIC.
}

void Plic::bind_irq_src_handler(unsigned irq, Irq_src_handler *handler)
{
    assert(irq >= 1);
    assert(irq < Num_irqs);

    info.printf("Bind IRQ source handler %p to irq %u.\n", handler, irq);

    if (handler && _sources[irq])
      L4Re::throw_error(-L4_EEXIST, "IRQ already has IRQ source handler.");

    _sources[irq] = handler;
}

Irq_src_handler *Plic::get_irq_src_handler(unsigned irq) const
{
  return _sources[irq];
}

int Plic::dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const
{
  if (propsz < 1)
      return -L4_ERANGE;

    int irq = fdt32_to_cpu(prop[0]);

    if (read)
      *read = 1;

    return irq;
}

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    auto irq_cells = node.get_prop<fdt32_t>("#interrupt-cells", nullptr);
    if (!irq_cells || fdt32_to_cpu(*irq_cells) != 1)
      L4Re::throw_error(-L4_EINVAL, "Missing or invalid interrupt-cells property.");

    int size_interrupts;
    if (!node.get_prop<fdt32_t>("interrupts-extended", &size_interrupts))
      L4Re::throw_error(-L4_EINVAL, "Missing interrupts-extended property.");

    auto plic = Vdev::make_device<Plic>(node, size_interrupts / 2);
    devs->vmm()->register_mmio_device(plic, Vmm::Region_type::Virtual, node);
    devs->vmm()->set_plic(plic);
    return plic;
  }
};

static F f;
static Vdev::Device_type t = {"riscv,plic0", nullptr, &f};

}

} // namespace
