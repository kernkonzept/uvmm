#include "device_factory.h"
#include "guest.h"
#include "irq.h"
#include "mmio_device.h"

static L4::Cap<L4::Irq>
get_irq_cap(Vdev::Dt_node const &node)
{
  int cap_name_len;
  char const *cap_name = node.get_prop<char>("l4vmm,virqcap", &cap_name_len);
  if (!cap_name)
    {
      Dbg(Dbg::Dev, Dbg::Warn, "virq")
        .printf("%s: 'l4vmm,virqcap' property missing.\n", node.get_name());
      return L4::Cap<L4::Irq>();
    }

  cap_name_len = strnlen(cap_name, cap_name_len);

  auto cap = L4Re::Env::env()->get_cap<L4::Irq>(cap_name, cap_name_len);
  if (!cap)
    {
      Dbg(Dbg::Dev, Dbg::Warn, "virq")
        .printf("%s: 'l4vmm,virq' property: capability %.*s is invalid.\n",
                node.get_name(), cap_name_len, cap_name);
      return L4::Cap<L4::Irq>();
    }

  return cap;
}

namespace {

using namespace Vdev;

class Irq_rcv
: public L4::Irqep_t<Irq_rcv>,
  public Device
{
public:
  Irq_rcv(Gic::Ic *ic, unsigned irq) : _sink(ic, irq) {}

  void handle_irq()
  { _sink.inject(); }

private:
  // Use an edge sink since we do not need any EOI handling and do not want to
  // explicitly ACK interrupts on the Irq_*_sink
  Vmm::Irq_edge_sink _sink;
};


struct F_rcv : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    auto cap = get_irq_cap(node);
    if (!cap)
      return nullptr;

    cxx::Ref_ptr<Gic::Ic> ic = devs->get_or_create_ic_dev(node, false);
    if (!ic)
      return nullptr;

    auto c = make_device<Irq_rcv>(ic.get(), ic->dt_get_interrupt(node, 0));
    L4Re::chkcap(devs->vmm()->registry()->register_obj(c.get(), cap));
    return c;
  }
};

static F_rcv f_rcv;
static Device_type t_rcv = { "l4vmm,virq-rcv", nullptr, &f_rcv };

class Irq_snd : public Device, public Vmm::Mmio_device_t<Irq_snd>
{
public:
  explicit Irq_snd(L4::Cap<L4::Irq> irq) : _irq(irq) {}

  void write(unsigned /*reg*/, char /*size*/, l4_uint64_t /*value*/, unsigned)
  {
    /* address does no matter */
    _irq->trigger();
  }

  l4_uint32_t read(unsigned /*reg*/, char /*size*/, unsigned /*cpu_id*/)
  {
    return 0;
  }

private:
  L4::Cap<L4::Irq> _irq;
};

struct F_snd : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    auto cap = get_irq_cap(node);
    if (!cap)
      return nullptr;

    auto c = make_device<Irq_snd>(cap);
    devs->vmm()->register_mmio_device(c, node);
    return c;
  }
};

static F_snd f_snd;
static Device_type t_snd = { "l4vmm,virq-snd", nullptr, &f_snd };
}
