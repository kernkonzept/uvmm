#include "device_factory.h"
#include "guest.h"
#include "irq.h"
#include "irq_dt.h"
#include "mmio_device.h"

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
    auto cap = Vdev::get_cap<L4::Irq>(node, "l4vmm,virqcap");
    if (!cap)
      return nullptr;

    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) < 0)
      return nullptr;

    if (!it.ic_is_virt())
      L4Re::chksys(-L4_EINVAL, "Irq_rcv requires a virtual interrupt controller");

    auto c = make_device<Irq_rcv>(it.ic().get(), it.irq());
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
    auto cap = Vdev::get_cap<L4::Irq>(node, "l4vmm,virqcap");
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
