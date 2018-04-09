#include "device_factory.h"
#include "virt_bus.h"

namespace Vdev {

cxx::H_list_t<Device_type> Device_type::types(true);
Factory *Factory::pass_thru;

Factory *
Factory::find_factory(Dt_node const &node)
{
  char const *const comp = "compatible";
  int count = node.stringlist_count(comp);
  if (count <= 0)
    return nullptr;

  int l4type_len;
  char const *l4type = node.get_prop<char>("l4vmm,vdev", &l4type_len);

  for (int i = 0; i < count; ++i)
    {
      int cid_len;
      char const *cid = node.stringlist_get(comp, i, &cid_len);
      auto const * factory = Device_type::find(cid, cid_len, l4type, l4type_len);
      if (factory)
        return factory->f;
    }
  return nullptr;
}

bool
Factory::create_irq_parent(Device_lookup *devs, Vdev::Dt_node const &node,
                           int depth)
{
  Vdev::Dt_node parent = node.find_irq_parent();

  // Is there an IRQ parent at all?
  if (!parent.is_valid())
    return true;

  // Is the device already present?
  if (devs->device_from_node(parent))
    return true;

  // Check for recursion caused by invalid device trees. We should not
  // visit more than 10 nodes while creating IRQ parents.
  if (depth > 10)
    {
      Err().printf("Recursion detected at node %s while creating interrupt"
                   " parents.\n", node.get_name());
      return false;
    }

  // Create IRQ parent regardless of presence of interrupts; create_dev() will
  // check for the IRQ parent again, but will return early since the IRQ parent
  // is already present at that point
  if (!create_irq_parent(devs, parent, depth + 1))
    return false;

  Dbg(Dbg::Dev, Dbg::Trace, "factory")
    .printf("\t%s:%d: Visiting node '%s' - '%s'\n", __func__, depth,
            node.get_name(), parent.get_name());

  bool res = (bool)create_dev(devs, parent);

  Dbg(Dbg::Dev, res ? Dbg::Trace : Dbg::Info, "factory")
    .printf("%s interrupt parent %s for %s\n",
            res ? "Successfully created" : "Failed to create",
            parent.get_name(), node.get_name());
  return res;
}

cxx::Ref_ptr<Device>
Factory::create_dev(Device_lookup *devs, Dt_node const &node)
{
  if (cxx::Ref_ptr<Device> d = devs->device_from_node(node))
    return d;

  Factory *f = find_factory(node);
  if (!f)
    f = pass_thru;

  if (!f)
    return nullptr;

  cxx::Ref_ptr<Device> dev = f->create(devs, node);
  if (!dev)
    return nullptr;

  devs->add_device(node, dev);
  return dev;
}
}
