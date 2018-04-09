#pragma once

#include "device.h"
#include "device_tree.h"

#include <l4/cxx/hlist>
#include <l4/cxx/ref_ptr>

namespace Vdev {

class Factory;

struct Device_type : public cxx::H_list_item_t<Device_type>

{
  char const *cid;
  char const *l4type;
  Factory *f;

  Device_type(char const *cid, char const *l4type, Factory *f)
  : cid(cid), l4type(l4type), f(f)
  {
    types.push_front(this);
  }

  static cxx::H_list_t<Device_type> types;
  static Device_type const *find(char const *cid, int cid_len,
                                 char const *l4type, int l4type_len)
  {
    if (l4type)
      l4type_len = strnlen(l4type, l4type_len);

    for (auto const *t: types)
      {
        if (strlen(t->cid) != (unsigned)cid_len)
          continue;

        if (strncmp(cid, t->cid, cid_len) == 0)
          {
            if (!t->l4type)
              return t;

            if (strlen(t->l4type) != (unsigned)l4type_len)
              continue;

            if (strncmp(l4type, t->l4type, l4type_len) == 0)
              return t;
          }
      }

    return nullptr;
  }
};


class Factory
{
  /**
   * Lookup factory for device node.
   *
   * \param node  The device node a Device a factory is needed for
   *
   * \retval  Pointer to factory, if factory present
   * \retval  nullptr, if no factory found
   */
  static Factory *find_factory(Dt_node const &node);

public:
  /**
   * Create a Device instance for the interrupt parent of a node
   *
   * \param devs   Pointer to device repository
   * \param node   The node we are creating an interrupt parent for
   * \param depth  A counter describing the invocation depth, default 0
   *
   * \retval true   Interrupt parent is available
   * \retval false  Interrupt parent is not available
   *
   * Creates a Device instance for the interrupt parent if there is one.
   */
  static bool create_irq_parent(Device_lookup *devs, Vdev::Dt_node const &node,
                                int depth = 0);

  /**
   * Does the node represent a virtual device?
   *
   * \retval true   The node describes a virtual device.
   * \retval false  The node describes a non virtual device
   *
   * is_dev() checks whether there is a factory for the device node
   * present and returns true if that is the case.
   */
  static bool is_vdev(Dt_node const &node)
  { return find_factory(node) != nullptr; }

  /**
   * Create a Device instance for the device described by node.
   *
   * \param devs  Pointer to device repository
   * \param node  The device node a Device instance shall be created for
   *
   * \retval      Pointer to the created Device
   * \retval      nullpointer, if device creation failed
   *
   * Implemented by each derived factory.
   */
  virtual cxx::Ref_ptr<Device> create(Device_lookup *devs,
                                      Dt_node const &node) = 0;

  virtual ~Factory() = 0;

  /**
   * Create a Device instance for a device.
   *
   * \param devs   Pointer to device repository
   * \param node   The device node a Device instance shall be created for
   *
   * \retval false  Device creation failed
   * \retval true   Device was successfully created and added to the device list
   *
   * Creates a device instance for a device node by invoking the responsible
   * factory and adds it to the device repository.
   */
  static cxx::Ref_ptr<Device> create_dev(Device_lookup *devs,
                                         Dt_node const &node);

protected:
  static Factory *pass_thru;
};

inline Factory::~Factory() {}

}
