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
  static Device_type const *find(char const *cid, l4_size_t cid_len,
                                 char const *l4type, l4_size_t l4type_len)
  {
    if (l4type)
      l4type_len = strnlen(l4type, l4type_len);

    for (auto const *t: types)
      {
        if (strlen(t->cid) != cid_len)
          continue;

        if (memcmp(cid, t->cid, cid_len) == 0)
          {
            if (!t->l4type)
              return t;

            if (!l4type || (strlen(t->l4type) != l4type_len))
              continue;

            if (memcmp(l4type, t->l4type, l4type_len) == 0)
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

L4::Cap<void>
_get_cap(Vdev::Dt_node const &node, char const *prop, L4::Cap<void> def_cap);

/**
 * Get capability specified by property
 *
 * \param  node    The node containing the property.
 * \param  prop    Pointer to the name of the property containing the name
 *                 of the capability.
 * \param  def_cap Default capability returned if no property is found.
 *
 * \return  On success a valid capability is returned. If the property is
 *          missing the default capability is returned. Otherwise an invalid
 *          capability is returned.
 *
 * This functions tries to lookup a capability name in the device tree and then
 * tries to get the referenced capability. It either returns
 * * a valid capability on success
 * * the default capability if the property is missing
 * * an invalid capability.
 * The function also generates warnings if the property is missing and no valid
 * default capability was passed or the referenced capability is invalid */
template <typename T>
L4::Cap<T> get_cap(Vdev::Dt_node const &node, char const *prop,
                   L4::Cap<void> def_cap = L4::Cap<void>())
{ return L4::cap_cast<T>(_get_cap(node, prop, def_cap)); }

}
