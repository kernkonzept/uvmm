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
public:
  virtual ~Factory() = 0;
  virtual cxx::Ref_ptr<Device> create(Device_lookup const *devs,
                                      Dt_node const &node) = 0;


  static cxx::Ref_ptr<Device> create_vdev(Device_lookup const *devs,
                                          Dt_node const &node)
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
        auto const *t = Device_type::find(cid, cid_len, l4type, l4type_len);
        if (t)
          return t->f->create(devs, node);
      }

    return nullptr;
  }

  static cxx::Ref_ptr<Device> create_dev(Device_lookup const *devs,
                                         Dt_node const &node)
  {
    if (auto r = create_vdev(devs, node))
      return r;

    if (pass_thru)
      return pass_thru->create(devs, node);

    return nullptr;
  }

  static Factory *pass_thru;
};

inline Factory::~Factory() {}

}
