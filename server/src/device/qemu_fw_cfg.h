/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020-2022 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *            Jan Klötzke <jan.kloetzke@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 */

#pragma once

#include "vm.h"

#include <l4/re/dataspace>
#include <l4/cxx/hlist>

/**
 * Qemu standardized interface to supply information from VMM to guest.
 */
namespace Qemu_fw_cfg {

struct Provider : public cxx::H_list_item_t<Provider>
{
  Provider()
  { types.push_front(this); }

  virtual void init(Vdev::Device_lookup * /*devs*/, Vdev::Dt_node const & /*node*/) {};
  virtual void init_late(Vdev::Device_lookup * /*devs*/) {};

  static cxx::H_list_t<Provider> types;
};

enum { File_name_size = 56 };

void set_item(l4_uint16_t selector, std::string const &blob);
void set_item(l4_uint16_t selector, L4::Cap<L4Re::Dataspace> ds,
              size_t offset = 0, size_t size = -1);
void set_item(l4_uint16_t selector, void const *data, size_t length);
void set_item_u16le(l4_uint16_t selector, l4_uint16_t data);
void set_item_u32le(l4_uint16_t selector, l4_uint32_t data);

void put_file(char const *fn, char const *blob, size_t size);
template<typename T>
void put_file(char const *fn, T &blob)
{ put_file(fn, blob.data(), blob.size()); }

};
