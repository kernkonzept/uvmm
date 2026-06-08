/*
 * Copyright (C) 2023-2024 Kernkonzept GmbH.
 * Author(s): Frank Mehnert <frank.mehnert@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

class Vcon_device
{
public:
  Vcon_device(L4::Cap<L4::Vcon> con)
  : _con(con)
  {
    /* Snapshot the console attributes before any derived UART backend
     * switches the vcon to raw mode. The vcon is often shared with the
     * launching shell, so the originals must be restored on teardown:
     * otherwise the shell is left without echo or newline translation after
     * the VM exits. */
    _con_attr_valid = l4_error(_con->get_attr(&_con_attr)) == L4_EOK;
  }

  ~Vcon_device()
  {
    if (_con_attr_valid)
      _con->set_attr(&_con_attr);

    if (_con_irq.is_valid())
      if (long err = l4_error(_con->unbind(0, _con_irq)) < 0)
          Dbg(Dbg::Irq, Dbg::Warn)
            .printf("Unbind notification IRQ from Vcon: %s\n.",
                    l4sys_errtostr(err));
  }

  void attach_con_irq(char const *devname)
  {
    l4_msgtag_t ret;
    L4Re::chkipc(ret = _con->bind(0, _con_irq),
                 "Bind notification IRQ to Vcon.");
    if (l4_error(ret) == -L4_ENOSYS)
      Err()
        .printf("Note that binding a %s console to the Moe Vcon interface would not work!\n",
                devname);
    L4Re::chksys(ret, "Bind notification IRQ to Vcon.");
  }

  template <typename DERIVED>
  void register_obj(L4::Registry_iface *registry)
  {
    _con_irq =
      L4Re::chkcap(registry->register_irq_obj(static_cast<DERIVED *>(this)),
                   "Register Vcon notification IRQ.");
  }

protected:
  L4::Cap<L4::Vcon> _con;

private:
  L4::Cap<L4::Irq> _con_irq;
  l4_vcon_attr_t _con_attr;
  bool _con_attr_valid = false;
};
