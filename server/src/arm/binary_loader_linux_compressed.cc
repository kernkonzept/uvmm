/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 */

#include <l4/sys/factory>
#include <zlib.h>

#include "binary_loader_linux.h"

namespace Boot {

class Linux_zip_loader : public Linux_loader
{
public:
  int load(char const *bin, std::shared_ptr<Binary_ds> image,
           Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list,
           l4_addr_t *entry) override
  {
    trace().printf("Checking for compressed Linux image...\n");

    if (!image->is_valid())
      return -L4_EINVAL;

    unsigned char const *h =
      static_cast<unsigned char const *>(image->get_header());
    if (h[0] == 0x1f && h[1] == 0x8b && h[2] == 0x08)
      {
        const L4Re::Env *e = L4Re::Env::env();
        L4Re::Rm::Unique_region<Bytef *> imager_src;
        L4Re::Rm::Unique_region<Byte *> imager_dst;
        size_t compr_sz = image->size();

        L4Re::chksys(e->rm()->attach(&imager_src, compr_sz,
                                     L4Re::Rm::F::Search_addr | L4Re::Rm::F::R,
                                     L4::Ipc::make_cap_rw(image->ds())),
                     "Attach compressed file.");

        uint32_t uncompr_sz = *(uint32_t *)&imager_src.get()[compr_sz - 4];

        info().printf("Detected gzip compressed image: uncompressing (%zd -> %u)\n",
                      compr_sz, uncompr_sz);

        L4::Cap<L4Re::Dataspace> f =
          L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>(),
                       "Allocate DS cap for uncompressed memory.");

        L4Re::chksys(e->mem_alloc()->alloc(uncompr_sz, f),
                     "Allocate memory in dataspace.");

        L4Re::chksys(e->rm()->attach(&imager_dst, uncompr_sz,
                                     L4Re::Rm::F::Search_addr | L4Re::Rm::F::RW,
                                     L4::Ipc::make_cap_rw(f)),
                     "Attach DS for uncompressed data.");

        z_stream strm = {};
        strm.next_in  = imager_src.get();
        strm.avail_in = compr_sz;

        int err = inflateInit2(&strm, 47);
        if (err == Z_OK)
          {
            strm.next_out = imager_dst.get();
            strm.avail_out = uncompr_sz;
            err = inflate(&strm, Z_NO_FLUSH);

            // Should finish in one round
            if (err != Z_STREAM_END)
              {
                Err().printf("zlib decompression error: %s\n", strm.msg);
                L4Re::throw_error(-L4_EINVAL);
              }
            else
              image.reset(new Boot::Binary_ds(f));
          }
        else
          {
            Err().printf("zlib init error: %d\n", err);
            L4Re::throw_error(-L4_EINVAL);
          }
      }

    return Linux_loader::load(bin, image, ram, free_list, entry);
  }
};

static Linux_zip_loader f __attribute__((init_priority(Boot::LinuxGzip)));

}
