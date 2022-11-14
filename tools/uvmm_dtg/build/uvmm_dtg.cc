/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include <vector>
#include <string>

#include "opts.h"
#include "device.h"
#include "const.h"
#include "output_txt.h"
#include "output_bin.h"
#include "writer.h"

#include "ic.h"

#include "config.h"

/* Ned usage:
 *
 * -- Create DS holding device tree
 * local dt = L4.Env.user_factory:create(L4.Proto.Dataspace, 4 * 1024):m("rw");
 *
 * -- Start the generator
 * L4.default_loader:start(
 * {
 *   caps = { dt = dt },
 * }, "rom/uvmm_dtg dt"):wait();
 *
 * -- Start uvmm
 * vmm.start_vm
 * {
 *  ...
 *  ext_caps = { dt = dt },
 *  fdt = "dt",
 *  ...
 * }
 *
 */

static int run(int argc, char **argv)
{
  Options options("uvmm_dtg", "a uvmm device tree generator");
  options.add_option("-h", "show usage", make_parser<Help_parser>(&options));
  options.add_option("--arch", "selects target architecture",
                     make_parser<Selector_parser, Arch>(
                       {{"x86", X86_32()}, {"x86_64", X86_64()},
                        {"arm32", Arm32()}, {"arm64", Arm64()},
                        {"mips32", Mips32()}, {"mips64", Mips64()}}),
                     make_default<Arch>(Default_arch));
  options.add_option("--format", "selects the output format",
                     make_parser<Selector_parser, OutFormat>(
                       {{"txt", Txt}, {"bin", Bin}}),
                     make_default<OutFormat>(Default_format));
  options.add_option("--mem-base", "start of memory distribution",
                     make_parser<UInt64_parser>(),
                     make_default<uint64_t>(0x7FFFFFFF));
  auto dlp = make_parser<Device_list_parser>();
  options.add_option("--device", "device configuration", dlp, Option::Multiple);

  // Convert the args array to an std::vector
  std::vector<std::string> vec;
  vec.reserve(argc - 1);
  std::copy(&argv[1], &argv[argc], std::back_inserter(vec));

  // Check if help is requested
  auto result = options.parse_one("-h", &vec, vec.begin());
  if (result.is_error())
    return result.print_error();

  // Now figure out the target arch, so that only devices available for this
  // arch are provided
  result = options.parse_one("--arch", &vec, vec.begin());
  if (result.is_error())
    return result.print_error();
  Arch arch = result.as<::Arch>("--arch");
  // Prepare the factory according to the arch. Also add relevant options for
  // this arch to the device parser before doing the actual parsing.
  Factory::prepare(arch, dlp);

  // Now parse all remaining options
  result = options.parse(&vec, vec.begin());
  if (result.is_error())
    return result.print_error();

  // Is there exactly one output filename provided?
  std::string file = "--";
  if (vec.size() > 0)
    {
      if (vec.size() > 1)
        {
          std::cerr << "Error: too many output filenames\n";
          return 1;
        }
      file = *vec.begin();
      if (file != "--" && file.rfind("-", 0) == 0)
        {
          std::cerr << "Error: unknown option " << file << "\n";
          return 1;
        }
    }

  // Create all required (including dependencies/defaults) devices
  Factory::create_all_devices();

  // We are ready to build up the device tree
  Region_mapper rm(result.as<uint64_t>("-mem-base"),
                   arch.is64bit ? std::numeric_limits<uint64_t>::max() :
                                  std::numeric_limits<uint32_t>::max());
  Tree t(arch, &rm);
  Factory::build_tree(&t);
  t.finalize();

  // Choose the output format and write to the given file
  if (result.as<OutFormat>("-format") == Txt)
    {
      OutputTxt s;
      s.build(&t);
      Writer::out(file, s.addr(), s.size());
    }
  else
    {
      OutputBin b;
      b.build(&t);
      Writer::out(file, b.addr(), b.size());
    }

  return 0;
}

int main(int argc, char **argv)
{
  try
  {
    return run(argc, argv);
  }
  catch(const Exception &e)
  {
    std::cerr << "Error: " << e.error << std::endl;
  }
  catch(...)
  {
    std::cerr << "Error: unknown\n";
  }
  return 1;
}
