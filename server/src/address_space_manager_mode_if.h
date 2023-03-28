/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once

namespace Vmm {

struct Address_space_manager_mode_if
{
  /// Is the operating mode `Iommu`?
  virtual bool is_iommu_mode() const = 0;
  /// Is the operating mode `Identity`?
  virtual bool is_identity_mode() const = 0;
  /// Is the operating mode `Dma_offset`?
  virtual bool is_dma_offset_mode() const = 0;
  /// Is the operating mode `Iommu_identity`?
  virtual bool is_iommu_identity_mode() const = 0;
  /// Is the operating mode any of the indentity modes?
  virtual bool is_any_identity_mode() const = 0;
  /// Is the operating mode `No_dma`?
  virtual bool is_no_dma_mode() const = 0;
};

}
