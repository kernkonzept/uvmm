PKGDIR          ?= ../..
L4DIR           ?= $(PKGDIR)/../..

include $(L4DIR)/mk/Makeconf

ASSET_TYPE       = dtb
SRC_DTS          = $(subst $(SRC_DIR)/,,$(wildcard $(SRC_DIR)/*.dts))
PRIVATE_INCDIR   = $(PKGDIR)/configs/dts/include $(PKGDIR)/configs/dts
DTC_FLAGS       := $(call checkdtc,-Wno-unit_address_vs_reg) \
                   $(call checkdtc,-Wno-simple_bus_reg) \
                   $(call checkdtc,-Wno-spi_bus_bridge) \
                   $(call checkdtc,-Wno-alias_paths) \
                   $(call checkdtc,-@)

clean::
	$(VERBOSE)$(RM) $(wildcard *.dtb)

include $(L4DIR)/mk/assets.mk
