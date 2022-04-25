PKGDIR          ?= ../..
L4DIR           ?= $(PKGDIR)/../..

include $(L4DIR)/mk/Makeconf

INSTALL_TARGET   = $(patsubst $(SRC_DIR)/%.dts,%.dtb,$(wildcard $(SRC_DIR)/*.dts))

PRIVATE_INCDIR        = $(PKGDIR)/configs/dts/include $(PKGDIR)/configs/dts
REQUIRE_HOST_TOOLS    = dtc
DTC_FLAGS            := $(call checkdtc,-Wno-unit_address_vs_reg) \
                        $(call checkdtc,-Wno-simple_bus_reg) \
                        $(call checkdtc,-Wno-spi_bus_bridge) \
                        $(call checkdtc,-Wno-alias_paths) \
                        $(call checkdtc,-@)

include $(L4DIR)/mk/lib.mk

clean::
	$(VERBOSE)$(RM) $(wildcard *.dtb)
