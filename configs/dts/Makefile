PKGDIR          ?= ../..
L4DIR           ?= $(PKGDIR)/../..

include $(L4DIR)/mk/Makeconf

INSTALL_TARGET   = $(patsubst $(SRC_DIR)/%.dts,%.dtb,$(wildcard $(SRC_DIR)/*.dts))

PRIVATE_INCDIR        = $(PKGDIR)/configs/dts/include $(PKGDIR)/configs/dts
REQUIRE_HOST_TOOLS    = dtc
DTC_FLAGS            := $(call checkdtc,-Wno-unit_address_vs_reg)

include $(L4DIR)/mk/lib.mk

