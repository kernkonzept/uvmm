PKGDIR          ?= ../..
L4DIR           ?= $(PKGDIR)/../..

INSTALL_TARGET   = $(patsubst $(SRC_DIR)/%.dts,%.dtb,$(wildcard $(SRC_DIR)/*.dts))

PRIVATE_INCDIR        = $(PKGDIR)/configs/dts/include $(PKGDIR)/configs/dts
REQUIRE_HOST_TOOLS    = dtc

include $(L4DIR)/mk/lib.mk

