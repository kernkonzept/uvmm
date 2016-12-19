PKGDIR ?= ../..
L4DIR  ?= $(PKGDIR)/../..

include $(L4DIR)/mk/Makeconf

SYSTEMS         = arm-l4f mips-l4f
TARGET          = uvmm
SRC_CC          = main.cc ram_ds.cc generic_guest.cc \
                  ARCH-$(ARCH)/gic.cc \
                  ARCH-$(ARCH)/guest.cc \
                  ARCH-$(ARCH)/vcpu_array.cc \
                  device_factory.cc \
                  virtio_console.cc \
                  virtio_proxy.cc \
                  dev_sysctl.cc \
                  virt_bus.cc io_proxy.cc

ifeq ($(ARCH),mips)
SRC_CC        += ARCH-$(ARCH)/guest_entry.cc
CXXFLAGS_guest_entry.cc = -msoft-float

LDFLAGS       += --no-warn-mismatch
endif

REQUIRES_LIBS   = libstdc++ libio-vbus libfdt
PRIVATE_INCDIR  = $(SRC_DIR)/../include $(SRC_DIR) $(SRC_DIR)/ARCH-$(ARCH)

include $(L4DIR)/mk/prog.mk

ifeq ($(ARCH),arm)
CARCHFLAGS := $(filter-out -march%,$(CARCHFLAGS)) -march=armv7-a
endif

# We do not want to have -fno-strict-aliasing
OPTS := $(OPTS_DEBUG) -O3
