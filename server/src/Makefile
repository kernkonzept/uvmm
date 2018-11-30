PKGDIR ?= ../..
L4DIR  ?= $(PKGDIR)/../..

include $(L4DIR)/mk/Makeconf

vpath %.cc $(SRC_DIR)/ARCH-$(ARCH)

SYSTEMS         = arm-l4f mips-l4f
TARGET          = uvmm
SRC_CC          = gic.cc main.cc ram_ds.cc generic_guest.cc guest.cc \
                  device_factory.cc \
                  virtio_console.cc \
                  virtio_proxy.cc \
                  dev_sysctl.cc \
                  virt_bus.cc io_proxy.cc

REQUIRES_LIBS   = libstdc++ libio-vbus libfdt
SRC_CC_IS_CXX11 = y
CXXFLAGS       += -O3
PRIVATE_INCDIR  = $(SRC_DIR) $(SRC_DIR)/ARCH-$(ARCH)

include $(L4DIR)/mk/prog.mk

ifeq ($(ARCH),arm)
CXXFLAGS := $(filter-out -march%,$(CXXFLAGS)) -mcpu=cortex-a15
endif

CXXFLAGS := $(filter-out -fno-strict-aliasing,$(CXXFLAGS))
