PKGDIR ?= ../..
L4DIR  ?= $(PKGDIR)/../..

include $(L4DIR)/mk/Makeconf

include $(PKGDIR)/server/src/Makefile.config
-include $(PKGDIR)/server/src/Makefile.config.local

SYSTEMS         = arm-l4f mips-l4f arm64-l4f amd64-l4f
TARGET          = uvmm
SRC_CC          = main.cc ram_ds.cc generic_guest.cc \
                  cpu_dev_array.cc generic_cpu_dev.cc \
                  ARCH-$(ARCH)/cpu_dev.cc \
                  device_factory.cc \
                  virtio_console.cc \
                  virtio_proxy.cc \
                  virtio_device_proxy.cc \
                  dev_sysctl.cc \
                  virt_bus.cc io_proxy.cc \
                  mmio_device.cc \
                  mmio_proxy.cc \
                  pm.cc vbus_event.cc vm.cc

SRC_CC-arm   = arm/gic.cc arm/guest_arm.cc arm/cpu_dev_arm.cc
SRC_CC-arm64 = arm/gic.cc arm/guest_arm.cc arm/cpu_dev_arm.cc
SRC_CC-mips  = ARCH-mips/gic.cc ARCH-mips/cpc.cc ARCH-mips/guest.cc
SRC_CC-amd64 = ARCH-amd64/guest.cc ARCH-amd64/mad.cc ARCH-amd64/pit.cc \
               ARCH-amd64/rtc.cc ARCH-amd64/virt_lapic.cc \
               ARCH-amd64/vcpu_ptr.cc ARCH-amd64/vm_state_vmx.cc \
               virtio_console_pci.cc virtio_proxy_pci.cc \
               pci_bus_bridge.cc

SRC_CC-$(CONFIG_VDEV_8250) += device/uart_8250.cc
SRC_CC-$(CONFIG_VDEV_PL011) += device/pl011.cc
SRC_CC-arm-$(CONFIG_VDEV_OPTEE) += device/optee.cc
SRC_CC-arm64-$(CONFIG_VDEV_OPTEE) += device/optee.cc

ifeq ($(ARCH),mips)
SRC_CC        += ARCH-$(ARCH)/guest_entry.cc
CXXFLAGS_guest_entry.cc = -msoft-float

LDFLAGS       += --no-warn-mismatch
endif

SRC_CC        += $(SRC_CC-$(ARCH))
SRC_CC        += $(SRC_CC-$(ARCH)-y)
SRC_CC        += $(SRC_CC-y)

REQUIRES_LIBS   = libstdc++ libio-vbus libfdt libpthread libvcpu

PRIVATE_INCDIR  = $(SRC_DIR)/../include $(SRC_DIR) $(SRC_DIR)/ARCH-$(ARCH)
PRIVATE_INCDIR-arm += $(SRC_DIR)/arm
PRIVATE_INCDIR-arm64 += $(SRC_DIR)/arm
PRIVATE_INCDIR += $(PRIVATE_INCDIR-$(ARCH))

include $(L4DIR)/mk/prog.mk

ifeq ($(ARCH),arm)
CARCHFLAGS := $(filter-out -march%,$(CARCHFLAGS)) -march=armv7-a
endif

# We do not want to have -fno-strict-aliasing
OPTS := $(OPTS_DEBUG) -O3
