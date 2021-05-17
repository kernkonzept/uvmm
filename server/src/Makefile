PKGDIR ?= ../..
L4DIR  ?= $(PKGDIR)/../..

include $(L4DIR)/mk/Makeconf

include $(PKGDIR)/server/src/Makefile.config
-include $(PKGDIR)/server/src/Makefile.config.local

$(GENERAL_D_LOC): $(PKGDIR)/server/src/Makefile.config \
                  $(wildcard $(PKGDIR)/server/src/Makefile.config.local)

SYSTEMS         = arm-l4f mips-l4f arm64-l4f amd64-l4f
TARGET          = uvmm

REQUIRES_LIBS   = libstdc++ libio-vbus libfdt libpthread
REQUIRES_LIBS-amd64 = acpica
REQUIRES_LIBS   += $(REQUIRES_LIBS-$(ARCH))

SRC_CC          = main.cc ram_ds.cc generic_guest.cc \
                  cpu_dev_array.cc generic_cpu_dev.cc \
                  ARCH-$(ARCH)/cpu_dev.cc \
                  host_dt.cc device_factory.cc \
                  virtio_console.cc \
                  virtio_proxy.cc \
                  virt_bus.cc io_proxy.cc \
                  mmio_device.cc \
                  pm.cc vbus_event.cc vm_memmap.cc vm_ram.cc vm.cc

ifneq ($(CONFIG_RELEASE_MODE),y)
SRC_CC-$(CONFIG_MONITOR)       += monitor/monitor.cc
SRC_CC-amd64-$(CONFIG_MONITOR) += debugger/generic_guest_debugger.cc
SRC_CC                         += debug.cc

CXXFLAGS-$(CONFIG_MONITOR)       += -DCONFIG_MONITOR
CXXFLAGS-amd64-$(CONFIG_MONITOR) += -DGUEST_DEBUGGER_SUPPORT
CXXFLAGS                         += $(CXXFLAGS-$(ARCH)-y)
endif
SRC_CC-arm-common = arm/gic.cc arm/gic-v2.cc arm/gic-v3.cc \
                    arm/guest_arm.cc arm/cpu_dev_arm.cc

SRC_CC-arm   = $(SRC_CC-arm-common)
SRC_CC-arm64 = $(SRC_CC-arm-common)
SRC_CC-mips  = ARCH-mips/gic.cc ARCH-mips/cpc.cc ARCH-mips/guest.cc
SRC_CC-amd64 = ARCH-amd64/guest.cc ARCH-amd64/mad.cc ARCH-amd64/pit.cc \
               ARCH-amd64/rtc.cc ARCH-amd64/virt_lapic.cc \
               ARCH-amd64/vcpu_ptr.cc ARCH-amd64/vm_state_vmx.cc \
               virtio_console_pci.cc virtio_proxy_pci.cc \
               device/pci_host_generic.cc ARCH-amd64/kvm_clock.cc \
               ARCH-amd64/legacy_pic.cc ARCH-amd64/acpi_platform.cc \
               ARCH-amd64/acpi_timer.cc

SRC_CC-arm-$(CONFIG_VDEV_PSCI)   += device/arm/psci.cc
SRC_CC-arm64-$(CONFIG_VDEV_PSCI) += device/arm/psci.cc

SRC_CC-amd64-$(CONFIG_VDEV_8250) += device/uart_8250_ioports.cc
SRC_CC-arm-$(CONFIG_VDEV_8250) += device/uart_8250.cc
SRC_CC-arm64-$(CONFIG_VDEV_8250) += device/uart_8250.cc
SRC_CC-$(CONFIG_VDEV_PL011) += device/pl011.cc
SRC_CC-arm-$(CONFIG_VDEV_OPTEE)   += device/optee.cc
SRC_CC-arm64-$(CONFIG_VDEV_OPTEE) += device/optee.cc
SRC_CC-$(CONFIG_VDEV_VIRTIO_POWER)   += device/virtio_input_power.cc
SRC_CC-$(CONFIG_VDEV_VIRQ) += device/virq.cc
SRC_CC-$(CONFIG_VDEV_MMIO_PROXY) += device/mmio_proxy.cc
SRC_CC-$(CONFIG_VDEV_SYSCTL) += device/sysctl.cc
SRC_CC-$(CONFIG_VDEV_DEVICE_PROXY) += device/virtio_device_proxy.cc
SRC_CC-arm-$(CONFIG_VDEV_DEVICE_PCI_HOST_ECAM_GENERIC) += device/pci_host_ecam_generic.cc
SRC_CC-arm64-$(CONFIG_VDEV_DEVICE_PCI_HOST_ECAM_GENERIC) += device/pci_host_ecam_generic.cc

ifeq ($(ARCH),mips)
SRC_CC        += ARCH-$(ARCH)/guest_entry.cc
CXXFLAGS_guest_entry.cc = -msoft-float

LDFLAGS       += --no-warn-mismatch
endif

SRC_CC        += $(SRC_CC-$(ARCH))
SRC_CC        += $(SRC_CC-$(ARCH)-y)

PRIVATE_INCDIR  = $(SRC_DIR)/../include $(SRC_DIR) $(SRC_DIR)/ARCH-$(ARCH)
PRIVATE_INCDIR-arm   += $(SRC_DIR)/arm $(SRC_DIR)/device/arm
PRIVATE_INCDIR-arm64 += $(SRC_DIR)/arm $(SRC_DIR)/device/arm
PRIVATE_INCDIR += $(PRIVATE_INCDIR-$(ARCH))
PRIVATE_INCDIR += $(SRC_DIR)/../../tools/uvmm_cli

include $(L4DIR)/mk/prog.mk

ifeq ($(ARCH),arm)
CARCHFLAGS := $(filter-out -march%,$(CARCHFLAGS)) -march=armv7-a
endif

# We do not want to have -fno-strict-aliasing
OPTS := $(OPTS_DEBUG) -O3
