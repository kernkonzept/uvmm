PKGDIR ?= ../..
L4DIR  ?= $(PKGDIR)/../..

include $(L4DIR)/mk/Makeconf

SYSTEMS         = arm-l4f mips-l4f arm64-l4f amd64-l4f
TARGET          = uvmm
VARIANTS        = nofpu

REQUIRES_LIBS   = libstdc++ libio-vbus libfdt libpthread
REQUIRES_LIBS_amd64-l4f = acpica

SRC_CC          = main.cc ram_ds.cc generic_guest.cc \
                  cpu_dev_array.cc generic_cpu_dev.cc \
                  ARCH-$(ARCH)/cpu_dev.cc \
                  host_dt.cc device_factory.cc \
                  virt_bus.cc io_proxy.cc \
                  mmio_device.cc \
                  pm.cc vbus_event.cc vm_memmap.cc vm_ram.cc vm.cc \
                  address_space_manager.cc \
                  device/rtc-hub.cc pm_device_if.cc

SRC_CC-$(CONFIG_UVMM_PCI_SUPPORT)       += pci_device.cc virt_pci_device.cc

SRC_CC-$(CONFIG_RELEASE_MODE)y          += debug.cc
SRC_CC-$(CONFIG_UVMM_MONITOR)           += monitor/monitor.cc
SRC_CC_amd64-l4f-$(CONFIG_UVMM_MONITOR) += debugger/generic_guest_debugger.cc

SRC_CC_arm-common-$(CONFIG_UVMM_VDEV_GIC_V2) += arm/gic-v2.cc
SRC_CC_arm-common-$(CONFIG_UVMM_VDEV_GIC_V3) += arm/gic-v3.cc
SRC_CC_arm-common-$(CONFIG_UVMM_VDEV_GIC_ITS) += arm/gic-v3_its.cc
SRC_CC_arm-common-$(CONFIG_UVMM_FAULT_INJECT)  += ARCH-$(ARCH)/guest_arm_exc.cc
SRC_CC_arm-common-$(CONFIG_UVMM_FAULT_INJECT)y += arm/guest_arm_noexc.cc

SRC_CC_arm-common = arm/gic_cpu.cc arm/gic_iface.cc \
                    arm/guest_arm.cc arm/cpu_dev_arm.cc \
                    io_port_handler_noop.cc ARCH-$(ARCH)/guest_subarch.cc

SRC_CC_arm-l4f   = $(SRC_CC_arm-common) $(SRC_CC_arm-common-y)
SRC_CC_arm64-l4f = $(SRC_CC_arm-common) $(SRC_CC_arm-common-y)
SRC_CC_mips-l4f  = ARCH-mips/gic.cc ARCH-mips/cpc.cc ARCH-mips/guest.cc \
                   io_port_handler_noop.cc
SRC_CC_amd64-l4f = ARCH-amd64/guest.cc ARCH-amd64/mad.cc ARCH-amd64/pit.cc \
                   ARCH-amd64/rtc.cc ARCH-amd64/virt_lapic.cc \
                   ARCH-amd64/ioapic.cc \
                   ARCH-amd64/vcpu_ptr.cc \
                   device/pci_host_bridge.cc device/pci_host_generic.cc \
                   ARCH-amd64/kvm_clock.cc \
                   ARCH-amd64/legacy_pic.cc ARCH-amd64/acpi_platform.cc \
                   ARCH-amd64/acpi_timer.cc ARCH-amd64/zeropage.cc \
                   ARCH-amd64/io_port_handler_l4util.cc \
                   ARCH-amd64/vm_state_vmx.cc ARCH-amd64/vm_state_svm.cc \
                   ARCH-amd64/guest-vmx.cc ARCH-amd64/guest-svm.cc \
                   ARCH-amd64/event_recorder.cc ARCH-amd64/event_record.cc

SRC_CC_amd64-l4f-$(CONFIG_UVMM_VDEV_DEVICE_FRAMEBUFFER) += ARCH-amd64/framebuffer.cc
SRC_CC-$(CONFIG_UVMM_VDEV_ISA_DEBUG_PORT) += ARCH-amd64/isa_debugport.cc
SRC_CC_amd64-l4f-$(CONFIG_UVMM_VDEV_VIRTIO_CONSOLE) += virtio_console_pci.cc
SRC_CC_amd64-l4f-$(CONFIG_UVMM_VDEV_VIRTIO_PROXY) += virtio_proxy_pci.cc

SRC_CC_arm-l4f-$(CONFIG_UVMM_VDEV_PSCI)   += device/arm/psci.cc
SRC_CC_arm64-l4f-$(CONFIG_UVMM_VDEV_PSCI) += device/arm/psci.cc

SRC_CC-$(CONFIG_UVMM_VDEV_8250)  += device/uart_8250.cc
SRC_CC-$(CONFIG_UVMM_VDEV_VIRTIO_CONSOLE) += virtio_console.cc
SRC_CC-$(CONFIG_UVMM_VDEV_VIRTIO_PROXY) += virtio_proxy.cc
SRC_CC-$(CONFIG_UVMM_VDEV_PL011) += device/pl011.cc
SRC_CC-$(CONFIG_UVMM_VDEV_OPTEE) += device/optee.cc
SRC_CC-$(CONFIG_UVMM_VDEV_PL031) += device/arm/pl031.cc
SRC_CC-$(CONFIG_UVMM_VDEV_VIRTIO_INPUT)   += device/virtio_input_event.cc
SRC_CC-$(CONFIG_UVMM_VDEV_VIRTIO_POWER)   += device/virtio_input_power.cc
SRC_CC_amd64-l4f-$(CONFIG_UVMM_VDEV_VIRTIO_POWER) += device/virtio_input_power_pci.cc
SRC_CC-$(CONFIG_UVMM_VDEV_VIRQ) += device/virq.cc
SRC_CC-$(CONFIG_UVMM_VDEV_MMIO_PROXY) += device/mmio_proxy.cc
SRC_CC-$(CONFIG_UVMM_VDEV_SYSCTL) += device/sysctl.cc
SRC_CC-$(CONFIG_UVMM_VDEV_DEVICE_PROXY) += device/virtio_device_mem_pool.cc \
                                           device/virtio_device_proxy.cc
SRC_CC_amd64-l4f-$(CONFIG_UVMM_VDEV_DEVICE_PROXY) += device/virtio_device_proxy_pci.cc
SRC_CC-$(CONFIG_UVMM_VDEV_DEVICE_PCI_HOST_ECAM_GENERIC) += device/pci_host_bridge.cc \
                                                           device/pci_host_ecam_generic.cc
SRC_CC-$(CONFIG_UVMM_VDEV_CFI_FLASH) +=  device/cfi.cc
SRC_CC-$(CONFIG_UVMM_EXTERNAL_RTC) += device/l4rtc.cc
SRC_CC-$(CONFIG_UVMM_VDEV_DEVICE_FRAMEBUFFER) += device/framebuffer.cc
SRC_CC-$(CONFIG_UVMM_VDEV_ROM) += device/rom.cc

SRC_CC-$(CONFIG_UVMM_QEMU_FW_IF) += device/qemu_fw_cfg.cc
SRC_CC_amd64-l4f-$(CONFIG_UVMM_QEMU_FW_IF) += \
	ARCH-amd64/qemu_fw_cfg_acpi.cc \
	ARCH-amd64/qemu_fw_cfg_boot.cc

SRC_CC += binary_loader.cc
SRC_CC-$(CONFIG_UVMM_LOADER_RAW) += binary_loader_raw.cc
SRC_CC-$(CONFIG_UVMM_LOADER_ELF) += binary_loader_elf.cc
SRC_CC-$(CONFIG_UVMM_LOADER_PE)  += binary_loader_pe.cc
SRC_CC-$(CONFIG_UVMM_LOADER_ROM) += binary_loader_rom.cc
SRC_CC_amd64-l4f-$(CONFIG_UVMM_LOADER_LINUX)  += ARCH-amd64/binary_loader_linux.cc
SRC_CC_arm-common-$(CONFIG_UVMM_LOADER_LINUX) += arm/binary_loader_linux.cc
SRC_CC-$(CONFIG_UVMM_LOADER_GZIP) += arm/binary_loader_linux_compressed.cc
REQUIRES_LIBS-$(CONFIG_UVMM_LOADER_GZIP) += zlib

include $(wildcard $(PKGDIR)/server/src/Makefile.devs.*)

ifeq ($(ARCH),mips)
SRC_CC        += ARCH-$(ARCH)/guest_entry.cc
CXXFLAGS_guest_entry.cc = -msoft-float

LDFLAGS       += --no-warn-mismatch
endif

PRIVATE_INCDIR  = $(SRC_DIR)/../include $(SRC_DIR) $(SRC_DIR)/ARCH-$(ARCH)
PRIVATE_INCDIR_arm-l4f   += $(SRC_DIR)/arm $(SRC_DIR)/device/arm
PRIVATE_INCDIR_arm64-l4f += $(SRC_DIR)/arm $(SRC_DIR)/device/arm
PRIVATE_INCDIR += $(SRC_DIR)/../../tools/uvmm_cli

include $(L4DIR)/mk/prog.mk

# Force armv7+ve on pre-armv8 AArch32 build trees.
ifeq ($(ARCH),arm)
ifeq ($(CONFIG_CPU_ARMV8PLUS),)
CARCHFLAGS := $(filter-out -march%,$(CARCHFLAGS)) $(GCCARMV7VEFPOPT_arm)
endif
endif

# We do not want to have -fno-strict-aliasing
OPTS := $(OPTS_DEBUG) -O3
