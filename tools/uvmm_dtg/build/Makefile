PKGDIR ?= ../../..
L4DIR  ?= $(PKGDIR)/../..

SYSTEMS = arm-l4f mips-l4f arm64-l4f amd64-l4f
TARGET = uvmm_dtg

SRC_CC = uvmm_dtg.cc device.cc tree.cc ic.cc \
	devices/memory.cc \
	devices/cpu.cc \
	devices/sysclock.cc \
	devices/gic.cc \
	devices/pic.cc \
	devices/ioapic.cc \
	devices/msi_control.cc \
	devices/pit.cc \
	devices/arm_psci.cc \
	devices/arm_timer.cc \
	devices/pl011.cc \
	devices/ns8250.cc \
	devices/acpi_platform.cc \
	devices/acpi_timer.cc \
	devices/pl031.cc \
	devices/rtc.cc \
	devices/stats.cc \
	devices/kvm_clock.cc \
	devices/virtio_console.cc \
	devices/virtio_input_power.cc \
	devices/virtio_input_power_pci.cc \
	devices/virtio_proxy.cc \
	devices/virtio_device_proxy.cc \
	devices/pci_host_ecam.cc \
	devices/pci_bridge.cc \
	devices/virtio_console_pci.cc \
	devices/virtio_proxy_pci.cc \
	devices/mmio_proxy.cc \
	devices/virq_rcv.cc \
	devices/virq_snd.cc \
	devices/syscon.cc \
	devices/cfi.cc \
	devices/optee.cc \
	devices/eisa.cc \
	devices/qemu_fw_if.cc \
	devices/isa-debugport.cc \
	devices/rom.cc \
	devices/l4rtc.cc

PRIVATE_INCDIR ?= $(SRC_DIR) $(SRC_DIR)/target $(SRC_DIR)/ARCH-$(ARCH)

REQUIRES_LIBS ?= libfdt libstdc++

include $(L4DIR)/mk/prog.mk
