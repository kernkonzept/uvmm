PKGDIR		?= ../..
L4DIR		?= $(PKGDIR)/../..

DTBS                  = virt-omap5.dtb virt-exynos5.dtb virt-ls1021a.dtb \
                        virt-mips.dtb
DTBS_DEPS             = $(patsubst %,.%.deps,$(DTBS))
DEL_ON_CLEAN          = $(DTBS) $(DTBS_DEPS)
INSTALL_TARGET        = $(DTBS)
REQUIRE_HOST_TOOLS    = dtc
DTC                  ?= dtc

vpath %.dts $(SRC_DIR)

include $(L4DIR)/mk/lib.mk

-include $(DTBS_DEPS)

%.dtb: %.dts $(SRC_DIR)/Makefile
	@$(BUILD_MESSAGE)
	$(VERBOSE)$(DTC) -d .$@.deps-x -O dtb -b 0 -o $@ $<
	$(VERBOSE)perl -ne 'print "$$_\n"; if (/^.*:\s*(.*)$$/) { print "$$_:\n" foreach (split(/ /,$$1)); }' <.$@.deps-x >.$@.deps
