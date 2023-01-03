## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause

#  by Grant Hernandez & Marius Muench (c) 2020

# Tooling
ifndef PREFIX
PREFIX := arm-none-eabi-
endif

OBJDUMP := $(PREFIX)objdump
OBJCOPY := $(PREFIX)objcopy
SIZE := $(PREFIX)size
AS := $(PREFIX)as
CC := $(PREFIX)gcc
LD := $(PREFIX)gcc

ifndef BUILD_DIR
BUILD_DIR=build
endif

LINKER_SCRIPT=modkit.ld
CFLAGS=-march=armv7-r \
       -mtune=cortex-r7 \
       -mthumb \
       -O1 \
       -nostdlib \
       -std=gnu99 \
       -fpie \
       -I $(CURDIR) \
       -Wall \
       -Wextra \
       -nostdlib \
       -nostdinc \
       -fno-builtin \
       -nostartfiles \
       -ffunction-sections \
       -nodefaultlibs \
       -Wno-unused-function \
       -Wno-unused-parameter \
       -Wl,--require-defined=TASK_NAME

ASFLAGS=-mthumb
DEPFLAGS=-M $(CFLAGS)
LDFLAGS=-Wl,-T$(LINKER_SCRIPT) \
	-Wl,--gc-sections \
	$(CFLAGS)

COMMON_SRC := shannon.c common.c modkit.c task.c
COMMON_OBJ := $(addprefix $(BUILD_DIR)/, $(COMMON_SRC:.c=.o))
COMMON_DEP := $(addprefix $(BUILD_DIR)/, $(COMMON_SRC:.c=.d))

#######################################

MODS := gsm_mm gsm_sm gsm_cc lte_rrc glink hello_world

gsm_mm_SRC := fuzzers/gsm_mm.c afl.c
gsm_cc_SRC := fuzzers/gsm_cc.c afl.c
gsm_sm_SRC := fuzzers/gsm_sm.c afl.c
lte_rrc_SRC := fuzzers/lte_rrc.c afl.c
glink_SRC := glink.c
hello_world_SRC := hello_world.c

#######################################

all : $(BUILD_DIR) $(addprefix $(BUILD_DIR)/, $(foreach mod,$(MODS),$(addsuffix .bin,$(mod))))

define MOD_template
$(1)_OBJ := $$(addprefix $$(BUILD_DIR)/, $$($(1)_SRC:.c=.o))
$(1)_DEP := $$(addprefix $$(BUILD_DIR)/, $$($(1)_SRC:.c=.d))

$(BUILD_DIR)/$(addsuffix .elf,$(1)) : $$($(1)_DEP) $$(COMMON_DEP) $$(COMMON_OBJ) $$($(1)_OBJ) $$(LINKER_SCRIPT)
	@echo "MOD $$@"
	@$$(LD) $$(LDFLAGS) -o $$@ $$($(1)_OBJ) $$(COMMON_OBJ)
endef

# Create recipes for all modules
$(foreach mod,$(MODS),$(eval $(call MOD_template,$(mod))))

$(BUILD_DIR)/%.o : %.c *.h
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.bin : $(BUILD_DIR)/%.elf
	@echo "BIN $@ <- $<"
	@$(OBJCOPY) -O binary $< $@
	@echo "====== $@ size ======"
	@$(SIZE) $<
	@echo "====================="

$(BUILD_DIR)/%.o : %.S
	@echo "AS $<"
	@$(AS) $(ASFLAGS) -c $< -o $@

$(BUILD_DIR)/%.d : %.c | $(BUILD_DIR)
	@echo "DEP $<"
	@$(CC) $(DEPFLAGS) $< -MF"$@" -MT"$@ $(<:.c=.o)" ### generate dep for $<

$(BUILD_DIR) :
	@echo "MKDIR $(BUILD_DIR)"
	@mkdir -p $(BUILD_DIR)/fuzzers

# include generated dep files
ifeq (,$(findstring clean, $(MAKECMDGOALS)))
-include $(COMMON_DEP) $(foreach mod,$(MODS), $($(mod)_DEP))
endif

clean:
	@echo "CLEAN $(BUILD_DIR)"
	@rm -rf $(BUILD_DIR)

.PHONY: all clean
