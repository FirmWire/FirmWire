## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause

#  by Grant Hernandez & Marius Muench (c) 2020

# Tooling
ifndef PREFIX
PREFIX := mipsel-linux-gnu-
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
# interaptiv
LINKER_SCRIPT=modkit.ld
CFLAGS=-march=interaptiv \
	   -mips16 \
       -O2 \
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
	-Wl,--build-id=none \
	   -Wl,--require-defined=TASK_NAME

ASFLAGS=
DEPFLAGS=-M $(CFLAGS)
LDFLAGS=-Wl,-T$(LINKER_SCRIPT) \
	-Wl,--gc-sections \
	$(CFLAGS)

COMMON_SRC := common.c task.c mtk_task.c
COMMON_OBJ := $(addprefix $(BUILD_DIR)/, $(COMMON_SRC:.c=.o))
COMMON_DEP := $(addprefix $(BUILD_DIR)/, $(COMMON_SRC:.c=.d))

#######################################

MODS := hello_world msg_inject_test lte_rrc

hello_world_SRC := hello_world.c

msg_inject_test_SRC := msg_inject_test.c
lte_rrc_SRC := fuzzers/lte_rrc.c afl.c

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

$(BUILD_DIR)/%.o : %.c
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
