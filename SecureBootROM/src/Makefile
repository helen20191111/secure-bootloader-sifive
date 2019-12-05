# Copyright 2019 SiFive, Inc #
# SPDX-License-Identifier: Apache-2.0 #

#############################################################
# Toolchain
#############################################################

BUILD_DIR = ../build
BUILD_DIRECTORIES = $(BUILD_DIR)
BSP_DIR = ../bsp
FREEDOM_DIR = ../freedom-metal

PROGRAM ?= securebootcore

SBR_DIR = .

## include SBR version
include $(SBR_DIR)/version.mk

## include all local defines and undefines for this project
include $(SBR_DIR)/defines.mk

SBR_INCS_DIR =	-I ../include
SBR_INCS_DIR += -I ../include/daim
SBR_INCS_DIR += -I ../include/km
SBR_INCS_DIR += -I ../include/pi
SBR_INCS_DIR += -I ../include/ppm
SBR_INCS_DIR += -I ../include/sbrm
SBR_INCS_DIR += -I ../include/slbv
SBR_INCS_DIR += -I ../include/sp

SCL_DIR = ../libraries/soscl
SCL_INC_DIR = -I $(SCL_DIR)/include
SCL_INC_DIR += -I $(SCL_DIR)/include/soscl

SCL_LIBRARY = $(SCL_DIR)/../libsoscl.a

# List of C source files
APP_SRC = $(wildcard *.c)
APP_SRC += $(wildcard $(SBR_DIR)/daim/*.c)
APP_SRC += $(wildcard $(SBR_DIR)/km/*.c)
APP_SRC += $(wildcard $(SBR_DIR)/pi/*.c)
APP_SRC += $(wildcard $(SBR_DIR)/ppm/*.c)
APP_SRC += $(wildcard $(SBR_DIR)/sbrm/*.c)
APP_SRC += $(wildcard $(SBR_DIR)/slbv/*.c)
APP_SRC += $(wildcard $(SBR_DIR)/sp/*.c)
# List of assembly source files
APP_ASM = $(wildcard *.S)

# Objects
APP_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(APP_SRC)))
APP_OBJS += $(patsubst %.S,$(BUILD_DIR)/%.o,$(notdir $(APP_ASM)))
APP_INCLUDES = \
	-I $(abspath $(BSP_DIR)) \
	-I $(abspath $(FREEDOM_DIR)/metal)\
	-I $(abspath $(FREEDOM_DIR)/metal/drivers)\
	-I $(abspath $(BSP_DIR)/install/include/metal) \
	$(SBR_INCS_DIR) \
	$(SCL_INC_DIR)

# List of object files to compile for the system:
PROGRAM_OBJS = \
	$(APP_OBJS)

# Add SCL to link
SBL_LDFLAGS = -L$(SCL_DIR)/..
SBL_LDLIBS = -Wl,--start-group -lsoscl -Wl,--end-group

# Virtual path for compiling
VPATH += $(SBR_DIR)/daim
VPATH += $(SBR_DIR)/km
VPATH += $(SBR_DIR)/pi
VPATH += $(SBR_DIR)/ppm
VPATH += $(SBR_DIR)/sbrm
VPATH += $(SBR_DIR)/slbv
VPATH += $(SBR_DIR)/sp

# Compiling options
CFLAGS_LOC = $(__CLIST_DEFINITIONS) $(__CLIST_UNDEFINITIONS)
ASMFLAGS_LOC = $(__ALIST_DEFINITIONS) $(__ALIST_UNDEFINITIONS)

# Compile Object Files ____________________________________________________________________
$(SCL_LIBRARY) :
	$(MAKE) -C $(SCL_DIR) $(basename $(notdir $@)) \
	AR=$(AR) \
	CC=$(CC) \
	CFLAGS="$(CFLAGS)"

$(BUILD_DIR)/%.o : %.c
	@echo "____ Build objects from C files : $<"
	$(CC) $(CFLAGS) $(CFLAGS_LOC) $(APP_INCLUDES) -o $@ -c $<
	@echo "____ Finished Building: $@"
	@echo

$(BUILD_DIR)/%.o : %.S
	@echo "____ Build objects from Assembly : $<"
	@echo "Building: $<"
	$(CC) $(ASMFLAGS) $(ASMFLAGS_LOC) $(APP_INCLUDES) -o $@ -c $<
	@echo "____ Finished Building: $@"
	@echo

$(BUILD_DIRECTORIES):
	mkdir -p $@
directories: $(BUILD_DIRECTORIES)

$(PROGRAM):	directories $(SCL_LIBRARY) $(PROGRAM_OBJS)
	@echo " ---> Link created objects"
	$(CC) $(CFLAGS) $(LDFLAGS) $(SBL_LDFLAGS) $(PROGRAM_OBJS) $(LDLIBS) $(SBL_LDLIBS) -o $@

clean::
	$(MAKE) -C $(SCL_DIR) clean
	rm -f $(BUILD_DIR)/*.o
	rm -f $(PROGRAM) $(PROGRAM).hex
	
