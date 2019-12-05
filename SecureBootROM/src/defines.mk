# Copyright 2019 SiFive, Inc #
# SPDX-License-Identifier: Apache-2.0 #

## List of constants to be activated/defined
## C code
__CLIST_DEFINITIONS = -DSCL_WORD32 \
						-D_WITH_TEST_CSK_ \
						-D_WITH_FREEDOM_METAL_ \
						-D_SUPPORT_ALGO_ECDSA384_ \
						-D_SUP_OLD_BEHAVIOR_ \
						-D_WITH_UART_WORKAROUND_\
						-D_TEST_KEYS_ \
						-D_WITHOUT_SELFTESTS_ \
						-D_LIFE_CYCLE_PHASE1_ \
						-D_WITH_SUP_STIM_ \
						-DCOREIP_MEM_WIDTH=$(COREIP_MEM_WIDTH) \
						-DMAJOR_VERSION=$(__MAJOR_VERSION) \
						-DMINOR_VERSION=$(__MINOR_VERSION) \
						-DEDIT_VERSION=$(__EDIT_VERSION) \
						-DREF_MAJOR_VERSION=$(__BREF_MAJOR_VERSION) \
						-DREF_MINOR_VERSION=$(__BREF_MINOR_VERSION) \
						-DREF_EDIT_VERSION=$(__BREF_EDIT_VERSION)
				
## Assembly code
__ALIST_DEFINITIONS =

## List of constants to be deactivated/undefined
## C code
__CLIST_UNDEFINITIONS = -U_WITH_TEST_CUK_ \
						-U_FPGA_SPECIFIC_ \
						-U_LIFE_CYCLE_PHASE2_ \
						-U_WITH_RMA_MODE_ON_ \
						-U_WITH_CHECK_ROM_ \
						-U_WITH_128BITS_ADDRESSING_ \
						-U_WITH_BOOT_ADDR_ \
						-U_WITH_FIRMWARE_VERSION_ \
						-U_DBG_DEVEL_ \
						-U_DBG_BEACON_
## Assembly code
__ALIST_UNDEFINITIONS =

## End Of File
