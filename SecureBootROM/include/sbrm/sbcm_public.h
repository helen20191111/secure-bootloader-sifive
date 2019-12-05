/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _SBRM_PUBLIC_H_
#define _SBRM_PUBLIC_H_

/** Global includes */
#include <memory.h>
#include <common.h>
#include <errors.h>
#include <metal/cpu.h>
/** Other includes */
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
/** SBRM errors base */
#define C_SBRM_BASE_ERROR        				( N_PREFIX_SBRM << C_PREFIX_OFFSET )

/** Size of table used as reference for CRC32 computation */
#define	C_SBRM_CRC_TABLE_SIZE_INT				0x100
/** Polynomial for CRC32 computation */
#define	C_SIFIVE_POLYNOMIAL						0xedb88320

/** Enumerations **************************************************************/
typedef enum
{
	/**  */
	N_SBRM_ERR_MIN = C_SBRM_BASE_ERROR,
	N_SBRM_ERR_AES_TEST_FAILURE,
	N_SBRM_ERR_ECDSA_TEST_FAILURE,
	N_SBRM_ERR_CPU_NOT_FOUND,
	N_SBRM_ERR_CPU_IRQ_NOT_FOUND,
	N_SBRM_ERR_,
	N_SBRM_ERR_MAX = N_SBRM_ERR_,
	N_SBRM_ERR_COUNT

} e_sbrm_error;

typedef enum
{
	/**  */
	N_SBRM_BUSID_MIN = 0,
	N_SBRM_BUSID_UART = N_SBRM_BUSID_MIN,
	N_SBRM_BUSID_SPI,
	N_SBRM_BUSID_USB,
	N_SBRM_BUSID_MAX = N_SBRM_BUSID_USB,
	N_SBRM_BUSID_COUNT

} e_sbrm_busid;


#define	C_SBRM_BUSID_DEFAULT					N_SBRM_BUSID_UART
/** Structures ****************************************************************/

typedef struct
{
	/** Previous power mode */
	uint32_t									power_mode;
	/** CRC Table */
	uint32_t									crc_ref_table[C_SBRM_CRC_TABLE_SIZE_INT];
	/** Pointer on CPU context structure */
	struct metal_cpu							*p_cpu;
	/** Pointer on interruption function pointer array */
	struct metal_interrupt						*p_cpu_intr;

} t_sbrm_context;

/** Functions *****************************************************************/
int32_t sbrm_init(void *p_ctx, void *p_in, uint32_t length_in);
void sbrm_shutdown(void *p_ctx);
/** OTP */
int32_t sbrm_read_otp(t_context *p_context, uint32_t offset, uint8_t *p_data, uint32_t length);
/**  */
int32_t sbrm_check_rom_crc(void);
int32_t sbrm_get_sbc_version(uint32_t *p_version);
int32_t sbrm_get_sbc_ref_version(uint32_t *p_version);
int32_t sbrm_get_uid(t_context *p_ctx, uint8_t *p_uid);
void sbrm_erase_contexts(t_context *p_ctx);
void sbrm_platform_reset(t_context *p_ctx);
void sbrm_platform_shutdown(t_context *p_ctx);

/** Macros ********************************************************************/




#endif /* _SBRM_PUBLIC_H_ */

/******************************************************************************/
/* End Of File */
