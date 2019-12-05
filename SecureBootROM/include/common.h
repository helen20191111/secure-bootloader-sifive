/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef INCLUDE_COMMON_H_
#define INCLUDE_COMMON_H_

/** Global includes */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#ifndef _WITH_FREEDOM_METAL_
#else
#include <metal/machine.h>
#include <metal/memory.h>
#include <metal/cpu.h>
#include <metal/uart.h>
#endif /* _WITH_FREEDOM_METAL_ */
/** Other includes */
#include <patch.h>
#include <scl_types.h>
#include <scl_hash_sha384.h>
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
#ifndef TRUE
#define	TRUE									1
#endif /* TRUE */

#ifndef FALSE
#define	FALSE									0
#endif /* FALSE */

#ifndef NULL
#define	NULL									((void*)0UL)
#endif /* NULL */

#ifndef _WITH_FREEDOM_METAL_
#define	C_OTP_BASE_ADDRESS						0x08000000UL
#define	C_IRAM_BASE_ADDRESS						0x20000000UL
#define	C_OTP_BASE_ADDRESS						0x08000000UL
#endif /* _WITH_FREEDOM_METAL */

/** Version *******************************************************************/
#ifndef MAJOR_VERSION
#define	SBR_VERSION_MAJOR						0x00
#else
#define	SBR_VERSION_MAJOR						MAJOR_VERSION
#endif /* MAJOR_VERSION */
#define	C_SBR_VERSION_MAJOR_OFST				24
#define	C_SBR_VERSION_MAJOR_MASK_NOOFST			0xff
#define	C_SBR_VERSION_MAJOR_MASK				( C_SBR_VERSION_MAJOR_MASK_NOOFST << C_SBR_VERSION_MAJOR_OFST )

#ifndef MINOR_VERSION
#define	SBR_VERSION_MINOR						0x00
#else
#define	SBR_VERSION_MINOR						MINOR_VERSION
#endif /* MINOR_VERSION */
#define	C_SBR_VERSION_MINOR_OFST				16
#define	C_SBR_VERSION_MINOR_MASK_NOOFST			0xff
#define	C_SBR_VERSION_MINOR_MASK				( C_SBR_VERSION_MINOR_MASK_NOOFST << C_SBR_VERSION_MINOR_OFST )


#ifndef EDIT_VERSION
#define	SBR_VERSION_EDIT						0x0001
#else
#define	SBR_VERSION_EDIT						EDIT_VERSION
#endif /* EDIT_VERSION */
#define	C_SBR_VERSION_EDIT_OFST					0
#define	C_SBR_VERSION_EDIT_MASK_NOOFST			0xffff
#define	C_SBR_VERSION_EDIT_MASK					( C_SBR_VERSION_EDIT_MASK_NOOFST << C_SBR_VERSION_EDIT_OFST )

#ifndef REF_MAJOR_VERSION
#define	SBR_REF_VERSION_MAJOR					0x00
#else
#define	SBR_REF_VERSION_MAJOR					REF_MAJOR_VERSION
#endif /* REF_MAJOR_VERSION */
#define	C_SBR_REF_VERSION_MAJOR_OFST			24
#define	C_SBR_REF_VERSION_MAJOR_MASK_NOOFST		0xff
#define	C_SBR_REF_VERSION_MAJOR_MASK			( C_SBR_REF_VERSION_MAJOR_MASK_NOOFST << C_SBR_REF_VERSION_MAJOR_OFST )

#ifndef REF_MINOR_VERSION
#define	SBR_REF_VERSION_MINOR					0x00
#else
#define	SBR_REF_VERSION_MINOR					REF_MINOR_VERSION
#endif /* REF_MINOR_VERSION */
#define	C_SBR_REF_VERSION_MINOR_OFST			16
#define	C_SBR_REF_VERSION_MINOR_MASK_NOOFST		0xff
#define	C_SBR_REF_VERSION_MINOR_MASK			( C_SBR_REF_VERSION_MINOR_MASK_NOOFST << C_SBR_REF_VERSION_MINOR_OFST )


#ifndef REF_EDIT_VERSION
#define	SBR_REF_VERSION_EDIT					0x0001
#else
#define	SBR_REF_VERSION_EDIT					REF_EDIT_VERSION
#endif /* REF_EDIT_VERSION */
#define	C_SBR_REF_VERSION_EDIT_OFST				0
#define	C_SBR_REF_VERSION_EDIT_MASK_NOOFST		0xffff
#define	C_SBR_REF_VERSION_EDIT_MASK				( C_SBR_REF_VERSION_EDIT_MASK_NOOFST << C_SBR_REF_VERSION_EDIT_OFST )

/******************************************************************************/
#define	C_GENERIC_KILO							1024
#define	C_GENERIC_MEGA							( C_GENERIC_KILO * C_GENERIC_KILO )

#define	C_AES128_SIZE							0x10
#define	C_AES256_SIZE							( 2 * C_AES128_SIZE )

#define	C_TRNG_SIZE								0x10
#define	C_TRNG_SIZE_32BITS						( C_TRNG_SIZE / sizeof(uint32_t) )

#define	C_EDCSA256_SIZE							0x20
#define	C_EDCSA384_SIZE							0x30

#define	C_RSA2048_SIZE							0x100
#define	C_RSA4096_SIZE							( 2 * C_RSA2048_SIZE )

#define	C_CRC32_SIZE							0x20

//#define	C_PATTERN_VIRGIN_8BITS					((int8_t)-1)
//#define	C_PATTERN_VIRGIN_16BITS					((int16_t)-1)
//#define	C_PATTERN_VIRGIN_32BITS					((int32_t)-1)
//#define	C_PATTERN_VIRGIN_64BITS					((int64_t)-1)
//#define	C_PATTERN_VIRGIN_MAXBITS				((intmax_t)-1)

#define	C_PATTERN_VIRGIN_8BITS					0xffU
#define	C_PATTERN_VIRGIN_16BITS					0xffffU
#define	C_PATTERN_VIRGIN_32BITS					0xffffffffUL
#define	C_PATTERN_VIRGIN_64BITS					0xffffffffffffffffULL
#if __riscv_xlen == 32
/** 32bits */
#define	C_PATTERN_VIRGIN_MAXBITS				0xffffffffffffffffULL
#elif __riscv_xlen == 64
/** 64bits */
#define	C_PATTERN_VIRGIN_MAXBITS				0xffffffffffffffffULL
#else
/** 128bits */
#define	C_PATTERN_VIRGIN_MAXBITS				0xffffffffffffffffffffffffffffffffULLL
#endif /* __riscv_xlen */

#define	C_SIGNATURE_MAX_SIZE					( 2 * C_EDCSA384_SIZE )
#define	C_SIGNATURE_MAX_SIZE_INT				( C_SIGNATURE_MAX_SIZE / sizeof(uint32_t) )

#define	C_ADDRESS_SIZE_MAX						16

#define	C_MAX_CHECK_LOOP_NB						2

#define	C_UID_SIZE_IN_BYTES						16

#define	C_CRYPTO_LIB_BUFFER_SIZE				( 8 * C_GENERIC_KILO )
#define	C_CRYPTO_LIB_BUFFER_SIZE_INT			( C_CRYPTO_LIB_BUFFER_SIZE / sizeof(word_type) )

/** Enumerations **************************************************************/

/** Structures ****************************************************************/

/** UART defines **************************************************************/
/** TXDATA register */
#define	C_UART_TXDATA_DATA_OFST					0
#define	C_UART_TXDATA_DATA_MASK_NOOFST			0xf
#define	C_UART_TXDATA_DATA_MASK					( C_UART_TXDATA_DATA_MASK_NOOFST << C_UART_TXDATA_DATA_OFST )

#define	C_UART_TXDATA_FULL_OFST					31
#define	C_UART_TXDATA_FULL_MASK_NOOFST			0x1
#define	C_UART_TXDATA_FULL_MASK					( C_UART_TXDATA_FULL_MASK_NOOFST << C_UART_TXDATA_FULL_OFST )

/** RXDATA register */
#define	C_UART_RXDATA_DATA_OFST					0
#define	C_UART_RXDATA_DATA_MASK_NOOFST			0xf
#define	C_UART_RXDATA_DATA_MASK					( C_UART_RXDATA_DATA_MASK_NOOFST << C_UART_RXDATA_DATA_OFST )

#define	C_UART_RXDATA_EMPTY_OFST				31
#define	C_UART_RXDATA_EMPTY_MASK_NOOFST			0x1
#define	C_UART_RXDATA_EMPTY_MASK				( C_UART_RXDATA_EMPTY_MASK_NOOFST << C_UART_RXDATA_EMPTY_OFST )

/** Transmit Control Register */
#define	C_UART_TXCTRL_TXEN_OFST					0
#define	C_UART_TXCTRL_TXEN_MASK_NOOFST			0x1
#define	C_UART_TXCTRL_TXEN_MASK					( C_UART_TXCTRL_TXEN_MASK_NOOFST << C_UART_TXCTRL_TXEN_OFST )

#define	C_UART_TXCTRL_NSTOP_OFST				1
#define	C_UART_TXCTRL_NSTOP_MASK_NOOFST			0x1
#define	C_UART_TXCTRL_NSTOP_MASK				( C_UART_TXCTRL_NSTOP_MASK_NOOFST << C_UART_TXCTRL_NSTOP_OFST )

#define	C_UART_TXCTRL_TXCNT_OFST				16
#define	C_UART_TXCTRL_TXCNT_MASK_NOOFST			0x7
#define	C_UART_TXCTRL_TXCNT_MASK				( C_UART_TXCTRL_TXCNT_MASK_NOOFST << C_UART_TXCTRL_TXCNT_OFST )

/** Receive Control Register */
#define	C_UART_RXCTRL_RXEN_OFST					0
#define	C_UART_RXCTRL_RXEN_MASK_NOOFST			0x1
#define	C_UART_RXCTRL_RXEN_MASK					( C_UART_RXCTRL_RXEN_MASK_NOOFST << C_UART_RXCTRL_RXEN_OFST )

#define	C_UART_RXCTRL_RXCNT_OFST				16
#define	C_UART_RXCTRL_RXCNT_MASK_NOOFST			0x7
#define	C_UART_RXCTRL_RXCNT_MASK				( C_UART_RXCTRL_RXCNT_MASK_NOOFST << C_UART_RXCTRL_RXCNT_OFST )

/** Interrupt Enable register */
#define	C_UART_IE_TXWM_OFST						0
#define	C_UART_IE_TXWM_MASK_NOOFST				0x1
#define	C_UART_IE_TXWM_MASK						( C_UART_IE_TXWM_MASK_NOOFST << C_UART_IE_TXWM_OFST )

#define	C_UART_IE_RXWM_OFST						1
#define	C_UART_IE_RXWM_MASK_NOOFST				0x1
#define	C_UART_IE_RXWM_MASK						( C_UART_IE_RXWM_MASK_NOOFST << C_UART_IE_RXWM_OFST )

/** Interrupt Pending register */
#define	C_UART_IP_TXWM_OFST						0
#define	C_UART_IP_TXWM_MASK_NOOFST				0x1
#define	C_UART_IP_TXWM_MASK						( C_UART_IP_TXWM_MASK_NOOFST << C_UART_IP_TXWM_OFST )

#define	C_UART_IP_RXWM_OFST						1
#define	C_UART_IP_RXWM_MASK_NOOFST				0x1
#define	C_UART_IP_RXWM_MASK						( C_UART_IP_RXWM_MASK_NOOFST << C_UART_IP_RXWM_OFST )

/** Baud rate Divisor register */
#define	C_UART_DIV_DIV_OFST						0
#define	C_UART_DIV_DIV_MASK_NOOFST				0xffff
#define	C_UART_DIV_DIV_MASK						( C_UART_DIV_DIV_MASK_NOOFST << C_UART_DIV_DIV_OFST )

#define	C_UART_DATA_MAX_THRESHOLD_RX			( C_UART_RXCTRL_RXCNT_MASK_NOOFST + 1 )
#define	C_UART_DATA_MAX_THRESHOLD_TX			( C_UART_TXCTRL_TXCNT_MASK_NOOFST + 1 )

typedef struct
{
	/** Offset 0x00000000 - TX data register */
	uint32_t									tx;
	/** Offset 0x00000004 - RX data register */
	uint32_t									rx;
	/** Offset 0x00000008 - TX control register */
	uint32_t									tx_ctrl;
	/** Offset 0x0000000c - RX control register */
	uint32_t									rx_ctrl;
	/** Offset 0x00000010 - Interrupt enable register */
	uint32_t									ie;
	/** Offset 0x00000014 - Interrupt pending register */
	uint32_t									ip;
	/** Offset 0x00000018 - Baud rate divisor register */
	uint32_t									div;

} t_reg_uart;


typedef struct __attribute__((packed))
{
	/** Magic words */
	uint32_t									magic1;
	uint32_t									magic2;
	/** Secure Boot ROM reference version */
	uint32_t									rom_ref_version;
	/** Firmware Version */
	uint32_t									firmware_version;
	/** Application Type */
	uint16_t									appli_type;
	/** Address Size */
	uint16_t									address_size;
	/** Secure Application image Size */
	uint32_t									secure_appli_image_size;
	/** Firmware Start Offset */
	uint32_t									fimware_start_offset;
	/** Copy Address */
	uint32_t									copy_address[( C_ADDRESS_SIZE_MAX / sizeof(uint32_t) )];
	/** Execution Address */
	uint32_t									execution_address[( C_ADDRESS_SIZE_MAX / sizeof(uint32_t) )];
	/** Algorithm */
	uint8_t										algo;
	/** Signing key identifier */
	uint8_t										sign_key_id;
	/** Key size in bits */
	uint16_t									key_size_bits;
	/** Signature */
	uint8_t										signature[C_SIGNATURE_MAX_SIZE];

} t_secure_header;

typedef struct
{
	/** RAM information */
	metal_memory								iram;
	/** Consecutive internal RAM free area - start address */
	uint32_t									free_ram_start;
	/** Consecutive internal RAM free area - end address */
	uint32_t									free_ram_end;
	/** OTP information */
	metal_memory								otp;
	/** Pointers on modules' context structures */
	/** Debug Authentication Interface Management */
	volatile void								*p_daim_context;
	/** Key Management */
	volatile void								*p_km_context;
	/** Platform Phase Management */
	volatile void								*p_ppm_context;
	/** Secure Boot Core Management */
	volatile void								*p_sbrm_context;
	/** Secure Flexible Loader Verification */
	volatile void								*p_slbv_context;
	/** Secure Protocol */
	volatile void								*p_sp_context;
	/** Table of function pointers for DAIM */
	t_api_fcts									*p_daim_fct_ptr;
	/** Table of function pointers for KM */
	t_api_fcts									*p_km_fct_ptr;
	/** Table of function pointers for PPM */
	t_api_fcts									*p_ppm_fct_ptr;
	/** Table of function pointers for SBRM */
	t_api_fcts									*p_sbrm_fct_ptr;
	/** Table of function pointers for SLBV */
	t_api_fcts									*p_slbv_fct_ptr;
	/** Table of function pointers for SP */
	t_api_fcts									*p_sp_fct_ptr;
	/** Pointers on different useful buffers */
	/** Pointer on SCL work buffer */
	volatile void								*p_scl_work_buffer;
	uint32_t									scl_work_buffer_size;
	/** Pointer on SCL hash context structure */
	volatile void								*p_scl_hash_ctx;
	/** Buffer for has computation spreadly used in SBR - it must be aligned, mandatory for SCL */
	__attribute__((aligned(0x10))) uint8_t		digest[SCL_SHA384_BYTE_HASHSIZE];

} t_context;

/** Functions *****************************************************************/
int32_t context_initialization(t_context *p_ctx);

/** Macros ********************************************************************/
#define	M_GET_OTP_ABSOLUTE_ADDR(_ctx_, _offset_) \
		((((t_context)_ctx_).otp._base_address) + _offset_)

#define M_CHANGE_ENDIANNESS_32BITS(__number__) \
											( ( ( __number__ >> 24 ) & 0x000000ff ) |\
												( ( __number__ >> 8 ) & 0x0000ff00 ) |\
												( ( __number__ << 8 ) & 0x00ff0000 ) | \
												( ( __number__ << 24 ) & 0xff000000 ) )

#define	M_WHOIS_MAX(_a_, _b_)				(( _a_ < _b_ ) ? _b_ : _a_)
#define	M_WHOIS_MIN(_a_, _b_)				(( _a_ < _b_ ) ? _a_ : _b_)

#endif /* INCLUDE_COMMON_H_ */

/******************************************************************************/
/* End Of File */
