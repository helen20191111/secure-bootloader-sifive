/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */


/** Global includes */
#include <common.h>
#include <errors.h>
#include <otp_mapping.h>
/** Other includes */
/** Local includes */
#include <km_public.h>
#include <km_internal.h>

/** External declarations */
extern t_km_context km_context;
/** Local declarations */
#ifndef _TEST_KEYS_
/** SiFive Test Key - Production version - ECDSA384 ***************************/
__attribute__((section(".rodata"))) const uint8_t stk[2 * C_EDCSA384_SIZE] =
{

};
/** SiFive Signing Key - Production version - ECDSA384 ************************/
__attribute__((section(".rodata"))) const uint8_t ssk[2 * C_EDCSA384_SIZE] =
{

};
#else
/** SiFive Test Key - Test version - ECDSA384 ***************************/
__attribute__((section(".rodata"))) const uint8_t stk[2 * C_EDCSA384_SIZE] =
{
		/** public key X coordinate */
		0x69,0x8f,0x0d,0xb2,0xd0,0x44,0x8d,0x35,0xd1,0x03,0xf7,0x0c,0xd3,0xb7,0x78,0x03,
		0x41,0x23,0x88,0x6b,0x5b,0xb6,0xd7,0x81,0xb5,0x56,0x73,0x37,0xa2,0x7b,0x09,0xa4,
		0x80,0xbf,0x1b,0xd6,0x2a,0x4a,0x85,0xe6,0xce,0x55,0x7c,0xc3,0x90,0xa8,0x1e,0x60,
		/** public key Y coordinate */
		0x8b,0x69,0x1e,0x3d,0x7b,0x25,0x19,0xf5,0x89,0x23,0xce,0xae,0xee,0xea,0x2a,0xa7,
		0x2c,0x24,0x91,0xde,0x3f,0x26,0xb8,0x3d,0x74,0xd9,0xcd,0x52,0xa5,0x4e,0x37,0x1e,
		0x35,0x1c,0x95,0x00,0x41,0x67,0x3d,0x68,0x70,0x6e,0xa8,0x08,0x34,0x0c,0x47,0x34
};
/** SiFive Signing Key - Test version - ECDSA384 ************************/
__attribute__((section(".rodata"))) const uint8_t ssk[2 * C_EDCSA384_SIZE] =
{
		/** public key X coordinate */
		0x69,0x8f,0x0d,0xb2,0xd0,0x44,0x8d,0x35,0xd1,0x03,0xf7,0x0c,0xd3,0xb7,0x78,0x03,
		0x41,0x23,0x88,0x6b,0x5b,0xb6,0xd7,0x81,0xb5,0x56,0x73,0x37,0xa2,0x7b,0x09,0xa4,
		0x80,0xbf,0x1b,0xd6,0x2a,0x4a,0x85,0xe6,0xce,0x55,0x7c,0xc3,0x90,0xa8,0x1e,0x60,
		/** public key Y coordinate */
		0x8b,0x69,0x1e,0x3d,0x7b,0x25,0x19,0xf5,0x89,0x23,0xce,0xae,0xee,0xea,0x2a,0xa7,
		0x2c,0x24,0x91,0xde,0x3f,0x26,0xb8,0x3d,0x74,0xd9,0xcd,0x52,0xa5,0x4e,0x37,0x1e,
		0x35,0x1c,0x95,0x00,0x41,0x67,0x3d,0x68,0x70,0x6e,0xa8,0x08,0x34,0x0c,0x47,0x34
};
#endif /* _TEST_KEYS_ */

/******************************************************************************/
//int32_t km_program_csk(uint8_t slot, t_key_data *p_cskdata)
//{
//	int32_t										err = GENERIC_ERR_UNKNOWN;
//	uint32_t									offset;
//	uint32_t									length;
//	uint8_t										*p_src;
//
//
//	/** Check input pointer */
//	if( !p_cskdata )
//	{
//		/** Pointer is null */
//		err = GENERIC_ERR_NULL_PTR;
//	}
//	else if( ( ( C_OTP_MAPPING_CSK_END_OFST - C_OTP_MAPPING_CSK_OFST ) / C_OTP_MAPPING_CSK_AERA_SIZE ) <= slot )
//	{
//		/** Slot doesn't fit ... */
//		err = N_KM_ERR_INVAL;
//	}
//	else
//	{
//		/** Now we're good, let's program CSK */
//
//		/** Unlock OTP */
//
//		/** Compute offset thanks to 'slot' */
//		p_src = (uint8_t*)&p_cskdata->algo;
//		offset = C_OTP_MAPPING_CSK_OFST + ( slot * C_OTP_MAPPING_CSK_AERA_SIZE );
//		length = C_KM_CSK_DESCR_CSK_SIZE_IN_BYTES + p_cskdata->key_size_bits + p_cskdata->signature_size;
//		/** Program OTP at 'offset' */
//
//		/** No error */
//		err = NO_ERROR;
//	}
//	/** End Of Function */
//	return err;
//}

/******************************************************************************/
/* End Of File */