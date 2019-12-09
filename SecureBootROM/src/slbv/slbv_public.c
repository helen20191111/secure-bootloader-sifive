/** slbv_public.c */
/**
 * Copyright 2019 SiFive
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
*/



/** Global includes */
#include <stdio.h>
#include <string.h>
#include <common.h>
#include <errors.h>
#include <patch.h>
#include <otp_mapping.h>
/** Other includes */
#include <soscl_retdefs.h>
#include <soscl_ecc.h>
#include <soscl_hash_sha384.h>
#include <soscl_ecdsa.h>
#include <km_public.h>
#include <sbrm_public.h>
/** Local includes */
#include <slbv_public.h>
#include <slbv_internal.h>

/** External declarations */
extern uintmax_t __iflash_start;
extern soscl_type_curve soscl_secp384r1;
/** Local declarations */
__attribute__((section(".bss"))) t_slbv_context slbv_context;
__attribute__((section(".data.patch.table"))) t_api_fcts slbv_fct_ptr =
{
		.initialize_fct = slbv_init,
		.shutdown_fct = slbv_shutdown,
		.read_fct = dummy_fct,
		.write_fct = dummy_fct,
		.gen1_fct = dummy_fct,
		.gen2_fct = dummy_fct,
		.gen3_fct = dummy_fct,
		.gen4_fct = dummy_fct,
};


/******************************************************************************/
int32_t slbv_init(void *p_ctx, void *p_in, uint32_t length_in)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		t_context								*p_context = (t_context*)p_ctx;
		/** Initialize internal structure */
		memset((void*)&slbv_context, 0x00, sizeof(t_slbv_context));
		/** Then set structure parameters */

		/** Local context structure assignment */
		p_context->p_slbv_context = (volatile void*)&slbv_context;
		/** No error */
		err = NO_ERROR;
	}
	/** End Of Function */
	return err;
}


/******************************************************************************/
int32_t slbv_shutdown(void *p_ctx)
{
	/** End Of Function */
	return NO_ERROR;
}

/******************************************************************************/
int32_t slbv_process(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Verify application header and its signature */
		err = sflv_check_slb(p_ctx);
		if( NO_ERROR == err )
		{
			/** Jump into SLB/SFL */
			slbv_context.jump_fct_ptr();
		}
	}
	/** Something goes wrong, let's reset the platform */
	sbrm_platform_reset(p_ctx);
	/** End Of Function */
	return err;
}

/******************************************************************************/
/** Look for Boot address */
int32_t	sflv_get_boot_address(t_context *p_ctx, uintmax_t *p_addr)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	int32_t										slot = C_OTP_MAPPING_BOOT_ADDR_SLOT_MAX;

	/** Check input pointer */
	if( !p_ctx || !p_addr )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Look for non virgin slot */
		while( ( slot >= 0 ) && ( NO_ERROR != err ) )
		{
			/** Start from last slot */
			*p_addr = *((uintmax_t*)(M_GET_OTP_ABSOLUTE_ADDR(*p_ctx, C_OTP_MAPPING_BOOT_ADDR_AERA_OFST + ( slot * C_OTP_MAPPING_BOOT_ADDR_ELMNT_SIZE ))));
			if( (uintmax_t)C_PATTERN_VIRGIN_MAXBITS == (uintmax_t)*p_addr )
			{
				/** Not found */
				slot--;
			}
			else
			{
				/** Found */
				err = NO_ERROR;
			}
		}
		/** Check if something has been found or not */
		if( err )
		{
			/** Nothing found, specific error then */
			err = N_SLBV_ERR_NO_BOOT_ADDRESS;
		}
	}
	/** End Of Function */
	return err;
}


/******************************************************************************/
int32_t sflv_get_application_version(t_context *p_ctx, uint32_t *p_version)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	int32_t										slot = C_OTP_MAPPING_APP_REFV_SLOT_MAX;

	/** Check input pointer */
	if( !p_ctx || !p_version )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Look for non virgin slot */
		while( ( slot >= 0 ) && ( NO_ERROR != err ) )
		{
			/** Start from last slot */
			*p_version = *((uint32_t*)M_GET_OTP_ABSOLUTE_ADDR(*p_ctx, C_OTP_MAPPING_APP_REFV_AREA_OFST + ( slot * C_OTP_MAPPING_APP_REFV_ELMNT_SIZE )));
			if( (uint32_t)C_PATTERN_VIRGIN_32BITS != (uint32_t)*p_version )
			{
				/** Found */
				err = NO_ERROR;
			}
			else
			{
				/**  */
				slot--;
			}
		}
		/** Check if something has been found or not */
		if( err )
		{
			/** Nothing found, specific error then */
			err = N_SLBV_ERR_NO_APP_REF_VERSION;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sflv_check_slb(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									tmp = 0;
	uint32_t									rom_version = 0;
	volatile uint32_t							tmp_size = 0;
	u_km_key									key;
	soscl_type_ecc_uint8_t_affine_point			Q;
	soscl_type_ecdsa_signature					signature;
	volatile uint8_t							*p_tmp;
	t_km_context								*p_km_ctx;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !p_ctx->p_km_context )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Assign pointer */
		p_km_ctx = (t_km_context*)p_ctx->p_km_context;
		/**  */
		err = sflv_get_boot_address(p_ctx, (uintmax_t*)&slbv_context.boot_addr);
		if( err || !slbv_context.boot_addr )
		{
			/** Set default value - address of free area in internal RAM/Flash */
			slbv_context.boot_addr = (volatile uintmax_t)&__iflash_start;
		}
		/** Assign value then */
		slbv_context.p_hdr = (volatile t_secure_header*)slbv_context.boot_addr;
		/** Look for synchronization pattern */
		if( ( C_SFLV_MAGIC_WORD1 != slbv_context.p_hdr->magic1 ) || ( C_SFLV_MAGIC_WORD2 != slbv_context.p_hdr->magic2 ) )
		{
			/** Synchronization pattern(s), no match */
			err = N_SLBV_ERR_SYNC_PTRN_FAILURE;
			goto sflv_check_slb_out;
		}
		/** Check Secure Boot ROM version */
		rom_version = ( ( SBR_REF_VERSION_EDIT << C_SBR_REF_VERSION_EDIT_OFST ) & C_SBR_REF_VERSION_EDIT_MASK ) |\
						( ( SBR_REF_VERSION_MINOR << C_SBR_REF_VERSION_MINOR_OFST ) & C_SBR_REF_VERSION_MINOR_MASK ) |\
						( ( SBR_REF_VERSION_MAJOR << C_SBR_REF_VERSION_MAJOR_OFST ) & C_SBR_REF_VERSION_MAJOR_MASK );
		if( rom_version > slbv_context.p_hdr->rom_ref_version )
		{
			/** Application is not compatible */
			err = N_SLBV_ERR_HDR_VERSION_MISMATCH;
			goto sflv_check_slb_out;
		}
		/** Check firmware version given in header compare to the one from storage area (OTP) */
		err = sflv_get_application_version(p_ctx, &slbv_context.ref_appli_version);
		if( N_SLBV_ERR_NO_APP_REF_VERSION == err )
		{
			/** Set very default version */
			slbv_context.ref_appli_version = (uint32_t)1UL;
		}
		else if( err )
		{
			/** Should not happen */
			goto sflv_check_slb_out;
		}
		/** Given version must be equal or greater than stored one */
		if( slbv_context.ref_appli_version > slbv_context.p_hdr->firmware_version )
		{
			/** Version does not match */
			err = N_SLBV_ERR_VERSION_MISMATCH;
			goto sflv_check_slb_out;
		}
		/** Check application type */
		switch( slbv_context.p_hdr->appli_type )
		{
			case N_SLBV_APP_TYPE_REGULAR:
				slbv_context.decryption = FALSE;
				break;
			case N_SLBV_APP_TYPE_ENCRYPTED:
			default:
				err = N_SLBV_ERR_APPLI_TYPE_NOT_SUPPORTED;
				goto sflv_check_slb_out;
		}
		/** Check signature description parameters */
		if( ( C_KM_CSK_DESCR_ALGO_ECDSA != slbv_context.p_hdr->algo ) ||
			( C_KM_CSK_DESCR_VERIF_KEY_CSK != slbv_context.p_hdr->sign_key_id ) ||
			( ( C_EDCSA384_SIZE * 8 ) != slbv_context.p_hdr->key_size_bits ) )
		{
			/**  */
			err = N_SLBV_ERR_INVAL;
			goto sflv_check_slb_out;
		}
		/** Check address range */
#if COREIP_MEM_WIDTH == 128
		/** 128bits core */
		if( C_SEC_HDR_ADDRESS_SIZE_128BITS != slbv_context.p_hdr->address_size )
		{
			/**  */
			err = N_SLBV_ERR_ADDR_SIZE_NOT_SUPPORTED;
			goto sflv_check_slb_out;
		}
		else
		{
			/** 128bits core */
			slbv_context.jump_fct_ptr = *((uintmax_t*)slbv_context.p_hdr->execution_address);
		}
#elif COREIP_MEM_WIDTH == 64
		/** 64bits */
		if( C_SEC_HDR_ADDRESS_SIZE_64BITS != slbv_context.p_hdr->address_size )
		{
			/**  */
			err = N_SLBV_ERR_ADDR_SIZE_NOT_SUPPORTED;
			goto sflv_check_slb_out;
		}
		else
		{
			/** 64bits */
			slbv_context.jump_fct_ptr = *((uint64_t*)slbv_context.p_hdr->execution_address);
		}
#else
		/** 32bits */
		if( C_SEC_HDR_ADDRESS_SIZE_32BITS != slbv_context.p_hdr->address_size )
		{
			/**  */
			err = N_SLBV_ERR_ADDR_SIZE_NOT_SUPPORTED;
			goto sflv_check_slb_out;
		}
		else
		{
			/** 32bits */
			slbv_context.jump_fct_ptr = *((uint32_t*)slbv_context.p_hdr->execution_address);
		}
#endif /* COREIP_MEM_WIDTH */
		/** Check signature */
		/** First, retrieve key */
		/** Retrieve key */
		err = km_get_key(slbv_context.p_hdr->sign_key_id,
							(u_km_key*)&key,
							(uint32_t*)&tmp);
		if( err )
		{
			/** Valid CSK not available/found */
			err = N_SLBV_ERR_NO_CSK_AVIALABLE;
			goto sflv_check_slb_out;
		}
		/** Initialization oh hash buffer */
		err = soscl_sha384_init((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx);
		if( err )
		{
			/** Critical error */
			err = N_SLBV_ERR_CRYPTO_FAILURE;
			goto sflv_check_slb_out;
		}
		/** Hash header */
		p_tmp = (volatile uint8_t*)slbv_context.p_hdr;
		tmp_size = (volatile uint32_t)sizeof(t_secure_header) - C_SIGNATURE_MAX_SIZE;
		err = soscl_sha384_core((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx,
								(uint8_t*)p_tmp,
								(uint32_t)tmp_size);
		if( err )
		{
			/** Should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sflv_check_slb_out;
		}
		/** Hash binary image */
		p_tmp = (volatile uint8_t*)slbv_context.p_hdr + sizeof(t_secure_header) + slbv_context.p_hdr->fimware_start_offset;
		tmp_size = (volatile uint32_t)slbv_context.p_hdr->secure_appli_image_size - sizeof(t_secure_header);
		/** Hash binary image */
		err = soscl_sha384_core((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx,
								(uint8_t*)p_tmp,
								(uint32_t)tmp_size);
		if( err )
		{
			/** Should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sflv_check_slb_out;
		}
		/** Then finish computation */
		memset((void*)p_ctx->digest, 0x00, SCL_SHA384_BYTE_HASHSIZE);
		err = soscl_sha384_finish(p_ctx->digest, (soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx);
		if( err )
		{
			/** Critical error */
			err = GENERIC_ERR_CRITICAL;
			goto sflv_check_slb_out;
		}
		/** Assign parameters */
		Q.x = key.ecdsa.p_x;
		Q.y = key.ecdsa.p_y;
		signature.r = (uint8_t*)slbv_context.p_hdr->signature;
		signature.s = signature.r + C_EDCSA384_SIZE;
		/** Check certificate */
		err = soscl_ecdsa_verification(Q,
										signature,
										&soscl_sha384,
										p_ctx->digest,
										SCL_SHA384_BYTE_HASHSIZE,
										&soscl_secp384r1,
										( SCL_HASH_INPUT_TYPE << SCL_INPUT_SHIFT ) ^
										( SCL_SHA384_ID << SCL_HASH_SHIFT ));
		if( err )
		{
			/** SLB is not granted to be executed on this platform */
			err = N_SLBV_ERR_CRYPTO_FAILURE;
			goto sflv_check_slb_out;
		}
		else
		{
			/** No error */
			err = NO_ERROR;
		}
#warning a more accurate implementation is mandatory to care about areas size and driver to program to destination area
		/** Check if SLB is XIP or not */
		if( ( (uintmax_t)( 0xff << 24 ) & (uintmax_t)slbv_context.boot_addr ) != ( (uintmax_t)( 0xff << 24 ) & (uintmax_t)slbv_context.p_hdr->copy_address ) )
		{
			/** If not, SLB has been checked ok, let's copy it at destination area */
			memcpy((void*)slbv_context.p_hdr->copy_address, (const void*)slbv_context.p_hdr + slbv_context.p_hdr->fimware_start_offset, slbv_context.p_hdr->secure_appli_image_size - sizeof(t_secure_header));
		}
	}
sflv_check_slb_out:
	/** End Of Function */
	return err;
}


/******************************************************************************/
/* End Of file */
