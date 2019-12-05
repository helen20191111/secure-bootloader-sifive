/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */


/** Global includes */
#include <stdio.h>
#include <stddef.h>
#include <common.h>
#include <errors.h>
#include <patch.h>
/** Other includes */
#include <scl_hash_sha384.h>
#include <km_public.h>
#include <pi_public.h>
#include <ppm_public.h>
#include <sbrm_public.h>
#include <sbrm_internal.h>
#include <sp_public.h>
#include <sp_internal.h>
#include <slbv_public.h>
#include <otp_mapping.h>
/** Local includes */


/** External declarations */
extern t_api_fcts km_fct_ptr;
extern t_api_fcts ppm_fct_ptr;
extern t_api_fcts sbrm_fct_ptr;
extern t_api_fcts slbv_fct_ptr;
extern t_api_fcts sp_fct_ptr;
/** Local declarations */
__attribute__((section(".bss"),aligned(0x10))) uint32_t scl_work_buffer[C_CRYPTO_LIB_BUFFER_SIZE_INT];
__attribute__((section(".bss"),aligned(0x10))) scl_sha384_ctx_t hash_ctx;
__attribute__((section(".bss"))) volatile t_context context;

/******************************************************************************/
int32_t dummy_fct(void *p_ctx, void *p_param1, void *p_param2, void *p_param3, void *p_param4)
{
	/** End Of Function */
	return NO_ERROR;
}

/******************************************************************************/
int32_t context_initialization(t_context *p_ctx)
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
		/** Assigning function pointers tables */
		p_ctx->p_km_fct_ptr = (t_api_fcts*)&km_fct_ptr;
		p_ctx->p_ppm_fct_ptr = (t_api_fcts*)&ppm_fct_ptr;
		p_ctx->p_sbrm_fct_ptr = (t_api_fcts*)&sbrm_fct_ptr;
		p_ctx->p_slbv_fct_ptr = (t_api_fcts*)&slbv_fct_ptr;
		p_ctx->p_sp_fct_ptr = (t_api_fcts*)&sp_fct_ptr;
		/** Assignment for data pointers */
		p_ctx->p_scl_work_buffer = (volatile void*)scl_work_buffer;
		p_ctx->scl_work_buffer_size = sizeof(scl_work_buffer);
		p_ctx->p_scl_hash_ctx = (volatile void*)&hash_ctx;
		/** No error */
		err = NO_ERROR;
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t main(void)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check SBR CRC */
	err = sbrm_check_rom_crc();
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Initialize internal context and parameters */
	err = context_initialization((t_context*)&context);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Initialize SBRM module */
	err = context.p_sbrm_fct_ptr->initialize_fct((void*)&context, NULL, 0);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Initialize SP module */
	err = context.p_sp_fct_ptr->initialize_fct((void*)&context, NULL, 0);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Initialize KM module */
	err = context.p_km_fct_ptr->initialize_fct((void*)&context, NULL, 0);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Perform self-tests */
	err = sbrm_selftest((t_context*)&context);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Check and set signing keys, retrieve CSK if any */
	km_check_key((t_context*)&context);
	/** Retrieve platform life cycle */
	err = ppm_get_life_cycle();
	if ( err )
	{
		/** Return value is not null thus error */
	}
	/** Treat platform life cycle */
	err = ppm_manage_life_cycle((t_context*)&context);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Depending on return value, perform specific action */
	}
	/** It should not go by here */
	while( 1 );
main_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
/* End Of File */
