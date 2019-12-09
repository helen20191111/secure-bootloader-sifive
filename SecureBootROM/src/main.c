/** main.c */
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
#include <stddef.h>
#include <common.h>
#include <errors.h>
#include <patch.h>
/** Other includes */
#include <soscl_hash_sha384.h>
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
__attribute__((section(".bss"),aligned(0x10))) uint32_t soscl_work_buffer[C_CRYPTO_LIB_BUFFER_SIZE_INT];
__attribute__((section(".bss"),aligned(0x10))) soscl_sha384_ctx_t hash_ctx;
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
		p_ctx->p_soscl_work_buffer = (volatile void*)soscl_work_buffer;
		p_ctx->soscl_work_buffer_size = sizeof(soscl_work_buffer);
		p_ctx->p_soscl_hash_ctx = (volatile void*)&hash_ctx;
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
