/** ppm_public.c */
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
#include <stdint.h>
#include <errors.h>
#include <otp_mapping.h>
/** Other includes */
#include <km_public.h>
#include <pi_public.h>
#include <ppm_public.h>
#include <sp_public.h>
#include <slbv_public.h>
#include <sbrm_public.h>
/** Local includes */
#include <ppm_public.h>
#include <ppm_internal.h>

/** External declarations */
extern t_context context;
/** Local declarations */
__attribute__((section(".bss"))) volatile t_ppm_context ppm_context;
__attribute__((section(".data.patch.table"))) t_api_fcts ppm_fct_ptr =
{
		.initialize_fct = ppm_init,
		.shutdown_fct = ppm_shutdown,
		.read_fct = dummy_fct,
		.write_fct = dummy_fct,
		.gen1_fct = dummy_fct,
		.gen2_fct = dummy_fct,
		.gen3_fct = dummy_fct,
		.gen4_fct = dummy_fct,
};


/******************************************************************************/
int32_t ppm_init(void *p_ctx, void *p_in, uint32_t length_in)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input parameter */
	if ( NULL == p_ctx )
	{
		/** Input pointer is null, not good */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		t_context								*p_context = (t_context*)p_ctx;
		/** Initialize context structure */
		memset((void*)&ppm_context, 0x00, sizeof(t_ppm_context));
		/** Always initialize life cycle pattern to "unknown" */
		ppm_context.lifecycle_phase = N_PPM_PHASE_U;
		/** Assign context structure pointer */
		p_context->p_ppm_context = (volatile void*)&ppm_context;
		/** No error */
		err = NO_ERROR;
	}
	/** End of function */
	return err;
}

/******************************************************************************/
int32_t ppm_shutdown(void *p_ctx)
{
	/** End Of Function */
	return NO_ERROR;
}


/******************************************************************************/
int32_t ppm_get_life_cycle(void)
{
	uint8_t										i;
	int32_t										err = GENERIC_ERR_NULL_PTR;
	uint32_t									tmp[( C_OTP_MAPPING_PHASE_ELMT_SIZE / sizeof(uint32_t) )];


	/** Initialize platform phase value */
	ppm_context.lifecycle_phase = N_PPM_PHASE_U;
	/** Initialize work buffer */
	memset((void*)tmp, 0x00, sizeof(tmp));
	/** Loop until finding the appropriate platform's phase */
	for( i = ( ( C_OTP_MAPPING_PHASE_SIZE / C_OTP_MAPPING_PHASE_ELMT_SIZE ) - 1 );i >= 0;i-- )
	{
		/** Read OTP to look for Life Cycle magic word */
		memcpy((void*)tmp, (const void*)M_GET_OTP_ABSOLUTE_ADDR(context, C_OTP_MAPPING_PHASE_OFFSET + ( i * C_OTP_MAPPING_PHASE_ELMT_SIZE )), C_OTP_MAPPING_PHASE_ELMT_SIZE);
		/**  */
		if ( ( 0 < i ) &&
			( C_PPM_LIFECYCLE_PATTERN_PHASE_PFX == tmp[C_PPM_LIFECYCLE_PATTERN_PHASE_PFX_IDX] ) &&
			( C_PPM_LIFECYCLE_PATTERN_PHASE2_SFX == tmp[C_PPM_LIFECYCLE_PATTERN_PHASE_SFX_IDX] ) )
		{
			/** Phase#2, platform must be shutdown */
			ppm_context.lifecycle_phase = N_PPM_PHASE_2;
			goto ppm_get_life_cycle_out;

		}
		else if ( ( C_PPM_LIFECYCLE_PATTERN_VIRGIN == tmp[C_PPM_LIFECYCLE_PATTERN_PHASE_PFX_IDX] ) &&
					( C_PPM_LIFECYCLE_PATTERN_VIRGIN == tmp[C_PPM_LIFECYCLE_PATTERN_PHASE_SFX_IDX] ) )
		{
			/** Virgin line */
			if ( 0 == i )
			{
				/** No Phase#1 then Phase#0 */
				err = NO_ERROR;
				ppm_context.lifecycle_phase = N_PPM_PHASE_0;
				goto ppm_get_life_cycle_out;
			}
			else
			{
				/** Keep on searching */
				continue;
			}
		}
		else if ( ( 0 == i ) &&
				( C_PPM_LIFECYCLE_PATTERN_PHASE_PFX == tmp[C_PPM_LIFECYCLE_PATTERN_PHASE_PFX_IDX] ) &&
				( C_PPM_LIFECYCLE_PATTERN_PHASE1_SFX == tmp[C_PPM_LIFECYCLE_PATTERN_PHASE_SFX_IDX] ) )
		{
			/** Phase#1 then */
			err = NO_ERROR;
			ppm_context.lifecycle_phase = N_PPM_PHASE_1;
			goto ppm_get_life_cycle_out;
		}
		else
		{
			/** Should not be there */
			err = N_PPM_ERR_NO_LIFECYCLE_PATTERN;
			ppm_context.lifecycle_phase = N_PPM_PHASE_U;
			goto ppm_get_life_cycle_out;
		}
	}
ppm_get_life_cycle_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t ppm_manage_life_cycle(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_NULL_PTR;

	/** Choose what to do depending on platform's life cycle */
	switch( ppm_context.lifecycle_phase )
	{
		case N_PPM_PHASE_0:
			/** SUP with STK */
			err = ppm_process_phase0(p_ctx);
			break;
		case N_PPM_PHASE_1:
			/** SUP with SSK/CSK and SLB launch */
			err = ppm_process_phase1(p_ctx);
			break;
		case N_PPM_PHASE_2:
			/** Platform must be shutdown as soon as possible */
			/** Go to shutdown mode */
			sbrm_shutdown(p_ctx);
			err = GENERIC_ERR_CRITICAL;
			break;
		default:
			/** Unknown phase, therefore only SUP+UID with SSK/CSK */
			err = ppm_process_phaseu(p_ctx);
			break;
	}
	/** End Of Function */
	return err;
}


/******************************************************************************/
/* End Of File */
