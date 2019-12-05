/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */


/** Global includes */
#include <errors.h>
#include <common.h>
/** Other includes */
#include <otp_mapping.h>
#include <sp_public.h>
#include <sbrm_public.h>
#include <slbv_public.h>
/** Local includes */
#include <ppm_public.h>
#include <ppm_internal.h>

/** External declarations */
extern t_ppm_context ppm_context;
/** Local declarations */


/******************************************************************************/
int32_t ppm_process_phase0(t_context *p_ctx)
{
	/** Call secure protocol function */
	/** End Of Function */
	return sp_launch_sup(p_ctx, N_SP_KEY_STK);
}


/******************************************************************************/


/******************************************************************************/
int32_t ppm_rma_mode(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									rma_mode = 0;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Read register to check for RMA boot mode */
		rma_mode = *((uint32_t*)M_GET_OTP_ABSOLUTE_ADDR((t_context)*p_ctx, C_OTP_MAPPING_RMA_MODE_OFST));
		if( C_OTP_RMA_MODE_PATTERN == rma_mode )
		{
			/** RMA mode enabled */
			ppm_context.rma_enable = TRUE;
		}
		else
		{
			/** RMA_mode disabled */
			ppm_context.rma_enable = FALSE;
		}
		err = NO_ERROR;
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t ppm_process_phase1(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input parameter */
	if ( !p_ctx )
	{
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Check if RMA mode is asked */
		ppm_rma_mode(p_ctx);
		if ( TRUE == ppm_context.rma_enable )
		{
			/** SUP session with UID */
			/** Call secure procedure function */
			err = sp_launch_sup(p_ctx, N_SP_KEY_SSK_CSK_UID);
		}
		else
		{
			/** SUP session without UID */
			err = sp_launch_sup(p_ctx, N_SP_KEY_SSK_CSK);
		}
		/** Check returned value */
		if ( N_SP_ERR_RESET_PLATFROM == err )
		{
			/** Reset platform immediately */
			sbrm_platform_reset(p_ctx);
			/** Wait for reset */
		}
		else if ( N_SP_ERR_SHUTDOWN_PLATFROM == err )
		{
			/** Set platform in shutdown mode immediately */
			sbrm_shutdown(p_ctx);
		}
		else
		{
			/** Enter SLB check and launch procedure if no specific error is returned */
			err = slbv_process((t_context*)p_ctx);
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t ppm_process_phaseu(t_context *p_ctx)
{
	/** Call secure protocol function */
	/** End Of Function */
	return sp_launch_sup(p_ctx, N_SP_KEY_SSK_CSK_UID);
}

/******************************************************************************/
/* End Of File */
