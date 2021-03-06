/** sbrm_private.c */
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
#include <stdint.h>
#include <string.h>
#include <errors.h>
#include <otp_mapping.h>
#include <soscl_selftests.h>
#include <soscl_retdefs.h>
/** Other includes */
#include <km_public.h>
#include <pi_public.h>
#include <ppm_public.h>
#include <sp_public.h>
#include <slbv_public.h>
/** Local includes */
#include <sbrm_public.h>


/** External declarations */
extern t_context context;
extern volatile t_sbrm_context sbrm_context;
/** Local declarations */

/******************************************************************************/
void sbrm_set_power_mode(uint32_t power_mode)
{
	/** Not yet integrated - may be platform dependent */
	switch( power_mode )
	{
		case 0:
			/**  */
			break;
		default:
			/** Shutdown mode */
			break;
	}
	/** End Of Function */
	return;
}

/******************************************************************************/
int32_t sbrm_selftest(t_context *p_ctx)
{
#ifdef _WITHOUT_SELFTESTS_
	return NO_ERROR;
#else
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto sbrm_selftest_out;
	}
	/** Call ECDSA selftest */
	err = soscl_ecdsa_p384r1_sha384_selftest();
	if ( SCL_OK != err )
	{
		/** ECDSA tests failed, can't trust platform */
		err = N_SBRM_ERR_ECDSA_TEST_FAILURE;
	}
	else
	{
		/** No error */
		err = NO_ERROR;
	}
sbrm_selftest_out:
	/** End Of Function */
	return err;
#endif /* _WITHOUT_SELFTESTS_ */
}

/******************************************************************************/
int32_t sbrm_compute_crc(uint32_t *p_crc, uint8_t *p_data, uint32_t size)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									tmp = 0;
	uint32_t									i;

	/** Check input pointer */
	if( !p_crc || !p_data )
	{
		/** Pointers should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !size )
	{
		/** There should be some data to process */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Process data */
		tmp = ~*p_crc;
		/** Computation loop */
		for( i = 0;i < size;i++ )
		{
			/**  */
			tmp = ( tmp >> 8 ) ^ sbrm_context.crc_ref_table[( tmp & 0xff ) ^ p_data[i]];
		}
		/** Set CRC */
		*p_crc = ~tmp;
		/** No error */
		err = NO_ERROR;
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/

/* End Of File */
