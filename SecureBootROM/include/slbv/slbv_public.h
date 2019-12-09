/** slbc_public.h */
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

#ifndef _SFLV_PUBLIC_H_
#define _SFLV_PUBLIC_H_

/** Global includes */
#include <stdint.h>
/** Other includes */
#include <common.h>
#include <errors.h>
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
#define C_SLBV_BASE_ERROR        					( N_PREFIX_SLBV << C_PREFIX_OFFSET )

#define	C_SEC_HDR_ADDRESS_SIZE_32BITS			0x0101
#define	C_SEC_HDR_ADDRESS_SIZE_64BITS			0x4e4e
#define	C_SEC_HDR_ADDRESS_SIZE_128BITS			0xb2b2

/** Enumerations **************************************************************/
typedef enum
{
	/**  */
	N_SLBV_ERR_MIN = C_SLBV_BASE_ERROR,
	N_SLBV_ERR_SYNC_PTRN_FAILURE = N_SLBV_ERR_MIN,
	N_SLBV_ERR_NOT_VIRGIN,
	N_SLBV_ERR_NO_FREE_LOCATION,
	N_SLBV_ERR_NO_CSK_AVIALABLE,
	N_SLBV_ERR_INVALID_SIGNATURE,
	N_SLBV_ERR_ALGO_NOT_SUPPORTED,
	N_SLBV_ERR_WRONG_KEY_SIZE,
	N_SLBV_ERR_INVAL,
	N_SLBV_ERR_APPLI_TYPE_NOT_SUPPORTED,
	N_SLBV_ERR_VERSION_MISMATCH,
	N_SLBV_ERR_HDR_VERSION_MISMATCH,
	N_SLBV_ERR_ADDR_SIZE_NOT_SUPPORTED,
	N_SLBV_ERR_CRYPTO_FAILURE,
	N_SLBV_ERR_NO_APP_REF_VERSION,
	N_SLBV_ERR_NO_BOOT_ADDRESS,
	N_SLBV_ERR_,
	N_SLBV_ERR_MAX = N_SLBV_ERR_,
	N_SLBV_ERR_COUNT

} e_slbv_error;

/** Structures ****************************************************************/
typedef int32_t (*__fct_ptr_entry32)(void);
typedef int64_t (*__fct_ptr_enrty64)(void);

#ifdef _WITH_128BITS_ADDRESSING_
typedef intmax_t (*__fct_ptr_enrty128)(void);
#endif /* _WITH_128BITS_ADDRESSING_ */

typedef struct
{
	/** Does application need decryption ? */
	uint8_t										decryption;
	/** Reference firmware version */
	uint32_t									ref_appli_version;
	/** Pointer on header */
	volatile t_secure_header					*p_hdr;
	/** Function pointer */
	void										(*jump_fct_ptr)(void);
	/** Boot address : where to read header of binary image */
	volatile uintmax_t							boot_addr;


} t_slbv_context;

/** Functions *****************************************************************/
int32_t slbv_init(void *p_ctx, void *p_in, uint32_t length_in);
int32_t slbv_shutdown(void *p_ctx);
int32_t slbv_process(t_context *p_ctx);
int32_t	sflv_get_boot_address(t_context *p_ctx, uintmax_t *p_addr);
int32_t sflv_get_application_version(t_context *p_ctx, uint32_t *p_version);
int32_t sflv_check_slb(t_context *p_ctx);

/** Macros ********************************************************************/

#endif /* _SFLV_PUBLIC_H_ */

/******************************************************************************/
/* End Of File */
