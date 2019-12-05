/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _ERRORS_H_
#define _ERRORS_H_

/** Global includes */
/** Other includes */
/** Local includes */


/** Defines *******************************************************************/
#define C_PREFIX_OFFSET							24
/** Enumeration ***************************************************************/

typedef enum
{
	/**  */
	N_PREFIX_MIN = 0,
	N_PREFIX_GENERIC,
	N_PREFIX_SP,
	N_PREFIX_PPM,
	N_PREFIX_SBRM,
	N_PREFIX_SLBV,
	N_PREFIX_KM,
	N_PREFIX_PI,
	N_PREFIX_DAIM,
	N_PREFIX_MAX = N_PREFIX_DAIM,

} e_sbc_prefix_errors;

/** SP errors base */
#define C_GENERIC_BASE_ERROR        				( N_PREFIX_GENERIC << C_PREFIX_OFFSET )

typedef enum
{
	/**  */
	NO_ERROR = 0,
	/**  */
	N_SBR_ERR_MIN = C_GENERIC_BASE_ERROR,
	GENERIC_ERR_INVAL,
	GENERIC_ERR_OUT_OF_RANGE,
	GENERIC_ERR_NULL_PTR,
	GENERIC_ERR_CRITICAL,
	GENERIC_ERR_NOT_SUPPORTED,
	GENERIC_ERR_RESET,
	GENERIC_ERR_SHUTDOWN,
	GENERIC_ERR_UNKNOWN,
	N_SBR_ERR_MAX = GENERIC_ERR_UNKNOWN,

} e_sbc_errors;

/** Structures ****************************************************************/

/** Macros ********************************************************************/


#endif /* _ERRORS_H_ */
