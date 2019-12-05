/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _PPM_PUBLIC_H_
#define _PPM_PUBLIC_H_

/** Global includes */
#include <stddef.h>
#include <errors.h>
#include <common.h>
/** Other includes */
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
/** PPM errors base */
#define C_PPM_BASE_ERROR        				( N_PREFIX_PPM << C_PREFIX_OFFSET )

#define	C_PPM_LIFECYCLE_PATTERN_SIZE_INBYTES	( 2 * sizeof(uint32_t) )

/** Prefix of Life Cycle Pattern */
#define	C_PPM_LIFECYCLE_PATTERN_PHASE_PFX_IDX	1
#define	C_PPM_LIFECYCLE_PATTERN_PHASE_PFX		0x51F17E1C
/** Suffix of Life Cycle Pattern */
#define	C_PPM_LIFECYCLE_PATTERN_PHASE_SFX_IDX	0
#define	C_PPM_LIFECYCLE_PATTERN_PHASE1_SFX		0xF131D001
#define	C_PPM_LIFECYCLE_PATTERN_PHASE2_SFX		0xDEAD0002

#define	C_PPM_LIFECYCLE_PATTERN_VIRGIN			C_PATTERN_VIRGIN_32BITS

/** Enumerations **************************************************************/
typedef enum
{
	/**  */
	N_PPM_PHASE_MIN = 0,
	N_PPM_PHASE_0 = N_PPM_PHASE_MIN,
	N_PPM_PHASE_1,
	N_PPM_PHASE_2,
	N_PPM_PHASE_U,
	N_PPM_PHASE_MAX = N_PPM_PHASE_U,
	N_PPM_PHASE_COUNT

} e_ppm_phase;

typedef enum
{
	/**  */
	N_PPM_ERR_MIN = C_PPM_BASE_ERROR,
	N_PPM_ERR_NO_LIFECYCLE_PATTERN,
	N_PPM_ERR_,
	N_PPM_ERR_MAX = N_PPM_ERR_,
	N_PPM_ERR_COUNT

} e_ppm_error;


/** Structures ****************************************************************/
typedef struct
{
	/** Platform phase */
	e_ppm_phase									lifecycle_phase;
	/** RMA Mode enabled ? */
	uint8_t										rma_enable;

} t_ppm_context;

/** Functions *****************************************************************/
int32_t ppm_init(void *p_ctx, void *p_in, uint32_t length_in);
int32_t ppm_shutdown(void *p_ctx);
int32_t ppm_get_life_cycle(void);
int32_t ppm_manage_life_cycle(t_context *p_ctx);



/** Macros ********************************************************************/

#endif /* _PPM_PUBLIC_H_ */

/******************************************************************************/
/* End Of File */
