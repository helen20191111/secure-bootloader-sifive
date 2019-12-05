/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _PPM_INTERNAL_H_
#define _PPM_INTERNAL_H_

/** Global includes */
/** Other includes */
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/

/** Enumerations **************************************************************/

/** Structures ****************************************************************/

/** Functions *****************************************************************/
int32_t ppm_process_phase0(t_context *p_ctx);
int32_t ppm_rma_mode(t_context *p_ctx);
int32_t ppm_process_phase1(t_context *p_ctx);
int32_t ppm_process_phaseu(t_context *p_ctx);


/** Macros ********************************************************************/

#endif /* _PPM_INTERNAL_H_ */

/******************************************************************************/
/* End Of File */
