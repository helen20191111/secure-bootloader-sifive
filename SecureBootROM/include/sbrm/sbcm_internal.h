/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SBRM_SBRM_INTERNAL_H_
#define SBRM_SBRM_INTERNAL_H_

/** Global includes */
#include <memory.h>
#include <common.h>
#include <errors.h>
#include <metal/cpu.h>
/** Other includes */
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/

/** Enumerations **************************************************************/


/** Structures ****************************************************************/


/** Functions *****************************************************************/
void sbrm_set_power_mode(uint32_t power_mode);
int32_t sbrm_selftest(t_context *p_ctx);
int32_t sbrm_compute_crc(uint32_t *p_crc, uint8_t *p_data, uint32_t size);

/** Macros ********************************************************************/



#endif /* SBRM_SBRM_INTERNAL_H_ */

/******************************************************************************/
/* End Of File */
