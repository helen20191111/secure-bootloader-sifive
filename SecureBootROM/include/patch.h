/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _PATCH_H_
#define _PATCH_H_

/** Global includes */
#include <stdint.h>
#include <errors.h>
/** Other includes */
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/

/** Enumerations **************************************************************/

/** Structures ****************************************************************/
typedef int(*__sbc_patch_func)(void *p_params1, void *p_param2, void *p_param3);

typedef struct __attribute__((packed))
{
	/** Initialization function */
	int32_t (*initialize_fct)(void *p_ctx, void *p_in, uint32_t length_in);
	/** Shutdown function */
	int32_t (*shutdown_fct)(void *p_ctx);
	/** Read function */
	int32_t (*read_fct)(void *p_ctx, void *p_in, uint32_t length_in, void *p_out, uint32_t *p_length_out);
	/** Write function */
	int32_t (*write_fct)(void *p_ctx, void *p_in, uint32_t length_in, void *p_out, uint32_t *p_length_out);
	/** Generic function 1 */
	int32_t (*gen1_fct)(void *p_ctx, void *p_param1, void *p_param2, void *p_param3, void *p_param4);
	/** Generic function 2 */
	int32_t (*gen2_fct)(void *p_ctx, void *p_param1, void *p_param2, void *p_param3, void *p_param4);
	/** Generic function 3 */
	int32_t (*gen3_fct)(void *p_ctx, void *p_param1, void *p_param2, void *p_param3, void *p_param4);
	/** Generic function 4 */
	int32_t (*gen4_fct)(void *p_ctx, void *p_param1, void *p_param2, void *p_param3, void *p_param4);

} t_api_fcts;


/** Functions *****************************************************************/
int32_t dummy_fct(void *p_ctx, void *p_param1, void *p_param2, void *p_param3, void *p_param4);


#endif /* _PATCH_H_ */
