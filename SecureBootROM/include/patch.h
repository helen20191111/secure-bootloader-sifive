/** patch.h */
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
