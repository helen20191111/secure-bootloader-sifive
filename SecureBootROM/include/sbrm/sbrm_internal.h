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
