/** ppm_private.h */
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
