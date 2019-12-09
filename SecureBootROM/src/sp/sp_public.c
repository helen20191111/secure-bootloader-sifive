/** sp_public.c */
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
#include <stdint.h>
#include <string.h>
#include <metal.h>
#include <metal-platform.h>
#include <metal/cpu.h>
#include <errors.h>
#include <common.h>
#include <patch.h>
/** Other includes */
#include <soscl_retdefs.h>
#include <soscl_hash_sha384.h>
/** Local includes */
#include <sp_public.h>
#include <sp_internal.h>

/** External declarations */
extern t_sp_context sp_context;
/** Local declarations */
__attribute__((section(".data.patch.table"))) t_api_fcts sp_fct_ptr =
{
		.initialize_fct = sp_init,
		.shutdown_fct = sp_shutdown,
		.read_fct = dummy_fct,
		.write_fct = dummy_fct,
		.gen1_fct = sp_launch_sup,
		.gen2_fct = dummy_fct,
		.gen3_fct = dummy_fct,
		.gen4_fct = dummy_fct,
};


/******************************************************************************/
int32_t sp_init(void *p_ctx, void *p_in, uint32_t length_in)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		t_context								*p_context = (t_context*)p_ctx;
		volatile t_sbrm_context					*p_sbrm_ctx;

		/** Get SBRM context to have CPU info */
		p_sbrm_ctx = (volatile t_sbrm_context*)p_context->p_sbrm_context;
		/** Initialize internal structure */
		memset((void*)&sp_context, 0x00, sizeof(t_sp_context));
		/** Then set structure parameters */
		sp_context.sup.mode = N_SP_MODE_RMA;
		sp_context.sup.key_id = N_KM_KEYID_CSK;
		sp_context.sup.first_pkt = TRUE;
		sp_context.csk_last_slot = FALSE;
		/** Local context structure assignment */
		p_context->p_sp_context = (volatile void*)&sp_context;
		/** Initialization of communication structure */
		/** Initialization of port structure */
		sp_context.port.uart.reg_uart = (volatile t_reg_uart*)METAL_SIFIVE_UART0_0_BASE_ADDRESS;
		sp_context.port.uart.uart0 = (struct metal_uart *)__METAL_DT_SERIAL_20000000_HANDLE;
		/** Set up interruption for UART0 */
		sp_context.port.uart.uart0_ic = metal_uart_interrupt_controller(sp_context.port.uart.uart0);
	    if( NULL == sp_context.port.uart.uart0_ic )
	    {
	        err = N_SP_ERR_SUP_CANT_RETRIEVE_IRQ_PTR;
	    }
	    else
	    {
	    	metal_interrupt_init(sp_context.port.uart.uart0_ic);
#ifdef _WITH_UART_WORKAROUND_
	    	sp_context.port.uart.uart0_irq = 0x10;
#else
	    	sp_context.port.uart.uart0_irq = metal_uart_get_interrupt_id(sp_context.port.uart.uart0);
#endif /* _WITH_UART_WORKAROUND_ */
			/** Register UART0 interruption handler */
			err = metal_interrupt_register_handler(sp_context.port.uart.uart0_ic, sp_context.port.uart.uart0_irq, (metal_interrupt_handler_t)sp_uart_isr, (void*)&sp_context);
			if( err )
			{
				err = N_SP_ERR_SUP_CANT_REGISTER_IRQ_HANDLER;
			}
			else
			{
				/** Be sure to disable UART interruptions first */
				sp_context.port.uart.reg_uart->ie = 0;
			    /**  */
			    err = metal_uart_receive_interrupt_enable(sp_context.port.uart.uart0);
			    if( err )
			    {
			        goto sp_init_out;
			    }
			    /**  */
			    err = metal_interrupt_enable(sp_context.port.uart.uart0_ic, sp_context.port.uart.uart0_irq);
			    if( err )
			    {
			        goto sp_init_out;
			    }
			    /** Lastly CPU interrupt */
			    err = metal_interrupt_enable(p_sbrm_ctx->p_cpu_intr, 0);
			    if( err )
			    {
			        goto sp_init_out;
			    }
				/** No error */
				err = NO_ERROR;
				/**  */
			}
	    }
	}
sp_init_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_shutdown(void *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		t_context								*p_context = (t_context*)p_ctx;

		memset((void*)&sp_context, 0x00, sizeof(t_sp_context));
		p_context->p_sp_context = (volatile void*)NULL;
		/** No error */
		err = NO_ERROR;
	}
	/**  */
	return err;
}

/******************************************************************************/
int32_t sp_launch_sup(t_context *p_ctx, e_sp_key_session key_session)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto sp_launch_sup_out;
	}
	/** Depending on 'key_session' */
	switch( key_session )
	{
		case N_SP_KEY_STK:
			sp_context.sup.mode = N_SP_MODE_NORMAL;
			sp_context.sup.key_id = N_KM_KEYID_CSK;
			break;
		case N_SP_KEY_STK_UID:
			sp_context.sup.mode = N_SP_MODE_RMA;
			break;
		case N_SP_KEY_SSK_CSK:
			sp_context.sup.mode = N_SP_MODE_NORMAL;
			sp_context.sup.key_id = N_KM_KEYID_CSK;
			break;
		case N_SP_KEY_SSK_CSK_UID:
			sp_context.sup.mode = N_SP_MODE_RMA;
			sp_context.sup.key_id = N_KM_KEYID_CSK;
			break;
		default:
			/** Session key is not known */
			err = GENERIC_ERR_NOT_SUPPORTED;
			goto sp_launch_sup_out;
	}
	/** Check stimulus */
	err = sp_check_stimulus(p_ctx);
	if( err )
	{
		/** SUP session cannot be opened */
		err = NO_ERROR;
	}
	else
	{
		/** Ok, then open bus to enable SUP communication */
		err = sp_sup_initialize_communication(p_ctx);
		if ( NO_ERROR == err )
		{
			/** Now wait for communication to start */
			err = sp_sup_open_communication(p_ctx);
			/** Close communication - no return value, keep the one from communication */
			sp_sup_close_communication(p_ctx);
		}
	}
	/**  */
sp_launch_sup_out:
	/** End Of function */
	return err;
}

/******************************************************************************/
/** End Of File */
