/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */



/** Global includes */
#include <string.h>
#include <common.h>
#include <errors.h>
#include <otp_mapping.h>
#include <metal/gpio.h>
/** Other includes */
#include <soscl_retdefs.h>
#include <soscl_ecc.h>
#include <soscl_hash_sha384.h>
#include <soscl_ecdsa.h>
#include <km_public.h>
#include <sbrm_internal.h>
/** Local includes */
#include <sp_public.h>
#include <sp_internal.h>

/** External declarations */
extern t_context context;
extern soscl_type_curve soscl_secp384r1;
extern uint32_t __sbrm_free_start_addr;
extern uint32_t __sbrm_free_end_addr;
/** Local declarations */
__attribute__((section(".bss"))) t_sp_context sp_context;
__attribute__((section(".bss"))) t_sp_sup_rx_pckt_hdr sp_sup_rx_hdr;
__attribute__((section(".bss"))) t_sp_sup_tx_pckt_hdr sp_sup_tx_hdr;
__attribute__((section(".bss"))) t_dummy_buffer dummy;
/** Array for key buffer
* Size is Old CSK descriptor + Old CSK size max + CSK Descriptor + CSK size Max + CSK sign size max */
__attribute__((section(".bss"))) uint8_t work_buf[M_WHOIS_MAX(C_KM_KEY_BUFFER_MAX_SIZE, sizeof(t_cmd_csk))];

/** UART **********************************************************************/
/******************************************************************************/
void sp_uart_isr(int32_t id, void *data)
{
	volatile uint32_t							counter = C_UART_DATA_MAX_THRESHOLD_RX;
	volatile uint32_t							tmp_rx = 0;
	uint32_t									*p_cnt;
	uint32_t									*p_idx;
	uint8_t										*p_dst;

	/** Pre-treatment */
	/** Are we in dummy mode ? */
	if( TRUE == sp_context.communication.dummy_mode )
	{
		/** Dummy mode */
		/** Point on local counter */
		p_cnt = (uint32_t*)&counter;
		/** Point on dummy index */
		p_idx = (uint32_t*)&dummy.index;
		/** Point on dummy buffer */
		p_dst = (uint8_t*)dummy.buffer;
	}
	else
	{
		/** Normal mode */
		/** Point on context counter */
		p_cnt = (uint32_t*)&sp_context.communication.lasting;
		/** Point on context index */
		p_idx = (uint32_t*)&sp_context.communication.received;
		/** Point on context buffer */
		p_dst = (uint8_t*)sp_context.communication.p_data;
	}
	/** Be sure to receive what is expected */
	while( ( !( (tmp_rx = sp_context.port.uart.reg_uart->rx ) & C_UART_RXDATA_EMPTY_MASK ) ) && *p_cnt )
	{
		/** Get data */
		p_dst[*p_idx] = (uint8_t)tmp_rx;
		/** Update lasting counter */
		(*p_cnt)--;
		/** Update incoming counter */
		(*p_idx)++;
		/** Dummy mode special case */
		if( TRUE == sp_context.communication.dummy_mode )
		{
			dummy.index %= C_SP_SUP_DUMMY_BUFFER_SIZE;
		}
	}
	/** Post-treatment */
	if( TRUE == sp_context.communication.dummy_mode )
	{
		/** Keep on receiving */
	}
	else
	{
		/** Mask interruption */
//		M_UART_RX_DISABLE(sp_context.port.uart.reg_uart);
		M_UART_MASK_RX_IRQ(sp_context.port.uart.reg_uart);
		/** Remove threshold value */
		sp_context.port.uart.reg_uart->rx_ctrl &= ~C_UART_RXCTRL_RXCNT_MASK;
		/** Recompute threshold */
		if( !sp_context.communication.lasting )
		{
			/** Put threshold to its maximum value */
			sp_context.port.uart.reg_uart->rx_ctrl |= ( ( ( C_UART_DATA_MAX_THRESHOLD_RX - 1 ) << C_UART_RXCTRL_RXCNT_OFST ) & C_UART_RXCTRL_RXCNT_MASK );
			/** Store data in dummy buffer - don't care about return value here */
			/** Indicate dummy mode is active */
			sp_context.communication.dummy_mode = TRUE;
		}
		else if( C_UART_DATA_MAX_THRESHOLD_RX > sp_context.communication.lasting )
		{
			sp_context.port.uart.reg_uart->rx_ctrl |= ( ( ( sp_context.communication.lasting - 1 ) << C_UART_RXCTRL_RXCNT_OFST ) & C_UART_RXCTRL_RXCNT_MASK );
			/** Indicate dummy mode is inactive */
			sp_context.communication.dummy_mode = FALSE;
		}
		else
		{
			sp_context.port.uart.reg_uart->rx_ctrl |= ( ( ( C_UART_DATA_MAX_THRESHOLD_RX - 1 ) << C_UART_RXCTRL_RXCNT_OFST ) & C_UART_RXCTRL_RXCNT_MASK );
			/** Indicate dummy mode is inactive */
			sp_context.communication.dummy_mode = FALSE;
		}
		/** Unmask interruption */
//		M_UART_RX_ENABLE(sp_context.port.uart.reg_uart);
		M_UART_UNMASK_RX_IRQ(sp_context.port.uart.reg_uart);
	}
	/** End Of Function */
	return;
}

/******************************************************************************/
int32_t sp_uart_receive_buffer(t_context *p_ctx, uint8_t *p_data, uint32_t *p_size)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									loop;
	uint32_t									i;
	volatile t_sbrm_context						*p_sbrm_ctx;

	/** Check input pointer */
	if( !p_data || !p_ctx || !p_size )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !*p_size )
	{
		/** Input size is null */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Get SBRM context to have CPU info */
		p_sbrm_ctx = (volatile t_sbrm_context*)p_ctx->p_sbrm_context;
		/** First check if there's data in dummy buffer */
		if ( dummy.index )
		{
			/** Some data has been received outside expected RX windows */
			if ( *p_size <= dummy.index )
			{
				/** First mask RX interruption */
				/** Disable interrupt */
//				sp_context.port.uart.reg_uart->ie &= ~( C_UART_IE_TXWM_MASK | C_UART_IE_RXWM_MASK );
				M_UART_MASK_RX_IRQ(sp_context.port.uart.reg_uart);
				M_UART_MASK_TX_IRQ(sp_context.port.uart.reg_uart);
				/** Retrieve data from dummy buffer */
				memcpy((void*)p_data, (const void*)dummy.buffer, *p_size);
				/** Update variables */
				sp_context.communication.lasting = 0;
				sp_context.communication.received = *p_size;
				/** Refresh index */
				dummy.index -= *p_size;
				if( dummy.index )
				{
					/** Move data in dummy buffer */
					memcpy((void*)dummy.buffer, (const void*)&dummy.buffer[*p_size], dummy.index);
				}
				/** Enable interrupt */
//				sp_context.port.uart.reg_uart->ie = C_UART_IE_TXWM_MASK;
				M_UART_UNMASK_RX_IRQ(sp_context.port.uart.reg_uart);
				/** Keep dummy mode */
				sp_context.communication.dummy_mode = TRUE;
				/** We have data so let's get out of here */
				goto sp_uart_receive_buffer_out;
			}
			else if( dummy.index < *p_size )
			{
				/** Disable interrupt */
//				sp_context.port.uart.reg_uart->ie &= ~( C_UART_IE_TXWM_MASK | C_UART_IE_RXWM_MASK );
				M_UART_MASK_RX_IRQ(sp_context.port.uart.reg_uart);
				M_UART_MASK_TX_IRQ(sp_context.port.uart.reg_uart);
				/** Retrieve data from dummy buffer */
				memcpy((void*)p_data, (const void*)dummy.buffer, dummy.index);
				/** Update variables */
				sp_context.communication.lasting = *p_size - dummy.index;
				sp_context.communication.received = dummy.index;
				sp_context.communication.p_data = &p_data[dummy.index];
				/** Dummy mode not expected */
				sp_context.communication.dummy_mode = FALSE;
				/** Then receive lasting data */
			}
		}
		else
		{
			/** No data received in the meantime */
			/** Prepare communication variables */
			sp_context.communication.lasting = *p_size;
			sp_context.communication.received = 0;
			sp_context.communication.p_data = p_data;
			/** Dummy mode not expected */
			sp_context.communication.dummy_mode = FALSE;
		}
//		/** Let's disable TX */
//		M_UART_TX_DISABLE(sp_context.port.uart.reg_uart);
	    /** Lets enable the UART interrupt */
		/** Remove previous threshold value for reception */
		sp_context.port.uart.reg_uart->rx_ctrl &= ~C_UART_RXCTRL_RXCNT_MASK;
		/** Recompute threshold */
		if( C_UART_DATA_MAX_THRESHOLD_RX > sp_context.communication.lasting )
		{
			sp_context.communication.threshold = sp_context.communication.lasting;
		}
		else
		{
			sp_context.communication.threshold = C_UART_DATA_MAX_THRESHOLD_RX;
		}
		sp_context.port.uart.reg_uart->rx_ctrl = ( ( ( sp_context.communication.threshold - 1 ) << C_UART_RXCTRL_RXCNT_OFST ) & C_UART_RXCTRL_RXCNT_MASK );
		/** Enable RX */
//		sp_context.port.uart.reg_uart->rx_ctrl |= C_UART_RXCTRL_RXEN_MASK;
		M_UART_RX_ENABLE(sp_context.port.uart.reg_uart);
		/** Enable interrupt */
//		sp_context.port.uart.reg_uart->ie = C_UART_IE_RXWM_MASK;
		M_UART_UNMASK_RX_IRQ(sp_context.port.uart.reg_uart);
	    /** Wait until reception is over */
	    while ( sp_context.communication.lasting > 0 )
	    {
	    	/** Waiting loop */
	    }
	    /** No error */
	    err = NO_ERROR;
	}
sp_uart_receive_buffer_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_uart_send_buffer(t_context *p_ctx, uint8_t *p_data, uint32_t size)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									security = 2 * size;
	uint32_t									lasting = size;
	volatile uint32_t							tmp = 0;
	register uint32_t							i;
	uint8_t										*p_src = p_data;

	/** Check input pointer */
	if( !p_ctx || !p_data )
	{
		/** Pointers should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !size )
	{
		/** Size should not be null */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Disable RX */
//		M_UART_MASK_RX_IRQ(sp_context.port.uart.reg_uart);
		M_UART_RX_DISABLE(sp_context.port.uart.reg_uart);
		/** Disable interrupt */
		sp_context.port.uart.reg_uart->ie &= ~( C_UART_IE_TXWM_MASK | C_UART_IE_RXWM_MASK );
		/** Enable TX */
		M_UART_TX_ENABLE(sp_context.port.uart.reg_uart);
		/** Sending loop */
//		while( lasting && security );
//		{
//			if( !( C_UART_TXDATA_FULL_MASK & sp_context.port.uart.reg_uart->tx ) )
//			{
//				/** Fill FIFO */
//				sp_context.port.uart.reg_uart->tx = (uint32_t)*p_src;
//				/** Update counter */
//				lasting--;
//				/** Update pointer */
//				p_src++;
//				/** Re-arm security loop */
//				security = 2 * size;
//			}
//			else
//			{
//				/** Decrement security loop */
//				security--;
//			}
//		}
		/**  */
		for( i = 0;i < size; )
		{
			/** Get TX status */
			tmp = (volatile uint32_t)sp_context.port.uart.reg_uart->tx;
			/** Wait for TX FIFO to be not full */
			if( C_UART_TXDATA_FULL_MASK & (uint32_t)tmp )
			{
				/** Wait for TX FIFO not to be full */
			}
			else
			{
				/** Set new character in FIFO */
				sp_context.port.uart.reg_uart->tx = (uint32_t)*p_src;
				/** Update counter */
				lasting--;
				/** Update pointer */
				p_src++;
				/** Re-arm security loop */
				security = 2 * size;
				/** Increment */
				i++;
			}
		}
		/** Check if everything has been sent */
		if( lasting )
		{
			/** Not all of the characters have been sent */
			err = N_SP_ERR_SUP_TX_COMMUNICATION_FAILURE;
		}
		else
		{
			/** All characters have been sent */
			err = NO_ERROR;
		}
	}
	/** End Of Function */
	return err;
}


/******************************************************************************/
int32_t sp_check_stimulus(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	int32_t										level = 0;
	int32_t										slot;
	uint32_t									tmp __attribute__((aligned(0x10)));

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Retrieve from OTP the stimulus */
		for( slot = C_OTP_MAPPING_SUP_STIM_SLOT_MAX;slot >= 0;slot-- )
		{
			/** Read configuration from OTP */
			memcpy((void*)&tmp,
					(const void*)M_GET_OTP_ABSOLUTE_ADDR(*p_ctx, C_OTP_MAPPING_SUP_STIM_AREA_OFST + ( C_OTP_MAPPING_SUP_STIM_ELMNT_SIZE * slot )),
					C_OTP_MAPPING_SUP_STIM_ELMNT_SIZE);
			/** Check if stimulus value has been defined */
			if( C_PATTERN_VIRGIN_32BITS != tmp )
			{
				/** No error */
				err = NO_ERROR;
				/** Fill structure */
				memcpy((void*)&sp_context.stimulus, (const void*)&tmp, sizeof(uint32_t));
				/** Exit condition */
				break;
			}
			else
			{
				/** No configuration */
				err = N_SP_ERR_SUP_BAD_PARAMS;
			}
		}
		/** Set default values if needed */
		if( N_SP_ERR_SUP_BAD_PARAMS == err )
		{
			/** UART0 */
			sp_context.stimulus.bus = ( 0 << C_SP_STIM_BUS_ID_UART_OFST );
			/** GPIO0 - default pin, level high */
			/** Read stimulus - GPIO 0 for now */
			sp_context.stimulus.gpio_bank = 0;
			/** Retrieve pin */
			sp_context.stimulus.pin = C_SUP_STIMULUS_PIN;
			sp_context.stimulus.level = 1;
		}
		/** Retrieve PIO bank base address */
		sp_context.stimulus.gpio = metal_gpio_get_device(sp_context.stimulus.gpio_bank);
		/** Check GPIO */
		level = metal_gpio_get_input_pin((struct metal_gpio*)sp_context.stimulus.gpio, sp_context.stimulus.pin);
		if( level == sp_context.stimulus.level )
		{
			/** SUP session is to be opened */
			err = NO_ERROR;
		}
		else
		{
			/** SUP session is not opened */
			err = N_SP_ERR_SUP_NO_SESSION_ALLOWED;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_get_port_id(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if ( !p_ctx )
	{
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** For now only support UART0 */
		if( !( C_SP_STIM_BUS_ID_UART_MASK & sp_context.stimulus.bus ) )
		{
			/** Read from OTP UART port ID if any */
			sp_context.port.bus_id = N_SBRM_BUSID_MIN;
			/** No error */
			err = NO_ERROR;
		}
		else
		{
			/** Other bus not supported for now */
			err = N_SP_ERR_SUP_COM_PORT_NOT_HANDLED;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_get_port_conf(t_context *p_ctx)
{
	int8_t										slot;
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Read from OTP UART configuration if any */
		for( slot = C_OTP_MAPPING_UART_SLOT_MAX;slot >= 0;slot-- )
		{
			/** Read configuration from OTP */
			memcpy((void*)sp_context.port.config,
					(const void*)M_GET_OTP_ABSOLUTE_ADDR(*p_ctx, C_OTP_MAPPING_UART_AREA_OFST + ( slot * C_OTP_MAPPING_UART_ELMNT_SIZE )),
					C_OTP_MAPPING_UART_ELMNT_SIZE);
			/** Check if baudrate value has been found */
			if( C_PATTERN_VIRGIN_32BITS != sp_context.port.config[C_SP_SUP_PORT_CONF_BAUDRATE_OFST] )
			{
				/** No error */
				err = NO_ERROR;
				break;
			}
			else
			{
				/** No configuration */
				err = N_SP_ERR_SUP_BAD_PARAMS;
			}
		}
		/**  */
		if ( N_SP_ERR_SUP_BAD_PARAMS == err )
		{
			/** Set default values for parameters */
			sp_context.port.config[C_SP_SUP_PORT_CONF_BAUDRATE_OFST] = C_SP_SUP_PORT_CONF_PARAMS0;
			sp_context.port.config[C_SP_SUP_PORT_CONF_PARAMS_OFST] = C_SP_SUP_PORT_CONF_PARAMS1;
			/** No error then */
			err = NO_ERROR;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_check_security(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									i;
	uint32_t									j;
	uint32_t									nb_certificates = 0;
	t_sig_element								*p_signature_element;
	t_km_context								*p_km_ctx;
	t_key_data									*p_key_data;
	e_km_keyid									key_id;
	u_km_key									key;
	soscl_type_ecc_uint8_t_affine_point			Q;
	soscl_type_ecdsa_signature					signature;


	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !p_ctx->p_soscl_hash_ctx )
	{
		/**  */
		err = N_SP_ERR_NOT_INITIALIZED;
	}
	else if( !p_ctx->p_km_context )
	{
		/** KM context pointer should not be null */
		err = GENERIC_ERR_CRITICAL;
	}
	else if( !p_ctx->p_soscl_hash_ctx )
	{
		/** SCL hash structure must not be null */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** KM context is set */
		p_km_ctx = (t_km_context*)p_ctx->p_km_context;
		/** Retrieve information from work buffer */
		if( !sp_context.security.sig_buf )
		{
			/** Should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_sup_check_security_out;
		}
		/** Point on signature element */
		p_signature_element = (t_sig_element*)sp_context.security.sig_buf;
		/** Check the signature(s) ********************************************/
		for( i = 0;i < sp_context.security.nb_signatures;i++ )
		{
			uint32_t							ref_key_size;
			uint8_t								*p_local_signature;
			e_km_keyid							key_id;

			/** For this signature element, retrieve the number of PKChain elements */
			nb_certificates = p_signature_element->nb_certificates;
			/** Point on local signature */
			p_local_signature = sp_context.security.sig_buf +\
								sizeof(t_sig_element) +\
								( nb_certificates * sizeof(t_key_data) );
			/** Special case - no PKChain */
			if ( !nb_certificates )
			{
				/** Only signature by key stored in platform */
				/** Reference key depends on command type */
				if( ( N_SP_SUP_SEGMENT_TYPE_UPDATECSK == sp_context.sup.p_rx_hdr->segment_elmnt.command_type ) ||
					( N_SP_SUP_SEGMENT_TYPE_WRITECSK == sp_context.sup.p_rx_hdr->segment_elmnt.command_type ) )
				{
					/** SSK/CUK is the reference */
					key_id = p_km_ctx->sign_key.id;
				}
				else if( C_OTP_MAPPING_NB_CSK_SLOTS > p_km_ctx->index_valid_csk )
				{
					/** Valid CSK is the reference */
					key_id = N_KM_KEYID_CSK;
				}
				else
				{
					/** This case must not lead to data treatment, thus error */
					err = N_SP_ERR_SUP_NET_UNKNOWN;
					goto sp_sup_check_security_out;

				}
				/** Retrieve which one of SSK, CUK or CSK is to be used */
				/** Retrieve key */
				err = km_get_key(key_id,
									(u_km_key*)&key,
									(uint32_t*)&ref_key_size);
				if( err )
				{
					/** Should not happen */
					err = GENERIC_ERR_CRITICAL;
					goto sp_sup_check_security_out;
				}
				/** Now check signature */
				/** Process hash digest on message */
				/** Initialization */
				err = soscl_sha384_init((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx);
				if( err )
				{
					/** Critical error */
					err = N_SP_ERR_SUP_CRYPTO_FAILURE;
					goto sp_sup_check_security_out;
				}
				/** Header */
				if( sp_context.sup.p_rx_hdr->segment_elmnt.command_length )
				{
					/** 'address' field must be counted */
					err = soscl_sha384_core((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx, (uint8_t*)sp_context.sup.p_rx_hdr, sizeof(t_sp_sup_rx_pckt_hdr));
				}
				else
				{
					/** 'address' field must not be counted, because there's no 'address' field */
					err = soscl_sha384_core((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx, (uint8_t*)sp_context.sup.p_rx_hdr, ( sizeof(t_sp_sup_rx_pckt_hdr) - sizeof(uint32_t) ));
				}
				if( err )
				{
					/** Critical error */
					err = N_SP_ERR_SUP_CRYPTO_FAILURE;
					goto sp_sup_check_security_out;
				}
				/** Real payload, data after 'address' field, is pointed in sp_context.sup.payload.p_data */
				/** Payload if any */
				if( sp_context.sup.p_rx_hdr->segment_elmnt.command_length )
				{
					/** Let's process the real payload - without 'address' field then */
					err = soscl_sha384_core((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx, (uint8_t*)sp_context.sup.payload.p_data, sp_context.sup.payload.size);
					if( err )
					{
						/** Critical error */
						err = N_SP_ERR_SUP_CRYPTO_FAILURE;
						goto sp_sup_check_security_out;
					}
				}
				/** Process security elements now - rawly , remove signature size */
				err = soscl_sha384_core((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx, (uint8_t*)sp_context.security.uid, ( sp_context.security.total_size - ( 2 * C_EDCSA384_SIZE ) ));
				if( err )
				{
					/** Critical error */
					err = N_SP_ERR_SUP_CRYPTO_FAILURE;
					goto sp_sup_check_security_out;
				}
				/** Then finish computation */
				memset((void*)p_ctx->digest, 0x00, C_SP_SUP_HASH_SIZE_IN_BYTES);
				err = soscl_sha384_finish(p_ctx->digest, (soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx);
				if( err )
				{
					/** Critical error */
					err = N_SP_ERR_SUP_CRYPTO_FAILURE;
					goto sp_sup_check_security_out;
				}
				/** Now verify signature */
				/** Set parameters */
				Q.x = key.ecdsa.p_x;
				Q.y = key.ecdsa.p_y;
				signature.r = p_local_signature;
				signature.s = p_local_signature + C_EDCSA384_SIZE;
				/** Call SCL ECDSA verification function */
				err = soscl_ecdsa_verification(Q,
												signature,
												&soscl_sha384,
												p_ctx->digest,
												C_SP_SUP_HASH_SIZE_IN_BYTES,
												&soscl_secp384r1,
												( SCL_HASH_INPUT_TYPE << SCL_INPUT_SHIFT ) ^
												( SCL_SHA384_ID << SCL_HASH_SHIFT ));
				if( err )
				{
					/**  */
					goto sp_sup_check_security_out;
				}
			}
			else
			{
				/** Point on next key element */
				p_key_data = (t_key_data*)( sp_context.security.sig_buf + sizeof(t_sig_element) );
				/** Check PK chain within signature */
				for( j = 0;j < nb_certificates;j++ )
				{
					/** Check algorithm */
					if( ( C_KM_CSK_DESCR_ALGO_ECDSA != p_key_data->algo ) ||
						(  (uint16_t)( 8 * C_EDCSA384_SIZE ) != p_key_data->key_size_bits ) )
					{
						err = GENERIC_ERR_CRITICAL;
						goto sp_sup_check_security_out;
					}
					/** Set signing key */
					if( !j )
					{
						/** Check the reference key */
						if( ( N_KM_KEYID_CUK == p_km_ctx->sign_key.id ) &&
							( C_KM_CSK_DESCR_VERIF_KEY_CUK == p_key_data->sign_key_id ) &&
							( ( N_SP_SUP_SEGMENT_TYPE_UPDATECSK == sp_context.sup.p_rx_hdr->segment_elmnt.command_type ) ||
							( N_SP_SUP_SEGMENT_TYPE_WRITECSK == sp_context.sup.p_rx_hdr->segment_elmnt.command_type ) ) )
						{
						}
						else if( ( N_KM_KEYID_SSK == p_km_ctx->sign_key.id ) &&
								( C_KM_CSK_DESCR_VERIF_KEY_SSK == p_key_data->sign_key_id ) &&
								( ( N_SP_SUP_SEGMENT_TYPE_UPDATECSK == sp_context.sup.p_rx_hdr->segment_elmnt.command_type ) ||
								( N_SP_SUP_SEGMENT_TYPE_WRITECSK == sp_context.sup.p_rx_hdr->segment_elmnt.command_type ) ) )
						{

						}
						else if( ( N_KM_KEYID_CSK == p_km_ctx->sign_key.id ) && ( C_KM_CSK_DESCR_VERIF_KEY_CSK == p_key_data->sign_key_id ) )
						{
						}
						else
						{
							/** Mismatch keys */
							err = N_SP_ERR_SUP_KEY_MISMATCH;
							goto sp_sup_check_security_out;
						}
						/** Retrieve key */
						err = km_get_key(p_km_ctx->sign_key.id,
											(u_km_key*)&key,
											(uint32_t*)&ref_key_size);
						if( err )
						{
							/** Should not happen */
							err = GENERIC_ERR_CRITICAL;
							goto sp_sup_check_security_out;
						}
					}
					else if( C_KM_CSK_DESCR_VERIF_KEY_PREVIOUS == p_key_data->sign_key_id )
					{
						/** Reference key is the previous one - parameter already filled */
					}
					else
					{
						/** Mismatch keys */
						err = N_SP_ERR_SUP_KEY_MISMATCH;
						goto sp_sup_check_security_out;
					}
					/** Then verify certificate */
					err = km_verify_signature((uint8_t*)p_key_data,
												(uint32_t)( ( p_key_data->key_size_bits / 8 ) + sizeof(uint32_t) ),
												(uint8_t*)p_key_data->certificate,
												N_KM_ALGO_ECDSA384,
												key);
					if( err )
					{
						/** Error in cryptographic computation */
						goto sp_sup_check_security_out;
					}
					/** If signature checked is ok, then checked key becomes new reference key */
					key.ecdsa.p_x = p_key_data->key;
					key.ecdsa.p_y = key.ecdsa.p_x + C_EDCSA384_SIZE;
					/** Update pointer to point on next PKChain element*/
					p_key_data += sizeof(t_key_data);
				}
				/** Ok, now PK chain has been verified. Let's verify SUP packet signature with latest PK chain key
				 * 'key' has been updated before */
				/** Process hash digest on message */
				/** Initialization */
				err = soscl_sha384_init((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx);
				if( err )
				{
					/** Critical error */
					err = N_SP_ERR_SUP_CRYPTO_FAILURE;
					goto sp_sup_check_security_out;
				}
				/** Header */
				if( sp_context.sup.p_rx_hdr->segment_elmnt.command_length )
				{
					/** 'address' field must be counted */
					err = soscl_sha384_core((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx, (uint8_t*)sp_context.sup.p_rx_hdr, sizeof(t_sp_sup_rx_pckt_hdr));
				}
				else
				{
					/** 'address' field must not be counted */
					err = soscl_sha384_core((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx, (uint8_t*)sp_context.sup.p_rx_hdr, ( sizeof(t_sp_sup_rx_pckt_hdr) - sizeof(uint32_t) ));
				}
				if( err )
				{
					/** Critical error */
					err = N_SP_ERR_SUP_CRYPTO_FAILURE;
					goto sp_sup_check_security_out;
				}
				/** Real payload, data after 'address' field, is pointed in sp_context.sup.payload.p_data */
				/** Payload if any */
				if( sp_context.sup.p_rx_hdr->segment_elmnt.command_length )
				{
					/** Let's process the real payload - without 'address' field then */
					err = soscl_sha384_core((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx, (uint8_t*)sp_context.sup.payload.p_data, sp_context.sup.payload.size);
					if( err )
					{
						/** Critical error */
						err = N_SP_ERR_SUP_CRYPTO_FAILURE;
						goto sp_sup_check_security_out;
					}
				}
				/** Process security elements now - rawly */
				err = soscl_sha384_core((soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx, (uint8_t*)sp_context.security.uid, ( sp_context.security.total_size - ( 2 * C_EDCSA384_SIZE ) ));
				if( err )
				{
					/** Critical error */
					err = N_SP_ERR_SUP_CRYPTO_FAILURE;
					goto sp_sup_check_security_out;
				}
				/** Then finish computation */
				memset((void*)p_ctx->digest, 0x00, C_SP_SUP_HASH_SIZE_IN_BYTES);
				err = soscl_sha384_finish(p_ctx->digest, (soscl_sha384_ctx_t*)p_ctx->p_soscl_hash_ctx);
				if( err )
				{
					/** Critical error */
					err = N_SP_ERR_SUP_CRYPTO_FAILURE;
					goto sp_sup_check_security_out;
				}
				/** Now verify signature */
				/** Set parameters */
				Q.x = key.ecdsa.p_x;
				Q.y = key.ecdsa.p_y;
				signature.r = p_local_signature;
				signature.s = p_local_signature + C_EDCSA384_SIZE;
				/** Call SCL ECDSA verification function */
				err = soscl_ecdsa_verification(Q,
												signature,
												soscl_sha384,
												p_ctx->digest,
												C_SP_SUP_HASH_SIZE_IN_BYTES,
												&soscl_secp384r1,
												( SCL_HASH_INPUT_TYPE << SCL_INPUT_SHIFT ) ^
												( SCL_SHA384_ID << SCL_HASH_SHIFT ));
				if( err )
				{
					/**  */
					goto sp_sup_check_security_out;
				}
			}
			/******************************************************************/
		}
		/** If we're here, it means that signature(s) is(are) checked Ok */
		/** No error */
		err = NO_ERROR;
	}
sp_sup_check_security_out:
	/** End Of Function */
	return err;
}
/******************************************************************************/
int32_t sp_sup_process_cmd(t_context *p_ctx, uint8_t **p_data, uint32_t *p_length)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx || !p_length )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Check received command */
		switch( sp_context.sup.p_rx_hdr->segment_elmnt.command_type )
		{
			case N_SP_SUP_SEGMENT_TYPE_COPY:
				/** Copy data to destination address */
//				err = sp_treat_copy();
				/** Already done when receiving command header - :/ */
				err = NO_ERROR;
				/** No specific data to return */
				*p_length = 0;
				break;
			case N_SP_SUP_SEGMENT_TYPE_WRITECSK:
				err = sp_treat_writecsk(p_ctx,
										sp_context.sup.payload.p_data,
										( sp_context.sup.p_rx_hdr->segment_elmnt.command_length - sizeof(uint32_t)));
				if( NO_ERROR == err )
				{
					err = N_SP_ERR_RESET_PLATFROM;
				}
				/** No specific data to return */
				*p_length = 0;
				break;
			case N_SP_SUP_SEGMENT_TYPE_UPDATECSK:
			{
				/** Then process new CSK */
				err = sp_treat_updatecsk(p_ctx,
										sp_context.sup.payload.p_data,
										( sp_context.sup.p_rx_hdr->segment_elmnt.command_length - sizeof(uint32_t) ));
				if( NO_ERROR == err )
				{
					err = N_SP_ERR_RESET_PLATFROM;
				}
				/** No specific data to return */
				*p_length = 0;
				break;
			}
			case N_SP_SUP_SEGMENT_TYPE_GETINFO:
				err = sp_treat_getinfo(p_ctx, (uint8_t**)p_data, p_length);
				break;
			case N_SP_SUP_SEGMENT_TYPE_EXECUTE:
				err = sp_treat_execute(p_ctx,
										*((uint32_t*)work_buf),
										sp_context.sup.payload.p_data,
										( sp_context.sup.p_rx_hdr->segment_elmnt.command_length - sizeof(uint32_t)),
										(uint8_t**)p_data,
										p_length);
				break;
			default:
				err = N_SP_ERR_SUP_CMD_NOT_SUPPORTED;
				break;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_send_response(t_context *p_ctx, uint8_t *p_data, uint32_t length)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointers */
	if( !p_ctx || !p_data )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !length )
	{
		/** Nothing to send - should not happen */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Send  */
		err = sp_uart_send_buffer(p_ctx, p_data, length);
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_initialize_communication(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input parameter */
	if( !p_ctx )
	{
		/** Pointer must not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto sp_sup_initialize_communication_out;
	}
	/** Retrieve communication port to use from OTP */
	err = sp_sup_get_port_id(p_ctx);
	if( err )
	{
		/** Set default port */
		sp_context.port.bus_id = C_SBRM_BUSID_DEFAULT;
	}
	/** Retrieve configuration parameters for this port */
	err = sp_sup_get_port_conf(p_ctx);
	if ( err )
	{
		/** Should not happen */
		err = GENERIC_ERR_CRITICAL;
		goto sp_sup_initialize_communication_out;
	}
	/** Initialize port */
	switch( sp_context.port.bus_id )
	{
		case N_SBRM_BUSID_UART:
			metal_uart_init(sp_context.port.uart.uart0, sp_context.port.config[C_SP_SUP_PORT_CONF_BAUDRATE_OFST]);
			err = NO_ERROR;
			break;
		default:
			err = N_SP_ERR_SUP_COM_PORT_NOT_HANDLED;
			goto sp_sup_initialize_communication_out;
	}
sp_sup_initialize_communication_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_prep_com(void)
{
	/** Zero-ize header for Rx and Tx */
	memset((void*)&sp_sup_rx_hdr, 0x00, sizeof(t_sp_sup_rx_pckt_hdr));
	memset((void*)&sp_sup_tx_hdr, 0x00, sizeof(t_sp_sup_tx_pckt_hdr));
	/**  */
	memset((void*)&sp_context.sup, 0x00, sizeof(t_sp_sup_context));
	/** Fill out several fields */
	sp_context.sup.p_rx_hdr = (t_sp_sup_rx_pckt_hdr*)&sp_sup_rx_hdr;
	sp_context.sup.p_tx_hdr = (t_sp_sup_tx_pckt_hdr*)&sp_sup_tx_hdr;
	/** Initialize contextual variables */
	sp_context.sup.first_pkt = TRUE;
	sp_context.sup.mode = N_SP_MODE_NORMAL;
	sp_context.sup.current_session_id = 0;
	sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SYNC;
	sp_context.state = N_SP_STATE_IDLE;
	/** End Of Function */
	return NO_ERROR;
}

/******************************************************************************/
int32_t sp_sup_open_communication(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	int32_t										err_cmd = GENERIC_ERR_UNKNOWN;
	uint32_t									length = 0;
	uint8_t										*p_data;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto sp_sup_open_communication_out;
	}
	/** Prepare communication context */
	err = sp_sup_prep_com();
	if( err )
	{
		/** Communication context preparation failed, therefore exit with error */
		goto sp_sup_open_communication_out;
	}
	/** Loop to receive packets - endless loop until communication is closed */
	while( ( NO_ERROR == err ) && ( C_SP_LAST_PACKET_NB != sp_context.sup.p_rx_hdr->last_packet ) )

	{

		/** Receive and process header */
		err = sp_sup_receive_packet(p_ctx);
		if( err )
		{
			/** Packet cannot be retrieved for any reason, exit with error */
			goto sp_sup_open_communication_out;
		}
		/** Check signature */
		err = sp_sup_check_security((t_context*)p_ctx);
		if ( err )
		{
			/** Exit and try to launch application if any */
			/** Because of security problem, no answer is sent back to Host */
			goto sp_sup_open_communication_out;
		}
		/** Process command then */
		err_cmd = sp_sup_process_cmd((t_context*)p_ctx, (uint8_t**)&p_data, (uint32_t*)&length);
		if( N_SP_ERR_RESET_PLATFROM == err_cmd )
		{
			/** Fill parameter to send error code to Host */
			/** Send packet response */
			err = sp_sup_packet_response(p_ctx,
											NO_ERROR,
											sp_context.sup.current_session_id,
											sp_context.sup.current_packet_nb,
											(uint8_t*)p_data,
											length);
			/** Must stop the loop to reset platform */
			err = err_cmd;
		}
		else
		{
			/** Send packet response */
			err = sp_sup_packet_response(p_ctx,
											err_cmd,
											sp_context.sup.current_session_id,
											sp_context.sup.current_packet_nb,
											(uint8_t*)p_data,
											length);
		}
	}
sp_sup_open_communication_out:
	/** End Of Function */
	return err;
}


/******************************************************************************/
void sp_sup_close_communication(t_context *p_ctx)
{
	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
	}
	else
	{
		/** Close bus */
		/** Disable interruptions */
		M_UART_MASK_RX_IRQ(sp_context.port.uart.reg_uart);
		M_UART_MASK_TX_IRQ(sp_context.port.uart.reg_uart);
		/** Disable RX and TX */
		M_UART_RX_DISABLE(sp_context.port.uart.reg_uart);
		M_UART_TX_DISABLE(sp_context.port.uart.reg_uart);
	}
	/** End Of Function */
	return;
}

/******************************************************************************/
int32_t sp_treat_writecsk(t_context *p_ctx, uint8_t *p_data, uint32_t length)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									i;
	uint32_t									ref_key_size = 0;
	uint8_t										*p_csk;
	t_key_data									*p_csk_data;
	t_km_context								*p_km_ctx;
	u_km_key									key;
	soscl_type_ecc_uint8_t_affine_point			Q;
	soscl_type_ecdsa_signature					signature;


	/** Check input parameters */
	if( ( !p_ctx ) || ( !p_data ) )
	{
		/** NULL pointer thus error */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( sizeof(t_key_data) != length )
	{
		/** length must be */
		err = N_SP_ERR_SUP_CANT_PROCEEED;
	}
	else
	{
		/** Fill local structure */
		p_csk_data = (t_key_data*)p_data;
		/** Check algorithm */
		if( C_KM_CSK_DESCR_ALGO_ECDSA != p_csk_data->algo )
		{
			/** Not the good one */
			err = N_SP_ERR_SUP_ALGO_MISMATCH;
			goto sp_treat_writecsk_out;
		}
		/** ECDSA384 size is 48 Bytes * 8bits = 0x30 * 8 */
		else if( (uint16_t)( C_EDCSA384_SIZE * 8 ) != p_csk_data->key_size_bits )
		{
			/**  */
			err = N_SP_ERR_SUP_WRITECSK_FAILED;
			goto sp_treat_writecsk_out;
		}
		/** Retrieve KM context structure */
		if( !p_ctx->p_km_context )
		{
			/** Should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_treat_writecsk_out;
		}
		/**  */
		p_km_ctx = (t_km_context*)p_ctx->p_km_context;
		/** Check if chosen area is free */
		if( p_km_ctx->index_free_csk > C_OTP_MAPPING_CSK_SLOT_MAX )
		{
			/** Can't perform command */
			err = N_SP_ERR_SUP_NO_FREE_SLOT;
			goto sp_treat_writecsk_out;
		}
		else if( TRUE == sp_context.csk_last_slot )
		{
			/**  */
			p_csk = (uint8_t*)M_GET_OTP_ABSOLUTE_ADDR(context, C_OTP_MAPPING_LAST_CSK_OFST);
		}
		else
		{
			/** Point on first free slot */
			p_csk = (uint8_t*)M_GET_OTP_ABSOLUTE_ADDR(context, ( ( p_km_ctx->index_free_csk * C_OTP_MAPPING_CSK_AERA_SIZE ) + C_OTP_MAPPING_CSK_OFST ) );
		}
		/** Check if CSK area is virgin */
		for( i = 0;i < C_OTP_MAPPING_CSK_AERA_SIZE;i++ )
		{
			/** Virgin pattern ? */
			if( C_PATTERN_VIRGIN_8BITS != p_csk[i] )
			{
				/** Can't proceed WRITE-CSK command */
				err = N_SP_ERR_SUP_WRITECSK_FAILED;
				goto sp_treat_writecsk_out;
			}
		}
		/** Everything is fine from destination point of view, let's check CSK signature */
		/** Is CUK present in platform */
		if( ( ( N_KM_KEYID_CUK == p_km_ctx->sign_key.id ) && ( C_KM_CSK_DESCR_VERIF_KEY_CUK == p_csk_data->sign_key_id ) ) ||
			( ( N_KM_KEYID_SSK == p_km_ctx->sign_key.id ) && ( C_KM_CSK_DESCR_VERIF_KEY_SSK == p_csk_data->sign_key_id ) ) )
		{
			/** Descriptor of CSK must refer to CUK/SSK, then verify certificate */
		}
		else
		{
			/** Mismatch keys */
			err = N_SP_ERR_SUP_KEY_MISMATCH;
			goto sp_treat_writecsk_out;
		}
		/** Retrieve key */
		err = km_get_key(p_km_ctx->sign_key.id,
							(u_km_key*)&key,
							(uint32_t*)&ref_key_size);
		if( err )
		{
			/** Should not happen */
			goto sp_treat_writecsk_out;
		}
		/** Assign parameters */
		Q.x = key.ecdsa.p_x;
		Q.y = key.ecdsa.p_y;
		signature.r = p_csk_data->certificate;
		signature.s = p_csk_data->certificate + C_EDCSA384_SIZE;
		/** Check certificate */
		err = soscl_ecdsa_verification(Q,
										signature,
										&soscl_sha384,
										(uint8_t*)p_csk_data,
										sizeof(t_key_data) - ( 2 * C_EDCSA384_SIZE ),
										&soscl_secp384r1,
										( SCL_MSG_INPUT_TYPE << SCL_INPUT_SHIFT ) ^
										( SCL_SHA384_ID << SCL_HASH_SHIFT ));
		if( err )
		{
			/** Can't proceed to CSK programming  */
			err = N_SP_ERR_SUP_WRITECSK_FAILED;
		}
		else
		{
			/** Now program CSK in storage area */
			memcpy((void*)p_csk, p_data, length);
			/** No error */
			err = NO_ERROR;
		}
	}
sp_treat_writecsk_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_treat_updatecsk(t_context *p_ctx, uint8_t *p_data, uint32_t length)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									i;
	uint32_t									ref_key_size = 0;
	uint8_t										*p_csk;
	t_key_data									*p_csk_data;
	t_km_context								*p_km_ctx;
	u_km_key									key;
	soscl_type_ecc_uint8_t_affine_point			Q;
	soscl_type_ecdsa_signature					signature;


	/** Check input parameters */
	if( ( !p_ctx ) || ( !p_data ) )
	{
		/** NULL pointer thus error */
		err = GENERIC_ERR_NULL_PTR;
	}
	/** Size must be CSK data (descriptor + CSK + CSK's certificate) +
	 *  old CSK (96 Bytes) + Certificate of those elements (96 Bytes) */
	else if( ( sizeof(t_key_data) + ( 4 * C_EDCSA384_SIZE ) ) != length )
	{
		/** length must be */
		err = N_SP_ERR_SUP_CANT_PROCEEED;
	}
	else if( !p_ctx->p_km_context )
	{
		/** Should not happen */
		err = GENERIC_ERR_CRITICAL;
	}
	else
	{
		/** Retrieve KM context structure */
		p_km_ctx = (t_km_context*)p_ctx->p_km_context;
		/** Process Old CSK first *********************************************/
		/** Check global signature */
		err = km_get_key(p_km_ctx->sign_key.id, (u_km_key *)&key, (uint32_t*)&ref_key_size);
		if ( err )
		{
			/** Should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_treat_updatecsk_out;
		}
		/** Assign parameters */
		Q.x = key.ecdsa.p_x;
		Q.y = key.ecdsa.p_y;
		signature.r = (uint8_t*)( p_data + length - ( 2 * C_EDCSA384_SIZE ) );
		signature.s = signature.r + C_EDCSA384_SIZE;
		/** Check certificate */
		err = soscl_ecdsa_verification(Q,
										signature,
										&soscl_sha384,
										(uint8_t*)p_data,
										length - ( 2 * C_EDCSA384_SIZE ),
										&soscl_secp384r1,
										( SCL_MSG_INPUT_TYPE << SCL_INPUT_SHIFT ) ^
										( SCL_SHA384_ID << SCL_HASH_SHIFT ));
		if( err )
		{
			/** Can't proceed to CSK programming  */
			err = N_SP_ERR_SUP_WRITECSK_FAILED;
		}
		/** Now, get old CSK */
		err = km_get_key(N_KM_KEYID_CSK, (u_km_key *)&key, (uint32_t*)&ref_key_size);
		if( err )
		{
			/** Can't proceed to UPDATE-CSK */
			err = N_SP_ERR_SUP_UPDATECSK_FAILED;
			goto sp_treat_updatecsk_out;
		}
		/** First check old CSK */
		err = memcmp((const void*)key.ecdsa.p_x, (const void*)p_data, ( 2 * C_EDCSA384_SIZE ));
		if( err )
		{
			/** CSK doesn't match */
			err = N_SP_ERR_SUP_UPDATECSK_FAILED;
			goto sp_treat_updatecsk_out;
		}
		/** Process new CSK then **********************************************/
		/** Fill local structure */
		p_csk_data = (t_key_data*)( p_data + ( 2 * C_EDCSA384_SIZE ) );
		/** Check algorithm */
		if( C_KM_CSK_DESCR_ALGO_ECDSA != p_csk_data->algo )
		{
			/** Not the good one */
			err = N_SP_ERR_SUP_ALGO_MISMATCH;
			goto sp_treat_updatecsk_out;
		}
		/** ECDSA384 size is 96 Bytes * 8bits = 0x30 * 8 */
		else if( (uint16_t)( C_EDCSA384_SIZE * 8 ) != p_csk_data->key_size_bits )
		{
			/**  */
			err = N_SP_ERR_SUP_WRITECSK_FAILED;
			goto sp_treat_updatecsk_out;
		}
		/** Check if chosen area is free */
		if( p_km_ctx->index_free_csk > C_OTP_MAPPING_CSK_SLOT_MAX )
		{
			/** Can't perform command */
			err = N_SP_ERR_SUP_NO_FREE_SLOT;
			goto sp_treat_updatecsk_out;
		}
		else if( TRUE == sp_context.csk_last_slot )
		{
			/**  */
			p_csk = (uint8_t*)M_GET_OTP_ABSOLUTE_ADDR(context, C_OTP_MAPPING_LAST_CSK_OFST);
		}
		else
		{
			/** Point on first free slot */
			p_csk = (uint8_t*)M_GET_OTP_ABSOLUTE_ADDR(context, ( ( p_km_ctx->index_free_csk * C_OTP_MAPPING_CSK_AERA_SIZE ) + C_OTP_MAPPING_CSK_OFST ) );
		}
		/** Everything is fine from destination point of view, let's check CSK signature */
		/** Is CUK present in platform */
		if( ( ( N_KM_KEYID_CUK == p_km_ctx->sign_key.id ) && ( C_KM_CSK_DESCR_VERIF_KEY_CUK == p_csk_data->sign_key_id ) ) ||
			( ( N_KM_KEYID_SSK == p_km_ctx->sign_key.id ) && ( C_KM_CSK_DESCR_VERIF_KEY_SSK == p_csk_data->sign_key_id ) ) )
		{
			/** Descriptor of CSK must refer to CUK/SSK, then verify certificate */
		}
		else
		{
			/** Mismatch keys */
			err = N_SP_ERR_SUP_KEY_MISMATCH;
			goto sp_treat_updatecsk_out;
		}
		/** Retrieve key */
		err = km_get_key(p_km_ctx->sign_key.id,
							(u_km_key*)&key,
							(uint32_t*)&ref_key_size);
		if( err )
		{
			/** Should not happen */
			goto sp_treat_updatecsk_out;
		}
		/** Assign parameters */
		Q.x = key.ecdsa.p_x;
		Q.y = key.ecdsa.p_y;
		signature.r = p_csk_data->certificate;
		signature.s = p_csk_data->certificate + C_EDCSA384_SIZE;
		/** Check certificate */
		err = soscl_ecdsa_verification(Q,
										signature,
										&soscl_sha384,
										(uint8_t*)p_csk_data,
										sizeof(t_key_data) - ( 2 * C_EDCSA384_SIZE ),
										&soscl_secp384r1,
										( SCL_MSG_INPUT_TYPE << SCL_INPUT_SHIFT ) ^
										( SCL_SHA384_ID << SCL_HASH_SHIFT ));
		if( err )
		{
			/** Can't proceed to CSK programming  */
			err = N_SP_ERR_SUP_WRITECSK_FAILED;
		}
		else
		{
			/** Now program CSK in storage area */
			memcpy((void*)p_csk, p_csk_data, sizeof(t_key_data));
			/** No error */
			err = NO_ERROR;
		}
	}
sp_treat_updatecsk_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_treat_execute(t_context *p_ctx, uintmax_t jump_addr, uint8_t *p_arg, uint32_t length, uint8_t **p_data, uint32_t *p_length)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t (*applet_fct_ptr)(uint8_t* p_arg, uint32_t length, uint8_t **p_ret_data, uint32_t *p_ret_size);

	/** Check input pointer */
	if( !p_arg )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		uint32_t								arg0 = (uint32_t)p_arg;
		uint32_t								arg1 = length;

		/** Check jump address */
		if( (  (uintmax_t)p_ctx->free_ram_end < jump_addr ) ||
			( (uintmax_t)p_ctx->free_ram_start > jump_addr ) )
		{
			/**  */
			err = N_SP_ERR_SUP_JUMP_ADDR_FAILURE;
			goto sp_treat_execute_out;
		}
		/** Assign function pointer */
		applet_fct_ptr = jump_addr;
		/** Call function */
		err = applet_fct_ptr(p_arg, length, p_data, p_length);

	}
sp_treat_execute_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_treat_getinfo(t_context *p_ctx, uint8_t** p_data, uint32_t *p_length)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	t_getinfo_template							*p_tmp = (t_getinfo_template*)work_buf;
	t_km_context								*p_km_ctx;

	/** Check input pointer */
	if( !p_ctx || !p_data || !p_length )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Assign pointer */
		p_km_ctx = (t_km_context*)p_ctx->p_km_context;
		/** Erase buffer */
		memset((void*)work_buf, 0x00, sizeof(t_getinfo_template));
		/** Assign output pointer */
		*p_data = (uint8_t*)p_tmp;
		/** Retrieve UID */
		err = sbrm_get_uid(p_ctx, p_tmp->uid);
		if( err )
		{
			/** Should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_treat_getinfo_out;
		}
		/** Retrieve SBR version */
		err = sbrm_get_sbc_version((uint32_t*)&p_tmp->version);
		if( err )
		{
			/** Should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_treat_getinfo_out;
		}
		/** Retrieve Applet memory area */
		p_tmp->applet_start = (uint32_t)&__sbrm_free_start_addr;
		p_tmp->applet_end = (uint32_t)&__sbrm_free_end_addr;
		/** Retrieve CSK free slot index */
		p_tmp->csk_slot = p_km_ctx->index_free_csk;
		/** Set size of returned data */
		*p_length = sizeof(t_getinfo_template);
		err = NO_ERROR;
	}
sp_treat_getinfo_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_pkt_fields(uint8_t **p_data, uint32_t *p_size)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									tmp_min_size = C_SP_SUP_PAYLOAD_MIN_SIZE;

	/** Check input pointers - don't care about '*p_data' to be null */
	if( !p_data || !p_size )
	{
		/** At east one pointer is null */
		err = GENERIC_ERR_NULL_PTR;
		goto sp_sup_pkt_fields_out;
	}
	/** Is it first packet ? */
	if( TRUE == sp_context.sup.first_pkt )
	{
		/** Check mode */
		if( ( N_SP_MODE_RMA != sp_context.sup.p_rx_hdr->packet_type ) &&
			( N_SP_MODE_NORMAL != sp_context.sup.p_rx_hdr->packet_type ) )
		{
			/** Unknown value thus error */
			err = N_SP_ERR_SUP_NET_BAD_CONFIG;
			goto sp_sup_pkt_fields_out;
		}
		else if( sp_context.sup.p_rx_hdr->packet_number )
		{
			/** SUP packet number must start from '0' */
			err = N_SP_ERR_SUP_NET_WRONG_PACKET_NB;
			goto sp_sup_pkt_fields_out;
		}
		/** Save mode */
		sp_context.sup.mode = (e_sp_sup_mode)sp_context.sup.p_rx_hdr->packet_type;
		/** Save first packet number */
		sp_context.sup.current_packet_nb = 0;
		/** Save payload size to be received */
		sp_context.sup.lasting_packet_len = sp_context.sup.p_rx_hdr->packet_length;
	}
	else if( ( ( sp_context.sup.current_packet_nb + 1 ) != sp_context.sup.p_rx_hdr->packet_number ) ||
			( sp_context.sup.mode != (e_sp_sup_mode)sp_context.sup.p_rx_hdr->packet_type ) )
	{
		/** Shouldn't be there */
		err = N_SP_ERR_SUP_NET_UNKNOWN;
		goto sp_sup_pkt_fields_out;
	}
	/** Is there a payload ? */
	if( tmp_min_size <= sp_context.sup.p_rx_hdr->packet_length )
	{
		/** Update packet reception state */
		sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SEG_HDR_PKT;
		*p_data = (uint8_t*)&sp_context.sup.p_rx_hdr->segment_elmnt.command_type;
		/** Size : Command type (32bits) + Command length (32bits) + address (32bits) */
		*p_size = C_SP_SUP_COMMAND_HDR_MIN_SIZE + sizeof(uint32_t);
		/** No error */
		err = NO_ERROR;
	}
	else
	{
		/** No payload, it's an error case */
		err = N_SP_ERR_SUP_PAYLOAD_SIZE_TOO_SMALL;
	}
sp_sup_pkt_fields_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_cmd_hdr(uint8_t **p_data, uint32_t *p_size)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointers - don't care about '*p_data' to be null */
	if( !p_data || !p_size )
	{
		/** At east one pointer is null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Be ready to receive segment payload if any */
		switch( sp_context.sup.p_rx_hdr->segment_elmnt.command_type )
		{
			case N_SP_SUP_SEGMENT_TYPE_COPY:
			{
				volatile uint32_t				addr = (volatile uint32_t)sp_context.sup.p_rx_hdr->segment_elmnt.address;

				/** 'length' is given for all payload, don't forget to remove 32bits for 'address' fro mpacket payload */
				*p_size = sp_context.sup.p_rx_hdr->segment_elmnt.command_length - sizeof(uint32_t);
				/** Check boundaries */
// _DBG_YG_
//				if( ( (volatile uint32_t)&__sbrm_free_start_addr <= addr ) && ( (volatile uint32_t)&__sbrm_free_end_addr > ( addr + *p_size ) ) )
//				{
					/** Data to copy is in range */
					*p_data = (uint8_t*)addr;
					sp_context.sup.payload.p_data = *p_data;
					sp_context.sup.payload.size = *p_size;
					/** Prepare next step */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SEG_PAYLOAD;
					/** No error */
					err = NO_ERROR;
//				}
//				else
//				{
//					/** Data will not fit into internal RAM */
//					err = N_SP_ERR_SUP_NO_MORE_MEMORY;
//					sp_context.sup.payload.p_data = 0;
//					sp_context.sup.payload.size = 0;
//				}
				break;
			}
			case N_SP_SUP_SEGMENT_TYPE_WRITECSK:
			case N_SP_SUP_SEGMENT_TYPE_UPDATECSK:
			{
				/** Specific address value to indicate that CSK must be programmed in last slot */
				if ( C_SP_SUP_CSK_LAST_SLOT_ADDR == sp_context.sup.p_rx_hdr->segment_elmnt.address)
				{
					/** CSK must be written in last slot */
					sp_context.csk_last_slot = TRUE;
				}
				else
				{
					/** CSK must be written in first free slot */
					sp_context.csk_last_slot = FALSE;
				}
				*p_data = (uint8_t*)work_buf;
				/** 'command_length' is given in Bytes, but subtract size of address field (32bits) */
				*p_size = ( sp_context.sup.p_rx_hdr->segment_elmnt.command_length - sizeof(uint32_t) );
				/** 'address' field of segment type structure holds address to work buffer */
				sp_context.sup.payload.p_data = (uint8_t*)work_buf;
				sp_context.sup.payload.size = *p_size;
				/** Prepare next step */
				sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SEG_PAYLOAD;
				/** No error */
				err = NO_ERROR;
				break;
			}
			case N_SP_SUP_SEGMENT_TYPE_GETINFO:
				if( sp_context.sup.p_rx_hdr->segment_elmnt.command_length )
				{
					/** must be null, therefore it's an error */
					err = N_SP_ERR_SUP_WRONG_CMD_LENGTH;
				}
				else
				{
					/** 'get-info' command is special because it has no 'address' field.
					 * As a consequence, next step length must be shortened with 1 Byte.
					 * And it corresponds to either 1 Byte of UID, or 'Number of signatures' field. */
					/** Update temporary pointers */
					*p_size = sp_context.sup.lasting_packet_len;
					/** 'address' field comes from previous reception state */
					*((uint32_t*)&sp_context.security.uid[0]) = sp_context.sup.p_rx_hdr->segment_elmnt.address;
					/** An 32bits has been already received ... 'address' field ... thus we point on next index*/
					*p_data = (uint8_t*)&sp_context.security.uid[sizeof(uint32_t)];
					sp_context.sup.payload.p_data = sp_context.security.uid;
					sp_context.sup.payload.size = *p_size + sizeof(uint32_t);
					sp_context.security.total_size = sp_context.sup.payload.size;
					/** Prepare next step */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SECU_SIG;
					/** No error */
					err = NO_ERROR;
				}
				break;
			case N_SP_SUP_SEGMENT_TYPE_EXECUTE:
				/** Here 'work_buf' is used as temporary buffer */
				*p_data = (uint8_t*)work_buf;
				/** 'length' is given in 32bits words */
				*p_size = ( sp_context.sup.p_rx_hdr->segment_elmnt.command_length - sizeof(uint32_t) );
				sp_context.sup.payload.p_data = *p_data;
				sp_context.sup.payload.size = *p_size;
				/** Prepare next step */
				sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SEG_PAYLOAD;
				/** No error */
				err = NO_ERROR;
				break;
			default:
				/** Error should not happen */
				err = N_SP_ERR_SUP_WRONG_CMD;
				break;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_secu(uint8_t **p_data, uint32_t *p_size)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint8_t										*p_uid = (uint8_t*)(M_GET_OTP_ABSOLUTE_ADDR(context, C_OTP_MAPPING_UID_OFST));

	/** Check input pointers - don't care about '*p_data' to be null */
	if( !p_data || !p_size )
	{
		/** At east one pointer is null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{

		/** Verify UID if present */
		if( N_SP_MODE_RMA == sp_context.sup.mode )
		{
			/** Read platform's UID from OTP */
			err = memcmp((const void*)p_uid, (const void*)sp_context.security.uid, C_UID_SIZE_IN_BYTES);
			if( err )
			{
				/** UIDs do not match, packet does not target current platform */
				err = N_SP_ERR_SUP_UID_NO_MATCH;
				goto sp_sup_secu_out;
			}
			else
			{
				/** No error for now - just to update the variable at this step */
				err = NO_ERROR;
			}
		}
		/** Packet must have, at least one signature */
		if( !sp_context.security.nb_signatures || ( C_SP_SUP_MAX_SIGNATURE_ELMNT_NB < sp_context.security.nb_signatures ) )
		{
			/** Signatures number does not fit */
			err = N_SP_ERR_SUP_PACKET_REJECTED;
		}
		else
		{
			/** Now parameter(s) is(are) ok */
			err = NO_ERROR;
		}
	}
sp_sup_secu_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_receive_packet(void *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									i;
	uint32_t									size_read = C_SP_HTT_MAGIC_WORD_SIZE;
	uint8_t										*p_tmp = (uint8_t*)&sp_sup_rx_hdr.htt_magic_word;
	t_context									*p_context;


	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer must not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto sp_sup_receive_packet_out;
	}
	/** Assign pointer */
	p_context = (t_context*)p_ctx;
	/** Initialize variables */
	sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SYNC;
	err = NO_ERROR;
	/** Loop to receive packet */
	while( ( N_SP_STATE_END > sp_context.state ) && ( NO_ERROR == err ) )
	{
		/** Read expected number of bytes */
		err = sp_uart_receive_buffer(p_ctx, (uint8_t*)p_tmp, (uint32_t*)&size_read);
		/**  */
		switch( sp_context.sup.state_pkg )
		{
			case N_SP_SUP_RCV_PKT_SYNC:
				/** Check session ID */
				if ( err )
				{
					/** Any other error will lead to exit from SUP */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				/** First read directly into HTT field */
				else if( ( NO_ERROR == err ) && ( C_SP_HTT_MAGIC_WORD == sp_sup_rx_hdr.htt_magic_word ) )
				{
					/** Good to go ... */
					/** No error then keep going */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SESSIONID;
					/** Point on appropriate buffer with appropriate size */
					p_tmp = (uint8_t*)&sp_context.sup.p_rx_hdr->session_id;
					size_read = sizeof(uint32_t);
					/** No error */
				}
				else if( NO_ERROR == err )
				{
					/** Try to re-synchronize */
					p_tmp[0] = p_tmp[1];
					p_tmp[1] = p_tmp[2];
					p_tmp[2] = p_tmp[3];
					p_tmp = (uint8_t*)&p_tmp[3];
					/** Read only next character */
					size_read = 1;
					/** If here, therefore synchronization pattern has not been found */
					/** Wait for next character */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SYNC;
					/** No error */
					err = NO_ERROR;
				}
				break;
			case N_SP_SUP_RCV_PKT_SESSIONID:
				/** Check session ID */
				if ( err )
				{
					/** Any other error will lead to exit from SUP */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				else if( TRUE == sp_context.sup.first_pkt )
				{
					/** If this packet is the first one, variable will be updated only when packet
					 * is checked ok */
					/** No error then keep going */
					/** Update saved session identifier */
					sp_context.sup.current_session_id = sp_context.sup.p_rx_hdr->session_id;
					/** Update packet reception state */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_FIELDS;
					/** Update data pointer and size */
					p_tmp = (uint8_t*)&sp_context.sup.p_rx_hdr->packet_number;
					size_read = 4 * sizeof(uint32_t);
				}
				else if( sp_context.sup.current_session_id == sp_context.sup.p_rx_hdr->session_id )
				{
					/** No error then keep going */
					/** Update packet reception state */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_FIELDS;
					/** Update data pointer and size */
					p_tmp = (uint8_t*)&sp_context.sup.p_rx_hdr->packet_number;
					size_read = 4 * sizeof(uint32_t);
				}
				else
				{
					/** Problem, then stop communication */
					err = N_SP_ERR_SUP_NET_WRONG_SESSION;
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				break;
			case N_SP_SUP_RCV_PKT_FIELDS:
				/** Check if error in receiving data */
				if( err )
				{
					/** Error should not happen */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				/** Packet fields have been received so let's analyze them */
				/** Here is first packet */
				else
				{
					/** Prepare next step */
					err = sp_sup_pkt_fields((uint8_t**)&p_tmp, (uint32_t*)&size_read);
					if( err )
					{
						/** Error should not happen */
						sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
						sp_context.state = N_SP_STATE_END;
					}
				}
				break;
			case N_SP_SUP_RCV_PKT_SEG_HDR_PKT:
				/** Check if error in receiving data */
				if( err )
				{
					/** Error should not happen */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				else
				{
					/** Update lasting packet length */
					sp_context.sup.lasting_packet_len -= size_read;
					/**  */
					err = sp_sup_cmd_hdr((uint8_t**)&p_tmp, (uint32_t*)&size_read);
					if( err )
					{
						/** Error should not happen */
						sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
						sp_context.state = N_SP_STATE_END;
					}
				}
				break;
			case N_SP_SUP_RCV_PKT_SEG_PAYLOAD:
				/** Check if error in receiving data */
				if( err )
				{
					/** Error should not happen */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				else
				{
					/** Update lasting packet length, and it lasts only security part */
					sp_context.sup.lasting_packet_len -= size_read;
					/** Prepare next step */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SECU_SIG;
					/** Update temporary pointers */
					size_read = sp_context.sup.lasting_packet_len;
					sp_context.security.total_size = size_read;
					p_tmp = (uint8_t*)sp_context.security.uid;
				}
				break;
			case N_SP_SUP_RCV_PKT_SECU_SIG:
				if( err )
				{
					/** Error should not happen */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				else
				{
					/** Check signature */
					err = sp_sup_secu((uint8_t**)&p_tmp, (uint32_t*)&size_read);
					if ( err )
					{
						/** Something goes wrong with security checks */
						err = N_SP_ERR_RESET_PLATFROM;
						goto sp_sup_receive_packet_out;
					}
					/** If OK, then whatever packet it is, it's no more first one */
					sp_context.sup.first_pkt = FALSE;
					/** Update global state */
					sp_context.state = N_SP_STATE_POST_PROCESS;
					/** Check if it is the last packet */
					if( C_SP_LAST_PACKET_NB == sp_context.sup.p_rx_hdr->last_packet )
					{
						/** Ok then stop reception window */
						sp_context.state = N_SP_STATE_END;
					}
					else
					{
						/** */
					}
					/** No error, just to be sure */
					err = NO_ERROR;
				}
				break;
			case N_SP_SUP_RCV_PKT_END:
			default:
				goto sp_sup_receive_packet_out;
		}
	}
sp_sup_receive_packet_out:
	/** Stop bus reception */
	/** Disable UART interruption */
	M_UART_MASK_RX_IRQ(sp_context.port.uart.reg_uart);
	/** Disable UART's RX */
	M_UART_RX_DISABLE(sp_context.port.uart.reg_uart);
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t sp_sup_packet_response(t_context *p_ctx,
								uint32_t error,
								uint32_t session_id,
								uint32_t packet_number,
								uint8_t *p_data,
								uint32_t length)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									crc;

	/** Check parameters in special case where there's data to send */
	if( !p_ctx || ( !p_data && length ) )
	{
		/** Pointer should not have been null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Prepare TX packet header */
		sp_context.sup.p_tx_hdr->sesion_id = session_id;
		sp_context.sup.p_tx_hdr->packet_number = packet_number;
		sp_context.sup.p_tx_hdr->tth_magic_word = C_SP_TTH_MAGIC_WORD;
		sp_context.sup.p_tx_hdr->ret_error = error;
		sp_context.sup.p_tx_hdr->data_length = length;
		/** Given 'length' with 'error' size - 32bits, 'data length' size - 32bits and 'crc' size - 32bits */
		sp_context.sup.p_tx_hdr->packet_length = sp_context.sup.p_tx_hdr->data_length + ( 3 * sizeof(uint32_t) );
		/** Zero-ize 'crc' buffer */
		crc = 0;
		/** CRC computation */
		/** Header */
		err = sbrm_compute_crc((uint32_t*)&crc, (uint8_t*)sp_context.sup.p_tx_hdr, sizeof(t_sp_sup_tx_pckt_hdr));
		if( err )
		{
			/** Error should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_sup_packet_response_out;
		}
		/** Payload - other if any */
		if( length )
		{
			err = sbrm_compute_crc((uint32_t*)&crc, (uint8_t*)p_data, length);
			if( err )
			{
				/** Error should not happen */
				err = GENERIC_ERR_CRITICAL;
				goto sp_sup_packet_response_out;
			}
		}
		/** Now start sending ... */
		/** ... with header ... */
		err = sp_uart_send_buffer(p_ctx, (uint8_t*)sp_context.sup.p_tx_hdr, sizeof(t_sp_sup_tx_pckt_hdr));
		if( err )
		{
			/** Error should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_sup_packet_response_out;
		}
		/** ... then payload if any */
		if ( length )
		{
			err = sp_uart_send_buffer(p_ctx, (uint8_t*)p_data, length);
			if( err )
			{
				/** Error should not happen */
				err = GENERIC_ERR_CRITICAL;
				goto sp_sup_packet_response_out;
			}
		}
		/** ... and finish with CRC */
		err = sp_uart_send_buffer(p_ctx, (uint8_t*)&crc, sizeof(uint32_t));
		if( err )
		{
			/** Error should not happen */
			err = GENERIC_ERR_CRITICAL;
		}
	}
sp_sup_packet_response_out:
	/** End Of Function */
	return err;
}



/******************************************************************************/
/* End Of File */
