/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _SP_INTERNAL_H_
#define _SP_INTERNAL_H_

/** Global includes */
#include <stdint.h>
#include <metal/machine.h>
#include <metal/cpu.h>
#include <metal/uart.h>
#include <metal/gpio.h>
#include <common.h>
/** Other includes */
#include <soscl_hash_sha384.h>
#include <sbrm_public.h>
#include <ppm_public.h>
#include <km_public.h>
/** Local includes */
#include <sp_public.h>

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
#define	C_SP_HTT_MAGIC_WORD								0xaa51f17e
#define	C_SP_HTT_MAGIC_WORD_SIZE						sizeof(uint32_t)

#define	C_SP_TTH_MAGIC_WORD								0x47717322
#define	C_SP_TTH_MAGIC_WORD_SIZE						C_SP_HTT_MAGIC_WORD_SIZE

#define	C_SP_LAST_PACKET_NB								0x1a574ac8

#define	C_SP_SUP_SEG_ADDRESS_SIZE_IN_BYTES				0x8
#define	C_SP_SUP_HASH_SIZE_IN_BYTES						SCL_SHA384_BYTE_HASHSIZE

#define	C_SP_SUP_PORT_CONF_SIZE_INTEGER					2
#define	C_SP_SUP_PORT_CONF_SIZE_BYTES					( C_SP_SUP_PORT_CONF_SIZE_INTEGER * sizeof(uint32_t) )

#define	C_SP_SUP_PORT_CONF_BAUDRATE_OFST				0
#define	C_SP_SUP_PORT_CONF_BAUDRATE_MASK_NOOFST			0xffffffffUL
#define	C_SP_SUP_PORT_CONF_BAUDRATE_MASK				( C_SP_SUP_PORT_CONF_BAUDRATE_MASK_NOOFST << C_SP_SUP_PORT_CONF_BAUDRATE_OFST )
#define	C_SP_SUP_PORT_CONF_PARAMS_BAUDRATE_NOOFST		0x1C200


#define	C_SP_SUP_PORT_CONF_PARAMS_OFST					1

#define	C_SP_SUP_PORT_CONF_PARAMS_PARITY_MASK_NOOFST	0x1
#define	C_SP_SUP_PORT_CONF_PARAMS_PARITY_MASK			( C_SP_SUP_PORT_CONF_PARAMS_PARITY_MASK_NOOFST << 0 )


#define	C_SP_SUP_PORT_CONF_PARAMS_STOP_MASK_NOOFST		0x1
#define	C_SP_SUP_PORT_CONF_PARAMS_STOP_MASK				( C_SP_SUP_PORT_CONF_PARAMS_STOP_MASK_NOOFST << 0 )

#define	C_SP_SUP_PORT_CONF_PARAMS_FLOW_NOOFST			0x00000004

/** Command header minimal size : 'command type' (32bits) + 'command length' (32bits) */
#define	C_SP_SUP_COMMAND_HDR_MIN_SIZE					( 2 * sizeof(uint32_t) )
/** Security header minimal size : 'number of signatures' (32bits) + 'signature number' (32bits)
 * There is, at least, one signature */
#define	C_SP_SUP_SECURITY_HDR_MIN_SIZE					( 2 * sizeof(uint32_t) )
/** Security signature and certificate minimal size : 'signature #1' (32bits) + Signature ECDSA384 (96 Bytes) */
#define	C_SP_SUP_SECURITY_PKCHAIN_MIN_SIZE				( ( 1 * sizeof(uint32_t) ) + ( 2 * C_EDCSA384_SIZE ) )


#define	C_SP_SUP_PAYLOAD_MIN_SIZE						( C_UID_SIZE_IN_BYTES +\
															C_SP_SUP_COMMAND_HDR_MIN_SIZE +\
															C_SP_SUP_SECURITY_HDR_MIN_SIZE +\
															C_SP_SUP_SECURITY_PKCHAIN_MIN_SIZE )

#define	C_SP_SUP_CSK_LAST_SLOT_ADDR						0x1A575107

/** _DBG_YG_ */
/** Default GPIO pin for SUP stimulus - FPGA central button */
#define	C_SUP_STIMULUS_PIN								19

/** Default values for port configuration parameters - To Be Updated */
//#define	C_SP_SUP_PORT_CONF_PARAMS0				0xDEADBEEF
#define	C_SP_SUP_PORT_CONF_PARAMS0						( ( C_SP_SUP_PORT_CONF_PARAMS_BAUDRATE_NOOFST << C_SP_SUP_PORT_CONF_BAUDRATE_OFST ) & C_SP_SUP_PORT_CONF_BAUDRATE_MASK )
#define	C_SP_SUP_PORT_CONF_PARAMS1						0xCAFEFADE
/**  */

/** Dummy buffer defines */
#define	C_SP_SUP_DUMMY_BUFFER_SIZE						0x400

/** PK Chain and Security *****************************************************/
/** PKChain element size : 'Pub Size Cert Algo' (32bits) + Public Key (384bits) + Certificate (384bits) */
#define	C_SP_SUP_PKCHAIN_ELMNT_SIZE						( sizeof(uint32_t) + ( 4 * C_EDCSA384_SIZE ) )
#define	C_SP_SUP_MAX_PK_CHAIN_ELMNT_NB					3
/** PKChain total size : 'Certs Number' (32bits) + 3 * PKChain element */
#define	C_SP_SUP_PKCHAIN_TOTAL_SIZE						( sizeof(uint32_t) + ( C_SP_SUP_MAX_PK_CHAIN_ELMNT_NB * C_SP_SUP_PKCHAIN_ELMNT_SIZE ) )

#define	C_SP_SUP_MAX_SIGNATURE_ELMNT_NB					3
/** Signature element size : 'Signature number' (32bits) + Total size of PKChain + Signature size (384bits) */
#define	C_SP_SUP_MAX_SIGNATURE_ELMNT_SIZE				( sizeof(uint32_t) + C_SP_SUP_PKCHAIN_TOTAL_SIZE + ( 2 * C_EDCSA384_SIZE ) )
/** Signature total size : 3 * Signature element */
#define	C_SP_SUP_MAX_SIGNATURE_TOTAL_SIZE				( C_SP_SUP_MAX_SIGNATURE_ELMNT_NB * C_SP_SUP_MAX_SIGNATURE_ELMNT_SIZE )

/** Stimulus parameters *******************************************************/
#define	C_SP_STIM_GPIO_PIN_OFST							0
#define	C_SP_STIM_GPIO_PIN_MASK_NOOFST					0xff
#define	C_SP_STIM_GPIO_PIN_MASK							( C_SP_STIM_GPIO_PIN_MASK_NOOFST << C_SP_STIM_GPIO_PIN_OFST )

#define	C_SP_STIM_GPIO_LVL_OFST							8
#define	C_SP_STIM_GPIO_LVL_MASK_NOOFST					0xff
#define	C_SP_STIM_GPIO_LVL_MASK							( C_SP_STIM_GPIO_LVL_MASK_NOOFST << C_SP_STIM_GPIO_LVL_OFST )

#define	C_SP_STIM_GPIO_BANK_OFST						16
#define	C_SP_STIM_GPIO_BANK_MASK_NOOFST					0xff
#define	C_SP_STIM_GPIO_BANK_MASK						( C_SP_STIM_GPIO_BANK_MASK_NOOFST << C_SP_STIM_GPIO_BANK_OFST )

#define	C_SP_STIM_BUS_ID_OFST							24
#define	C_SP_STIM_BUS_ID_MASK_NOOFST					0xff
#define	C_SP_STIM_BUS_ID_MASK							( C_SP_STIM_BUS_ID_MASK_NOOFST << C_SP_STIM_BUS_ID_OFST )

#define	C_SP_STIM_BUS_ID_UART_OFST						0
#define	C_SP_STIM_BUS_ID_UART_MASK_NOOFST				0x3
#define	C_SP_STIM_BUS_ID_UART_MASK						( C_SP_STIM_BUS_ID_UART_MASK_NOOFST << C_SP_STIM_BUS_ID_UART_OFST )

#define	C_SP_STIM_BUS_ID_SPI_OFST						2
#define	C_SP_STIM_BUS_ID_SPI_MASK_NOOFST				0x3
#define	C_SP_STIM_BUS_ID_SPI_MASK						( C_SP_STIM_BUS_ID_SPI_MASK_NOOFST << C_SP_STIM_BUS_ID_SPI_OFST )

#define	C_SP_STIM_BUS_ID_USB_OFST						4
#define	C_SP_STIM_BUS_ID_USB_MASK_NOOFST				0x1
#define	C_SP_STIM_BUS_ID_USB_MASK						( C_SP_STIM_BUS_ID_USB_MASK_NOOFST << C_SP_STIM_BUS_ID_USB_OFST )

#define	C_SP_STIM_BUS_ID_ETH_OFST						6
#define	C_SP_STIM_BUS_ID_ETH_MASK_NOOFST				0x1
#define	C_SP_STIM_BUS_ID_ETH_MASK						( C_SP_STIM_BUS_ID_ETH_MASK_NOOFST << C_SP_STIM_BUS_ID_ETH_OFST )

/** Enumerations **************************************************************/
/** SP internal state */
typedef enum
{
	/** Minimal value */
	N_SP_STATE_MIN = 0,
	N_SP_STATE_NOT_INITIALIZED = N_SP_STATE_MIN,
	N_SP_STATE_IDLE,
	N_SP_STATE_SUP_RECEPTION,
	N_SP_STATE_POST_PROCESS,
	N_SP_STATE_END,
	N_SP_STATE_MAX = N_SP_STATE_END,
	N_SP_STATE_COUNT

} e_sp_state;
/** Segment type */
typedef enum
{
	/**  */
	N_SP_SUP_SEGMENT_TYPE_MIN = 0x00000000UL,
	/* 0x01 */
	N_SP_SUP_SEGMENT_TYPE_COPY,
#ifdef _SUP_OLD_BEHAVIOR_
	/* 0x05 */
	N_SP_SUP_SEGMENT_TYPE_WRITECSK = 0x00000005UL,
	/* 0x0a */
	N_SP_SUP_SEGMENT_TYPE_UPDATECSK = 0x0000000aUL,
	/* 0x10 */
	N_SP_SUP_SEGMENT_TYPE_GETINFO = 0x00000010UL,
	/* 0x80 */
	N_SP_SUP_SEGMENT_TYPE_EXECUTE = 0x00000080UL,
#else
	/* 0xa94f2cb5UL */
	N_SP_SUP_SEGMENT_TYPE_WRITECSK = 0xa94f2cb5UL,
	/* 0x68234fbaUL */
	N_SP_SUP_SEGMENT_TYPE_UPDATECSK = 0x68234fbaUL,
	/* 0xc3788d10UL */
	N_SP_SUP_SEGMENT_TYPE_GETINFO = 0xc3788d10UL,
	/* 0x1e5dd280UL */
	N_SP_SUP_SEGMENT_TYPE_EXECUTE = 0x1e5dd280UL,
#endif /* _SUP_OLD_BEHAVIOR_ */
	N_SP_SUP_SEGMENT_TYPE_MAX = N_SP_SUP_SEGMENT_TYPE_EXECUTE

} e_sp_command_type;

typedef enum
{
	/** Minimum value */
	N_SP_SUP_RCV_PKT_MIN = 0,
	N_SP_SUP_RCV_PKT_SYNC = N_SP_SUP_RCV_PKT_MIN,
	N_SP_SUP_RCV_PKT_SESSIONID,
	N_SP_SUP_RCV_PKT_FIELDS,
	N_SP_SUP_RCV_PKT_SEG_HDR_PKT,
	N_SP_SUP_RCV_PKT_SEG_PAYLOAD,
	N_SP_SUP_RCV_PKT_SECU_SIG,
	N_SP_SUP_RCV_PKT_END,
	N_SP_SUP_RCV_PKT_MAX = N_SP_SUP_RCV_PKT_END,
	N_SP_SUP_RCV_PKT_COUNT

} e_sp_sup_rcv_pkt_state;

/** Structures ****************************************************************/
/** Structure for dummy character reception with or without DMA */
typedef struct __attribute__((packed, aligned(0x10)))
{
	/** Buffer */
	uint8_t										buffer[C_SP_SUP_DUMMY_BUFFER_SIZE];
	/** Index/Size in buffer */
	uint32_t									index;

} t_dummy_buffer;


/** SUP RX packet header */
typedef struct __attribute__((packed))
{
	/** HTT Magic Word - 4 Bytes */
	uint32_t									htt_magic_word;
	/** Session Identifier - 4 Bytes */
	uint32_t									session_id;
	/** Packet Number - 4 Bytes */
	uint32_t									packet_number;
	/** Last Packet - 4 Bytes */
	uint32_t									last_packet;
	/** Packet Type - 4 Bytes */
	uint32_t									packet_type;
	/** Packet Length - 4 Bytes */
	uint32_t									packet_length;
	/** Structure for segment description */
	struct __attribute__((packed))
	{
		/** Segment type - 4 Bytes */
		uint32_t								command_type;
		/** Segment length - 4 Bytes */
		uint32_t								command_length;
		/**  */
		uint32_t								address;

	} segment_elmnt;

} t_sp_sup_rx_pckt_hdr;

/** SUP TX packet header */
typedef struct __attribute__((packed))
{
	/** TTH Magic Word - 4 Bytes */
	uint32_t									tth_magic_word;
	/** Session Identifier - 4 Bytes */
	uint32_t									sesion_id;
	/** Packet Number - 4 Bytes */
	uint32_t									packet_number;
	/** Packet Length - 4 Bytes */
	uint32_t									packet_length;
	/** Error Code - 4 Bytes */
	int32_t										ret_error;
	/** Data length - 4 Bytes */
	uint32_t									data_length;

} t_sp_sup_tx_pckt_hdr;

/******************************************************************************/
typedef struct __attribute__((packed))
{
	/** Signature number */
	uint32_t									sig_nb;
	/** Number of certificate */
	uint32_t									nb_certificates;

} t_sig_element;

/** PK chain element */
typedef struct __attribute__((packed))
{
	/** Public key size */
	uint32_t									key_size;
	struct __attribute__((packed))
	{
		/** Public key */
		uint32_t								key[C_SIGNATURE_MAX_SIZE_INT];
		/** Certificate of public key */
		uint32_t								certificate[C_SIGNATURE_MAX_SIZE_INT];
	} pkchain_elmnt[C_SP_SUP_MAX_PK_CHAIN_ELMNT_NB];

} t_pkchain_element;

/******************************************************************************/
typedef struct __attribute__((packed))
{
	/** UID */
	uint8_t										uid[C_UID_SIZE_IN_BYTES];
	/** Secure Boot Core version */
	uint32_t									version;
	/** Applet RAM start address */
	uint32_t									applet_start;
	/** Applet RAM end address */
	uint32_t									applet_end;
	/** CSK last free slot in storage */
	uint32_t									csk_slot;


} t_getinfo_template;

/******************************************************************************/
/** SUP context structure */
typedef struct
{
	/** Current security key used */
	e_km_keyid									key_id;
	/** SUP mode if any */
	e_sp_sup_mode								mode;
	/** Is it first packet ? */
	uint8_t										first_pkt;
	/** Current packet session ID */
	uint32_t									current_session_id;
	/** Current packet number */
	uint32_t									current_packet_nb;
	/** lasting length of segments in packet */
	uint32_t									lasting_packet_len;
	/** Packet reception state */
	e_sp_sup_rcv_pkt_state						state_pkg;
	/** SUP packet data RX */
	t_sp_sup_rx_pckt_hdr						*p_rx_hdr __attribute__((aligned (0x10)));
	/** SUP packet data TX */
	t_sp_sup_tx_pckt_hdr						*p_tx_hdr __attribute__((aligned (0x10)));
	struct
	{
		/** Size of payload data */
		uint32_t								size;
		/** Pointer on buffer */
		uint8_t									*p_data;

	} payload;

} t_sp_sup_context;

typedef struct
{
	/** System Frequency */
	uint32_t									device_freq;
	/** SP state */
	e_sp_state									state;
	/** Must program CSK in last slot ? */
	uint8_t										csk_last_slot;
	/** Stimulus specific structure */
	struct __attribute__((packed,aligned(0x10)))
	{
		/** Stimulus */
		uint8_t									pin;
		/** Pin number */
		uint8_t									level;
		/** Pin level */
		uint8_t									gpio_bank;
		/** Bus list */
		uint8_t									bus;
		/**  */
		struct metal_gpio						*gpio;

	} stimulus;
	/** Communication port structure */
	struct
	{
		/** Bus Identifier */
		e_sbrm_busid							bus_id;
		/** Raw configuration parameters */
		uint32_t								config[C_SP_SUP_PORT_CONF_SIZE_INTEGER];;
		/**  */
		struct
		{
			/**  */
			volatile t_reg_uart					*reg_uart;
			/** Pointer on UART0 function pointers array */
			struct metal_uart 					*uart0;
			/** Pointer on UART0 interruption function pointer arrays */
			struct metal_interrupt				*uart0_ic;
			/** UART interruption identifier */
			uint32_t							uart0_irq;

		} uart;

	} port;
	/** Communication context structure */
	struct __attribute__((aligned(0x10)))
	{
		/** Lasting number of Bytes to be received */
		uint32_t								lasting;
		/** Number of characters received */
		uint32_t								received;
		/** Current watermark level */
		uint32_t								threshold;
		/** Is it in dummy mode ? */
		uint32_t								dummy_mode;
		/** Current data pointer */
		uint8_t									*p_data;

	} communication;
	/** Security packet element */
	struct __attribute__((packed,aligned(0x10)))
	{
		/** Total size of packet security part */
		uint32_t								total_size;
		/** UID field - optional */
		uint8_t									uid[C_UID_SIZE_IN_BYTES];
		/** Number of signatures */
		uint32_t								nb_signatures;
		/** Buffer for signature(s) */
		uint8_t									sig_buf[C_SP_SUP_MAX_SIGNATURE_TOTAL_SIZE];

	} security;
	/** SUP context structure */
	t_sp_sup_context							sup;

} t_sp_context;



/** Functions *****************************************************************/
/** UART */
void sp_uart_isr(int32_t id, void *data);
int32_t sp_uart_receive_buffer(t_context *p_ctx, uint8_t *p_data, uint32_t *p_size);
int32_t sp_uart_send_buffer(t_context *p_ctx, uint8_t *p_data, uint32_t size);
/**  */
int32_t sp_check_stimulus(t_context *p_ctx);
int32_t sp_sup_get_port_id(t_context *p_ctx);
int32_t sp_sup_get_port_conf(t_context *p_ctx);
/**  */
int32_t sp_sup_initialize_communication(t_context *p_ctx);
int32_t sp_sup_prep_com(void);
int32_t sp_sup_open_communication(t_context *p_ctx);
void sp_sup_close_communication(t_context *p_ctx);
int32_t sp_treat_copy(t_context *p_ctx, uint64_t address, uint64_t length, uint8_t *p_data);
int32_t sp_treat_writecsk(t_context *p_ctx, uint8_t *p_data, uint32_t length);
int32_t sp_treat_updatecsk(t_context *p_ctx, uint8_t *p_data, uint32_t length);
int32_t sp_treat_execute(t_context *p_ctx, uintmax_t jump_addr, uint8_t *p_arg, uint32_t length, uint8_t **p_data, uint32_t *p_length);
int32_t sp_treat_getinfo(t_context *p_ctx, uint8_t** p_data, uint32_t *p_length);
int32_t sp_sup_pkt_fields(uint8_t **p_data, uint32_t *p_size);
int32_t sp_sup_cmd_hdr(uint8_t **p_data, uint32_t *p_size);
int32_t sp_sup_secu(uint8_t **p_data, uint32_t *p_size);
int32_t sp_sup_receive_packet(void *p_ctx);
int32_t sp_sup_packet_response(t_context *p_ctx,
								uint32_t error,
								uint32_t session_id,
								uint32_t packet_number,
								uint8_t *p_data,
								uint32_t length);

/**  */
int32_t sp_sup_check_security(t_context *p_ctx);
int32_t sp_sup_process_cmd(t_context *p_ctx, uint8_t **p_data, uint32_t *p_length);
int32_t sp_sup_send_response(t_context *p_ctx, uint8_t *p_data, uint32_t length);

/** Macros ********************************************************************/
#define	M_UART_RX_DISABLE(_reguart_)	\
	((volatile t_reg_uart*)_reguart_)->rx_ctrl &= ~C_UART_RXCTRL_RXEN_MASK

#define	M_UART_RX_ENABLE(_reguart_)	\
	((volatile t_reg_uart*)_reguart_)->rx_ctrl |= C_UART_RXCTRL_RXEN_MASK

#define	M_UART_TX_DISABLE(_reguart_)	\
	((volatile t_reg_uart*)_reguart_)->tx_ctrl &= ~C_UART_TXCTRL_TXEN_MASK

#define	M_UART_TX_ENABLE(_reguart_)	\
	((volatile t_reg_uart*)_reguart_)->tx_ctrl |= C_UART_TXCTRL_TXEN_MASK

#define	M_UART_MASK_RX_IRQ(_reguart_)	\
	((volatile t_reg_uart*)_reguart_)->ie &= ~C_UART_IE_RXWM_MASK

#define	M_UART_UNMASK_RX_IRQ(_reguart_)	\
	((volatile t_reg_uart*)_reguart_)->ie |= C_UART_IE_RXWM_MASK

#define	M_UART_MASK_TX_IRQ(_reguart_)	\
	((volatile t_reg_uart*)_reguart_)->ie &= ~C_UART_IE_TXWM_MASK

#define	M_UART_UNMASK_TX_IRQ(_reguart_)	\
	((volatile t_reg_uart*)_reguart_)->ie |= C_UART_IE_TXWM_MASK

#endif /* _SP_INTERNAL_H_ */

/******************************************************************************/
/* End Of File */
