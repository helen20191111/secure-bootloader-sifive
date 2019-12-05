/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _KM_PUBLIC_H_
#define _KM_PUBLIC_H_

/** Global includes */
#include <errors.h>
#include <common.h>
#include <otp_mapping.h>
/** Other includes */
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
#define C_KM_BASE_ERROR        					( N_PREFIX_KM << C_PREFIX_OFFSET )


#define	C_KM_CSK_DESCR_ALGO_OFST				0
#define	C_KM_CSK_DESCR_ALGO_MASK_NOOFST			0xff
#define	C_KM_CSK_DESCR_ALGO_MASK				( C_KM_CSK_DESCRIPTOR_ALGO_MASK_NOOFST << C_KM_CSK_DESCRIPTOR_ALGO_OFST )
#define	C_KM_CSK_DESCR_ALGO_SIZE				sizeof(uint8_t)

#define	C_KM_CSK_DESCR_VERIF_KEY_OFST			( C_KM_CSK_DESCR_ALGO_OFST + C_KM_CSK_DESCR_ALGO_SIZE )
#define	C_KM_CSK_DESCR_VERIF_KEY_MASK_NOOFST	0xff
#define	C_KM_CSK_DESCR_VERIF_KEY_MASK			( C_KM_CSK_DESCR_VERIF_KEY_MASK_NOOFST << C_KM_CSK_DESCR_VERIF_KEY_OFST )
#define	C_KM_CSK_DESCR_VERIF_KEY_SIZE			sizeof(uint8_t)
/** CSK size is in bits, so don't forget to divide size by 8 to have Byte size */
#define	C_KM_CSK_DESCR_CSK_SIZE_OFST			( C_KM_CSK_DESCR_VERIF_KEY_OFST + C_KM_CSK_DESCR_VERIF_KEY_SIZE )
#define	C_KM_CSK_DESCR_CSK_SIZE_MASK_NOOFST		0xffff
#define	C_KM_CSK_DESCR_CSK_SIZE_MASK			( C_KM_CSK_DESCR_CSK_SIZE_MASK_NOOFST << C_KM_CSK_DESCR_CSK_SIZE_OFST )
#define	C_KM_CSK_DESCR_CSK_SIZE_SIZE			sizeof(uint16_t)

#define	C_KM_CSK_DESCR_CSK_SIZE_IN_BYTES		( C_KM_CSK_DESCR_ALGO_SIZE + C_KM_CSK_DESCR_VERIF_KEY_SIZE + C_KM_CSK_DESCR_CSK_SIZE_SIZE )

#define	C_KM_CSK_DESCR_ALGO_ECDSA				0xa7
#define	C_KM_CSK_DESCR_ALGO_NONE				C_PATTERN_VIRGIN_8BITS

#define	C_KM_CSK_DESCR_VERIF_KEY_SSK			0x2c
#define	C_KM_CSK_DESCR_VERIF_KEY_CUK			0x5e
#define	C_KM_CSK_DESCR_VERIF_KEY_CSK			0x84
#define	C_KM_CSK_DESCR_VERIF_KEY_PREVIOUS		0xd7

#define	C_KM_KEY_BUFFER_MAX_SIZE				( C_KM_CSK_DESCR_CSK_SIZE_IN_BYTES + C_SIGNATURE_MAX_SIZE +\
													C_KM_CSK_DESCR_CSK_SIZE_IN_BYTES + C_SIGNATURE_MAX_SIZE +\
													C_SIGNATURE_MAX_SIZE )

#define	C_KM_ARGVARGC_BUFFER_MAX_SIZE			( 0x100 + ( 3 * sizeof(uint32_t) ) )

/** Enumerations **************************************************************/
typedef enum
{
	/**  */
	N_KM_ERR_MIN = C_KM_BASE_ERROR,
	N_KM_ERR_NO_INDEX = N_KM_ERR_MIN,
	N_KM_ERR_NOT_VIRGIN,
	N_KM_ERR_NO_FREE_LOCATION,
	N_KM_ERR_NO_CSK,
	N_KM_ERR_NO_KEY,
	N_KM_ERR_INVALID_SIGNATURE,
	N_KM_ERR_ALGO_NOT_SUPPORTED,
	N_KM_ERR_VERIFKEY_NOT_SUPPORTED,
	N_KM_ERR_WRONG_KEY_SIZE,
	N_KM_ERR_INVAL,
	N_KM_ERR_SCL_INITIALIZATION_FAILURE,
	N_KM_ERR_,
	N_KM_ERR_MAX = N_KM_ERR_,
	N_KM_ERR_COUNT

} e_km_error;

/** Supported algorithms */
typedef enum
{
	/**  */
	N_KM_ALGO_MIN = 0,
#ifdef _SUPPORT_ALGO_AES_128_
	N_KM_ALGO_AES128,
#endif /* _SUPPORT_ALGO_AES_128_ */
#ifdef _SUPPORT_ALGO_AES_256_
	N_KM_ALGO_AES256,
#endif /* _SUPPORT_ALGO_AES_256_ */
#ifdef _SUPPORT_ALGO_RSA2048_
	N_KM_ALGO_RSA2048,
#endif /* _SUPPORT_ALGO_RSA2048_ */
#ifdef _SUPPORT_ALGO_RSA4096_
	N_KM_ALGO_RSA4096,
#endif /* _SUPPORT_ALGO_RSA4096_ */
#ifdef _SUPPORT_ALGO_ECDSA256_
	N_KM_ALGO_ECDSA256,
#endif /* _SUPPORT_ALGO_ECDSA256_ */
#ifdef _SUPPORT_ALGO_ECDSA384_
	N_KM_ALGO_ECDSA384,
#endif /* _SUPPORT_ALGO_ECDSA384_ */
	N_KM_ALGO_NONE,
	N_KM_ALGO_MAX = N_KM_ALGO_NONE,
	N_KM_ALGO_COUNT

} e_km_support_algos;

/** SBR key identifier */
typedef enum
{
	/**  */
	N_KM_KEYID_MIN = 0,
	N_KM_KEYID_STK = N_KM_KEYID_MIN,
	N_KM_KEYID_SSK = 0x2c,
	N_KM_KEYID_CUK = 0x5e,
	N_KM_KEYID_CSK = 0x84,
	N_KM_KEYID_PREVIOUS = 0xd7,
	/** Not relevant */
	N_KM_KEYID_MAX,
	N_KM_KEYID_COUNT

} e_km_keyid;

/** Structures ****************************************************************/
typedef struct __attribute__((packed))
{
	/** Algorithm */
	uint8_t										algo;
	/** Signing key identifier */
	uint8_t										sign_key_id;
	/** Key size in bits */
	uint16_t									key_size_bits;
	/** CSK */
	uint8_t										key[2 * C_EDCSA384_SIZE];
	/** CSK signature */
	uint8_t										certificate[2 * C_EDCSA384_SIZE];

} t_key_data;

typedef struct __attribute__((packed))
{
	/** Old CSK */
	uint8_t										old_csk[2 * C_EDCSA384_SIZE];
	/** New CSK */
	t_key_data									new_csk;
} t_update_csk;

typedef union __attribute__((packed))
{
	/** WRITE-CSK */
	t_key_data								write_csk;
	/** UPDATE-CSK */
	t_update_csk							update_csk;

} t_cmd_csk;


#if defined(_SUPPORT_ALGO_ECDSA256_) || defined(_SUPPORT_ALGO_ECDSA384_ )
typedef struct
{
	/** X */
	uint8_t										*p_x;
	/** Y */
	uint8_t										*p_y;

} t_km_key_ecdsa;
#endif /* ECDSA */

#if defined(_SUPPORT_ALGO_RSA2048_) || defined(_SUPPORT_ALGO_RSA4096_ )
typedef struct
{
	/** Modulus */
	uint8_t										*p_modulus;
	/** Exponent */
	uint8_t										*p_exponent;
} t_km_key_rsa;
#endif /* RSA */


typedef union
{
#if defined(_SUPPORT_ALGO_ECDSA256_) || defined(_SUPPORT_ALGO_ECDSA384_ )
	/**  */
	t_km_key_ecdsa								ecdsa;
#endif /* ECDSA */
#if defined(_SUPPORT_ALGO_RSA2048_) || defined(_SUPPORT_ALGO_RSA4096_ )
	/**  */
	t_km_key_rsa								rsa;
#endif /* RSA */

} u_km_key;


/** CSK parameters structure */
//typedef struct
//{
//	/** Signature size */
//	uint32_t									signature_size;
//	/** CSK descriptor - 4 Bytes */
//	uint8_t										*p_descriptor;
//	/** Pointer on CSK */
//	uint8_t										*p_csk;
//	/** Pointer on CSK's signature */
//	uint8_t										*p_csk_signature;
//
//} t_km_cskdata;

typedef struct
{
	/** Pointer on CSK descriptor */
//	t_km_cskdata								valid_csk;
	t_key_data									valid_csk;
	/** Index of last valid CSK */
	uint8_t										index_valid_csk;
	/** Index of first free CSK location */
	uint8_t										index_free_csk;
	/** Signing key identifier - it could be either SSK either CUK */
	struct __attribute__((packed))
	{
		/** Key identifier */
		e_km_keyid								id;
		/** Pointer on key */
		volatile uint8_t						*p_sign_key;
	} sign_key;

} t_km_context;

/** Functions *****************************************************************/
int32_t km_init(void *p_ctx, void *p_in, uint32_t length_in);
int32_t km_shutdown(void *p_ctx);
void km_check_key(t_context *p_ctx);
int32_t km_check_csk_slot(t_context *p_ctx, uint8_t slot);
int32_t km_check_csk(t_context *p_ctx);
int32_t km_get_key(e_km_keyid key_id, u_km_key *p_key, uint32_t *p_key_size);
//int32_t km_write_csk(uint8_t slot, t_key_data *p_cskdata);
int32_t km_verify_signature(uint8_t *p_message,
							uint32_t mess_length,
							uint8_t *p_signature,
							e_km_support_algos algo,
							u_km_key key);

/** Macros ********************************************************************/

#endif /* _KM_PUBLIC_H_ */

/* End Of File */
