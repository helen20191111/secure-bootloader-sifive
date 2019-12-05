/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */


/** Global includes */
#include <stdio.h>
#include <string.h>
/** Other includes */
#include <errors.h>
#include <common.h>
#include <otp_mapping.h>
#include <patch.h>
#include <scl_retdefs.h>
#include <scl_ecc.h>
#include <scl_hash_sha384.h>
#include <scl_ecdsa.h>
#include <sbrm_public.h>
/** Local includes */
#include <km_public.h>
#include <km_internal.h>

/** External declarations */
extern uint8_t ssk[2 * C_EDCSA384_SIZE];
extern uint8_t stk[2 * C_EDCSA384_SIZE];
extern scl_type_curve scl_secp384r1;
extern t_context context;
/** Local declarations */
/** SCL work buffer - size 8 kBytes / 2k (32bits) Words */
__attribute__((section(".bss"))) t_km_context km_context;
__attribute__((section(".data.patch.table"))) t_api_fcts km_fct_ptr =
{
		.initialize_fct = km_init,
		.shutdown_fct = km_shutdown,
		.read_fct = dummy_fct,
		.write_fct = dummy_fct,
		.gen1_fct = dummy_fct,
		.gen2_fct = dummy_fct,
		.gen3_fct = dummy_fct,
		.gen4_fct = dummy_fct,
};

/******************************************************************************/
int32_t km_init(void *p_ctx, void *p_in, uint32_t length_in)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Null pointer */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		t_context								*p_context = (t_context*)p_ctx;
		/** Assign pointer on local context structure */
		p_context->p_km_context = (volatile void*)&km_context;
		/** Initialize context structure */
		memset((void*)&km_context, 0x00, sizeof(t_km_context));
		/** Fill out parameters */
		/** For initialization, default value is invalid value - 0xff */
		km_context.index_free_csk = C_PATTERN_VIRGIN_8BITS;
		km_context.index_valid_csk = C_PATTERN_VIRGIN_8BITS;
		/** For initialization, default signing key is SSK */
		km_context.sign_key.id = N_KM_KEYID_SSK;
		/** Initializing SCL work buffer */
		if( !p_context->p_scl_work_buffer )
		{
			/** Pointer should not be null */
			err = GENERIC_ERR_NULL_PTR;
			goto km_init_out;
		}
		/**  */
		err = scl_init((word_type*)p_context->p_scl_work_buffer, ( p_context->scl_work_buffer_size / sizeof(word_type) ));
		if( err )
		{
			/** Error initializing SCL library */
			err = N_KM_ERR_SCL_INITIALIZATION_FAILURE;
		}
		else
		{
			/**  */
			if( !p_context->p_scl_hash_ctx )
			{
				/** Pointer should not be null */
				err = GENERIC_ERR_NULL_PTR;
				goto km_init_out;
			}
			/** Then initialize hash context */
			/** Initialize cryptographic library context for hash computation */
			err = scl_sha384_init((scl_sha384_ctx_t*)p_context->p_scl_hash_ctx);
			if ( err )
			{
				/** Error in cryptographic initialization */
				err = N_KM_ERR_SCL_INITIALIZATION_FAILURE;
			}
			else
			{
				/** No error; */
				err = NO_ERROR;
			}
		}
	}
km_init_out:
	/** End Of Function */
	return err;
}


/******************************************************************************/
int32_t km_shutdown(void *p_ctx)
{
	/** End Of Function */
	return NO_ERROR;
}


/******************************************************************************/
void km_check_key(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									i;
	uint32_t									offset = 0;
	uint32_t									descriptor;
	uint8_t										*p_desc = (uint8_t*)&descriptor;
	/** Warning !!! Here, the pointer is used only for key descriptor, not key value and its certificate  */
	t_key_data									*p_key_data = (t_key_data*)&descriptor;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
		/** Set default value even if it could be useless */
		km_context.sign_key.id = N_KM_KEYID_SSK;
	}
	else
	{
#warning When CUK is not valid, then SSK is used - It may not be appropriated
		/**  */
// _DBG_YG_
//		offset = M_GET_OTP_ABSOLUTE_ADDR(*p_ctx, C_OTP_MAPPING_CUK_DESC_OFST);
//		/* Retrieve CUK descriptor */
//		memcpy((void*)&descriptor,
//				(const void*)offset,
//				C_OTP_MAPPING_CUK_DESC_SIZE);
		err = sbrm_read_otp(p_ctx, C_OTP_MAPPING_CUK_DESC_OFST, (uint8_t*)&descriptor, C_OTP_MAPPING_CUK_DESC_SIZE);
		if( err )
		{
			/** Should not happen */
			goto km_check_key_out;
		}
		/** Check stored values */
		if( C_KM_CSK_DESCR_ALGO_ECDSA != p_key_data->algo )
		{
			/** No valid CUK, then use SSK */
			km_context.sign_key.id = N_KM_KEYID_SSK;
		}
		else if( ( C_EDCSA384_SIZE * 8 ) != p_key_data->key_size_bits )
		{
			/** No valid CUK, then use SSK */
			km_context.sign_key.id = N_KM_KEYID_SSK;
		}
		/**  */
		else
		{
			/** Descriptor parameters look ok, then use CUK */
			km_context.sign_key.id = N_KM_KEYID_CUK;
		}
		/** Then search for valid CSK if any */
		err = km_check_csk(p_ctx);
		if( err )
		{
			/** Either no CSK in storage area, either an error occurred and CSK cannot be trusted */
			km_context.index_free_csk = 0;
			km_context.index_valid_csk = C_PATTERN_VIRGIN_8BITS;
			/** Free CSK structure */
			memset((void*)&km_context.valid_csk, 0x00, sizeof(km_context.valid_csk));
		}
	}
km_check_key_out:
	/** End Of Function */
	return;
}

/******************************************************************************/
int32_t km_check_csk_slot(t_context *p_ctx, uint8_t slot)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	register uint32_t							i;
	t_key_data									csk_area;

	if( !p_ctx )
	{
		/** Pointer must not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto km_check_csk_slot_out;
	}
	else
	{
		uint8_t									*p_csk_area = (uint8_t*)&csk_area;

		/** Check input slot */
		if( C_OTP_MAPPING_NB_CSK_SLOTS > slot )
		{
			/** Set return value if area is virgin */
			err = NO_ERROR;
			/** Point on requested CSK slot */
// _DBG_YG_
//			p_csk_area = (uint8_t*)(M_GET_OTP_ABSOLUTE_ADDR(context,( C_OTP_MAPPING_CSK_OFST + ( slot * C_OTP_MAPPING_CSK_AERA_SIZE ) ) ));
			err = sbrm_read_otp(p_ctx,
								( C_OTP_MAPPING_CSK_OFST + ( slot * C_OTP_MAPPING_CSK_AERA_SIZE ) ),
								p_csk_area,
								C_OTP_MAPPING_CSK_AERA_SIZE);
			if( err )
			{
				/** Should not happen */
				goto km_check_csk_slot_out;
			}
			/** Check area */
			for( i = 0;i < C_OTP_MAPPING_CSK_AERA_SIZE;i++ )
			{
				/** Check virgin pattern */
				if ( C_PATTERN_VIRGIN_8BITS != p_csk_area[i] )
				{
					/** Not virgin */
					err = N_KM_ERR_NOT_VIRGIN;
					break;
				}
			}
		}
		else
		{
			err = N_KM_ERR_NO_INDEX;
		}
	}
km_check_csk_slot_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t km_check_csk(t_context *p_ctx)
{
	int8_t										slot;
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint32_t									key_size = 0;
	uint8_t										*p_key;
	u_km_key									key;
	t_key_data									key_ref;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Find valid CSK in storage area */
		for( slot = C_OTP_MAPPING_CSK_SLOT_MAX;slot >= 0;slot-- )
		{
			/** Point on chosen CSK data */
			err = km_check_csk_slot(p_ctx, slot);
			if( N_KM_ERR_NOT_VIRGIN == err )
			{
				/** CSK's descriptor is not virgin therefore check if algorithm is supported */
				err = sbrm_read_otp(p_ctx,
									( C_OTP_MAPPING_CSK_OFST + ( slot * C_OTP_MAPPING_CSK_AERA_SIZE ) ),
									(uint8_t*)&km_context.valid_csk,
									C_OTP_MAPPING_CSK_AERA_SIZE);
				if( err )
				{
					/** Should not happen */
					goto km_check_csk_out;
				}
				/** Algorithm is supported, now check CSK's signature */
				if( C_KM_CSK_DESCR_ALGO_ECDSA != km_context.valid_csk.algo )
				{
					/** Algorithm not supported */
					err = N_KM_ERR_ALGO_NOT_SUPPORTED;
					continue;
				}
				/** Then check if verification key is supported */
				else if( ( C_KM_CSK_DESCR_VERIF_KEY_SSK != km_context.valid_csk.sign_key_id ) &&
						( C_KM_CSK_DESCR_VERIF_KEY_CUK != km_context.valid_csk.sign_key_id ) )
				{
					/** Verification key not supported */
					err = N_KM_ERR_VERIFKEY_NOT_SUPPORTED;
					continue;
				}
				else if( ( C_EDCSA384_SIZE * 8 ) != km_context.valid_csk.key_size_bits )
				{
					/** Size doesn't match */
					err = N_KM_ERR_WRONG_KEY_SIZE;
					continue;
				}
				else if( C_KM_CSK_DESCR_VERIF_KEY_CUK == km_context.valid_csk.sign_key_id )
				{
					/** Point on CUK */
					err = km_get_key(N_KM_KEYID_CUK,
										(u_km_key*)&key,
										(uint32_t*)&key_size);
				}
				else
				{
					/** Point on SSK */
					err = km_get_key(N_KM_KEYID_SSK,
										(u_km_key*)&key,
										(uint32_t*)&key_size);
				}
				/** Check CSK with retrieved verification key*/
				if( NO_ERROR == err )
				{
					uint32_t					mess_length;

					/** Size of CSK data structure minus certificate/signature size */
					mess_length = sizeof(t_key_data) - C_OTP_MAPPING_CSK_KEY_SIZE;
					/** Verify key signature */
					err = km_verify_signature((uint8_t*)&km_context.valid_csk,
												mess_length,
												(uint8_t*)km_context.valid_csk.certificate,
												N_KM_ALGO_ECDSA384,
												key);
					if( NO_ERROR == err )
					{
						/** Set valid CSK slot */
						km_context.index_valid_csk = slot;
						/** Set free slot index, if any */
						if( C_OTP_MAPPING_CSK_SLOT_MAX == km_context.index_valid_csk )
						{
							/** No more free slot, no more room to store CSK */
							km_context.index_free_csk = C_PATTERN_VIRGIN_8BITS;
						}
						/** Then exit */
						goto km_check_csk_out;
					}
				}
				else
				{
					/** Critical error, should not happen */
					goto km_check_csk_out;
				}
			}
			/** Slot if free to use */
			else if( NO_ERROR == err )
			{
				/** Update free slot */
				if( km_context.index_free_csk > slot )
				{
					/** Free slot updated */
					km_context.index_free_csk = slot;
				}
			}
			else
			{
				/** Unwanted error */
				goto km_check_csk_out;
			}
		}
		/** Interpret loop result */
		if( ( C_PATTERN_VIRGIN_8BITS == km_context.index_valid_csk ) && ( C_PATTERN_VIRGIN_8BITS == km_context.index_free_csk ) )
		{
			/** All slots are occupied; but here, it means no CSK is valid */
			err = N_KM_ERR_NO_FREE_LOCATION;
		}
		else if( !km_context.index_free_csk && ( C_PATTERN_VIRGIN_8BITS == km_context.index_valid_csk ) )
		{
			/** All slots are free, then no CSK is present */
			err = N_KM_ERR_NO_CSK;
		}
#warning Ici, il y a sans doute des chemins à couvrir pour les index de csk valide et csk free slot
	}
km_check_csk_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int32_t km_get_key(e_km_keyid key_id, u_km_key *p_key, uint32_t *p_key_size)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;
	uint8_t										*p_tmp = (uint8_t*)p_key;

	/** Check input parameters - case '*p_key' null is not relevant */
	if( !p_key || !p_key_size )
	{
		/** At least, one pointer is null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Choose key */
		switch( key_id )
		{
			case N_KM_KEYID_STK:
				/** Assign already existing array */
				p_key->ecdsa.p_x = (uint8_t*)stk;
				p_key->ecdsa.p_y = (uint8_t*)( p_key->ecdsa.p_x + C_EDCSA384_SIZE );
				/** Set key size */
				*p_key_size = (uint32_t)sizeof(stk);
				/** No error */
				err = NO_ERROR;
				break;
			case N_KM_KEYID_SSK:
				/** Assign already existing array */
				p_key->ecdsa.p_x = (uint8_t*)ssk;
				p_key->ecdsa.p_y = (uint8_t*)( p_key->ecdsa.p_x + C_EDCSA384_SIZE );
				/** Set key size */
				*p_key_size = (uint32_t)sizeof(ssk);
				/** No error */
				err = NO_ERROR;
				break;
			case N_KM_KEYID_CUK:
				/** Assign already existing array */
				p_key->ecdsa.p_x = (uint8_t*)M_GET_OTP_ABSOLUTE_ADDR(context, C_OTP_MAPPING_CUK_OFST);
				p_key->ecdsa.p_y = (uint8_t*)( p_key->ecdsa.p_x + C_EDCSA384_SIZE );
				/** Set key size */
				*p_key_size = (uint32_t)C_OTP_MAPPING_CUK_SIZE;
				/** No error */
				err = NO_ERROR;
				break;
			case N_KM_KEYID_CSK:
				if( km_context.valid_csk.algo )
				{
					/** Return pointer on CSK location */
					p_key->ecdsa.p_x = km_context.valid_csk.key;
					p_key->ecdsa.p_y = (uint8_t*)( p_key->ecdsa.p_x + C_EDCSA384_SIZE );
					/** Set key size */
					*p_key_size = (uint32_t)sizeof(km_context.valid_csk.key);
					/** No error */
					err = NO_ERROR;
				}
				else
				{
					/** No CSK available */
					err = N_KM_ERR_NO_CSK;
				}
				break;
			default:
				err = N_KM_ERR_NO_KEY;
				break;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
//int32_t km_write_csk(uint8_t slot, t_key_data *p_cskdata)
//{
//	int32_t										err = GENERIC_ERR_UNKNOWN;
//	u_km_key									key;
//
//	/** Check input parameters */
//	if( !p_cskdata )
//	{
//		/** Input pointer is null */
//		err = GENERIC_ERR_NULL_PTR;
//	}
//	else if( C_OTP_MAPPING_NB_CSK_SLOTS <= slot )
//	{
//		/** Slot doesn't fit ... */
//		err = N_KM_ERR_INVAL;
//	}
//	else
//	{
//		uint32_t								mess_length;
//		/**  */
//		key.ecdsa.p_x = (uint8_t*)ssk;
//		key.ecdsa.p_y = (uint8_t*)&ssk[C_EDCSA384_SIZE];
//		/** Key size * 2 / 8bits */
//		mess_length = ( p_cskdata->key_size_bits * 2 ) / 8 + C_KM_CSK_DESCR_CSK_SIZE_IN_BYTES;
//		/** Check CSK signature - buffer where is stored CSK must gathers descriptor and CSK itself */
//		err = km_verify_signature((uint8_t*)&p_cskdata->algo,
//									mess_length,
//									p_cskdata->certificate,
//									N_KM_ALGO_ECDSA384,
//									key);
//		if( err )
//		{
//			/** CSK in message is not valid, it should not happen */
//			err = N_KM_ERR_INVALID_SIGNATURE;
//		}
//		else
//		{
//			/** Now program CSK into designated slot, that should be free */
//			err = km_program_csk(slot, p_cskdata);
//		}
//	}
//	/** End Of Function */
//	return err;
//}

/******************************************************************************/
int32_t km_verify_signature(uint8_t *p_message,
							uint32_t mess_length,
							uint8_t *p_signature,
							e_km_support_algos algo,
							u_km_key key)
{
	uint8_t										loop;
	int32_t										err[C_KM_VERIFY_LOOP_MAX];
	scl_type_ecc_uint8_t_affine_point			Q;
	scl_type_ecdsa_signature					signature;


	/** Initialize error array */
	for( loop = 0;loop < C_KM_VERIFY_LOOP_MAX;loop++ )
	{
		err[loop] = GENERIC_ERR_UNKNOWN;
	}
	/** Check input pointers */
	if( ( NULL == p_message ) ||
		( NULL == p_signature ) )
	{
		/** At least one of the pointers is null */
		err[0] = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Check algorithm */
		switch( algo )
		{
#ifdef _SUPPORT_ALGO_RSA2048_
		case N_KM_ALGO_RSA2048:
			break;
#endif /* _SUPPORT_ALGO_RSA2048_ */
#ifdef _SUPPORT_ALGO_RSA4096_
		case N_KM_ALGO_RSA4096:
			break;
#endif /* _SUPPORT_ALGO_RSA4096_ */
#ifdef _SUPPORT_ALGO_ECDSA256_
		case N_KM_ALGO_ECDSA256:
			break;
#endif /* _SUPPORT_ALGO_ECDSA256_ */
#ifdef _SUPPORT_ALGO_ECDSA384_
		case N_KM_ALGO_ECDSA384:
			break;
#endif /* _SUPPORT_ALGO_ECDSA384_ */
		default:
			err[0] = N_KM_ERR_ALGO_NOT_SUPPORTED;
			goto km_verify_signature_out;
		}
		/** Algorithm is supported then call cryptographic library */
		for( loop = 0;loop < C_KM_VERIFY_LOOP_MAX;loop++ )
		{
			/** Set parameters */
			Q.x = key.ecdsa.p_x;
			Q.y = key.ecdsa.p_y;
			signature.r = p_signature;
			signature.s = p_signature + C_EDCSA384_SIZE;
			err[loop] = scl_ecdsa_verification(Q,
											signature,
											scl_sha384,
											p_message,
											mess_length,
											&scl_secp384r1,
											( SCL_MSG_INPUT_TYPE << SCL_INPUT_SHIFT ) ^
											( SCL_SHA384_ID << SCL_HASH_SHIFT ));
		}
	}
	/** If one of the returned value is not Ok then error */
	for( loop = 0;loop < C_KM_VERIFY_LOOP_MAX;loop++ )
	{
		if ( err[loop] )
		{
			/** Set error value to default index */
			err[0] = err[loop];
			break;
		}
	}
km_verify_signature_out:
	/** End Of Function */
	return err[0];
}

/******************************************************************************/
/* End Of File */
