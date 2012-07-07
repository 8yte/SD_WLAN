/** @file mcypt.h
 *
 *  @brief This file declares all encryption/decryption APIs
 *
 *  Copyright (C) 2009, Marvell International Ltd. 
 *  All Rights Reserved
 */

/******************************************************
Change log:
    02/13/2009: initial version
******************************************************/

#ifndef _MCYPT_H_
#define _MCYPT_H_
/** encrypt/decrypt data pkt */
int mencrypt_decrypt(u8 * iv, u8 * buf_in, u32 len, u32 * rk, u8 * buf_out);
/** generic mic data */
int mgen_mic(u8 * iv, u8 * icd, u32 icd_len, u8 * data,
             u32 data_len, u32 * mic_rk, u8 * mic);
/** key expand function */
void mkey_expand(u32 * key, u32 * ex_key);
#endif /* !_MCYPT_H_ */
