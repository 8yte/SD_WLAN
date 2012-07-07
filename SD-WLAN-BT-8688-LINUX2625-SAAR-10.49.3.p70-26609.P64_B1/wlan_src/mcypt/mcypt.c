/** @file mcypt.c
 *
 *  @brief This file declares the exported symbols for encryption.
 *
 *  Copyright (C) 2009, Marvell International Ltd. 
 *  All Rights Reserved
 */

/******************************************************
Change log:
    02/13/2009: initial version
******************************************************/
#include <linux/module.h>

/** status success */
#define STATUS_SUCCESS 0
/** status failure */
#define STATUS_FAILURE -1

/********************************************************
		Local Variables
********************************************************/
/** Sbox */
const u8 Sbox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2,
        0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26,
        0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43,
        0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
        0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19,
        0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b,
        0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b,
        0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7,
        0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce,
        0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
        0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab,
        0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72,
        0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41,
        0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12,
        0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09,
        0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e,
        0xd7, 0xcb, 0x39, 0x48
};

/** circular rotate left */
#define ROTLEFT(A,B) ((A<<B)|(A>>(32-B)))

/** TOW */
#define TOW(A)    (Sbox[((u32)A)>>24 & 0xFF]<<24 |\
                   Sbox[((u32)A)>>16 & 0xFF]<<16 |\
                   Sbox[((u32)A)>>8  & 0xFF]<<8  |\
                   Sbox[((u32)A)     & 0xFF] )

/** L */
#define L(B)      ( B^ROTLEFT(B,2)^ROTLEFT(B,10)^ROTLEFT(B,18)^ROTLEFT(B,24))

/** LPRIME */
#define LPRIME(B) ( B^ROTLEFT(B,13)^ROTLEFT(B,23))

/**  Key computation */
#define KEY(N)    TPrime(K[N-3]^K[N-2]^K[N-1]^CK[N-4])^K[N-4]

#ifndef BIG_ENDIAN
#define RTOL16(x)   ((x<<16)|(x>>16))
#define swap_byte_32(x) (((RTOL16(x) & 0xFF00FF) << 8) ^ ((RTOL16(x) & 0xFF00FF00) >> 8))
#else
/** 32 bits byte swap */
#define swap_byte_32(x) x
#endif

/********************************************************
		Global Variables
********************************************************/

/********************************************************
		Local Functions
********************************************************/
/**
 *  @brief This function calculates the TPrime for B 
 *  
 *  @param B        (b0,b1,b2,b3) 4 bytes
 *
 *  @return 	    TPrime value
 */
static inline u32
TPrime(u32 B)
{
    register u32 temp;
    temp = TOW(B);
    return (LPRIME(temp));
}

/**
 *  @brief This function encrypts using sms4 algorithm
 *  
 *  @param plaintext   A pointer to array of 4 uint32's 
 *  @param K           A pointer to round_key buffer of 32 uint32's     
 *  @param ciphertext  A pointer to array of 4 uint32's (encrypted text) 
 *  @return 	        N/A
 */
static inline void
sms4_encrypt(u32 * plaintext, u32 * K, u32 * ciphertext)
{
    register u32 tmp;
    register u32 Xr0, Xr1, Xr2, Xr3;
    int i;

    Xr0 = swap_byte_32(plaintext[0]);
    Xr1 = swap_byte_32(plaintext[1]);
    Xr2 = swap_byte_32(plaintext[2]);
    Xr3 = swap_byte_32(plaintext[3]);

    for (i = 0; i < 32; i += 4) {
        tmp = TOW(Xr1 ^ Xr2 ^ Xr3 ^ K[i]);
        tmp = L(tmp);
        Xr0 = Xr0 ^ tmp;

        tmp = TOW(Xr2 ^ Xr3 ^ Xr0 ^ K[i + 1]);
        tmp = L(tmp);
        Xr1 = Xr1 ^ tmp;

        tmp = TOW(Xr3 ^ Xr0 ^ Xr1 ^ K[i + 2]);
        tmp = L(tmp);
        Xr2 = Xr2 ^ tmp;

        tmp = TOW(Xr0 ^ Xr1 ^ Xr2 ^ K[i + 3]);
        tmp = L(tmp);
        Xr3 = Xr3 ^ tmp;
    }
    ciphertext[0] = swap_byte_32(Xr3);
    ciphertext[1] = swap_byte_32(Xr2);
    ciphertext[2] = swap_byte_32(Xr1);
    ciphertext[3] = swap_byte_32(Xr0);
}

/********************************************************
		Global functions
********************************************************/
/**
 *  @brief This function do packet encryption/decryption 
 *  
 *  @param iv           A pointer to IV buffer 
 *  @param buf_in       A pointer to plain txt buffer      
 *  @param len          len of buf_in buffer
 *  @param rk           A pointer to expand key buffer
 *  @param buf_out      A pointer to output crypted txt buffer
 *  @return 	        WAPI_STATUS_SUCCESS or WAPI_STATUS_FAILURE
 */
int
mencrypt_decrypt(u8 * iv, u8 * buf_in, u32 len, u32 * rk, u8 * buf_out)
{
    u32 count, left;
    u32 iv_tmp[4];
    u32 *in = (u32 *) buf_in;
    u32 *out = (u32 *) buf_out;
    u8 *uIn, *uOut, *uIv;
    int i;

    if (len == 0) {
        return STATUS_FAILURE;
    }

    count = len / 16;
    left = len % 16;

    sms4_encrypt((u32 *) iv, (u32 *) rk, (u32 *) iv_tmp);

    for (i = 0; i < count; i++) {
        out[0] = in[0] ^ iv_tmp[0];
        out[1] = in[1] ^ iv_tmp[1];
        out[2] = in[2] ^ iv_tmp[2];
        out[3] = in[3] ^ iv_tmp[3];
        sms4_encrypt((u32 *) iv_tmp, (u32 *) rk, (u32 *) iv_tmp);
        in += 4;
        out += 4;
    }
    uIn = (u8 *) in;
    uOut = (u8 *) out;
    uIv = (u8 *) iv_tmp;
    for (i = 0; i < left; i++) {
        uOut[i] = uIn[i] ^ uIv[i];
    }
    return STATUS_SUCCESS;
}

/**
 *  @brief This function caculate mic value.
 *  
 *  @param iv           A pointer to IV buffer
 *  @param icd          A pointer to integrity check data buffer      
 *  @param icd_len      Length of integrity check data buffer
 *  @param data         A pointer to data buffer
 *  @param data_len     Length of data buffer
 *  @param mic_rk       A pointer to icd expand key buffer
 *  @param mic          A pointer of mic buffer
 *  @return 	        WLAN_STATUS_SUCCESS or WLAN_STATUS_FAILURE
 */
int
mgen_mic(u8 * iv, u8 * icd, u32 icd_len, u8 * data, u32 data_len, u32 * mic_rk,
         u8 * mic)
{
    u32 mic_tmp[4];
    u32 *pdata = NULL;
    u32 len = 0;
    int i;

    if ((icd_len == 0) || (data_len > 4096)) {
        return STATUS_FAILURE;
    }

    sms4_encrypt((u32 *) iv, (u32 *) mic_rk, (u32 *) mic_tmp);

    pdata = (u32 *) icd;
    len = icd_len / 16;
    for (i = 0; i < len; i++) {
        mic_tmp[0] ^= pdata[0];
        mic_tmp[1] ^= pdata[1];
        mic_tmp[2] ^= pdata[2];
        mic_tmp[3] ^= pdata[3];
        pdata += 4;
        sms4_encrypt((u32 *) mic_tmp, (u32 *) mic_rk, (u32 *) mic_tmp);
    }

    pdata = (u32 *) data;
    len = data_len / 16;
    for (i = 0; i < len; i++) {
        mic_tmp[0] ^= pdata[0];
        mic_tmp[1] ^= pdata[1];
        mic_tmp[2] ^= pdata[2];
        mic_tmp[3] ^= pdata[3];
        pdata += 4;
        sms4_encrypt((u32 *) mic_tmp, (u32 *) mic_rk, (u32 *) mic_tmp);
    }

    memcpy(mic, mic_tmp, sizeof(mic_tmp));

    return STATUS_SUCCESS;
}

/**
 *  @brief This function calculates the expand key
 *  
 *  @param key          A pointer to array of 4 uint32's key
 *  @param ex_key       A pointer to expand key buffuer (32 uint32)  
 *  @return 	        N/A
 */
void
mkey_expand(u32 * key, u32 * ex_key)
{
    const u32 CK[32] = { 0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    };
    u32 K[36];

    K[0] = swap_byte_32(key[0]) ^ 0xa3b1bac6;
    K[1] = swap_byte_32(key[1]) ^ 0x56aa3350;
    K[2] = swap_byte_32(key[2]) ^ 0x677d9197;
    K[3] = swap_byte_32(key[3]) ^ 0xb27022dc;

    K[4] = KEY(4);
    K[5] = KEY(5);

    K[6] = KEY(6);
    K[7] = KEY(7);
    K[8] = KEY(8);
    K[9] = KEY(9);
    K[10] = KEY(10);
    K[11] = KEY(11);
    K[12] = KEY(12);
    K[13] = KEY(13);
    K[14] = KEY(14);
    K[15] = KEY(15);
    K[16] = KEY(16);
    K[17] = KEY(17);
    K[18] = KEY(18);
    K[19] = KEY(19);
    K[20] = KEY(20);
    K[21] = KEY(21);
    K[22] = KEY(22);
    K[23] = KEY(23);
    K[24] = KEY(24);
    K[25] = KEY(25);
    K[26] = KEY(26);
    K[27] = KEY(27);
    K[28] = KEY(28);
    K[29] = KEY(29);
    K[30] = KEY(30);
    K[31] = KEY(31);
    K[32] = KEY(32);
    K[33] = KEY(33);
    K[34] = KEY(34);
    K[35] = KEY(35);

    memcpy(ex_key, &K[4], sizeof(u32) * 32);
}

EXPORT_SYMBOL(mkey_expand);
EXPORT_SYMBOL(mgen_mic);
EXPORT_SYMBOL(mencrypt_decrypt);
MODULE_VERSION("mcrypt_v001");
MODULE_LICENSE("Marvell Proprietary");
