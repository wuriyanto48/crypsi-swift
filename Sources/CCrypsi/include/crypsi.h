/*
The MIT License (MIT)

Copyright (c) 2023 The TelkomDev Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef CRYPSI_H
#define CRYPSI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

#define HEX_STRINGS "0123456789abcdef"
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define HMAC_KEY_MIN_SIZE 32

static unsigned char HEX_LOOKUP[22];

static const unsigned char HEX_TABLE[][2] = {
    {0x30, 0}, 
    {0x31, 1}, 
    {0x32, 2}, 
    {0x33, 3}, 
    {0x34, 4}, 
    {0x35, 5}, 
    {0x36, 6}, 
    {0x37, 7}, 
    {0x38, 8}, 
    {0x39, 9}, 
    {0x61, 10}, 
    {0x62, 11}, 
    {0x63, 12}, 
    {0x64, 13}, 
    {0x65, 14}, 
    {0x66, 15}, 
    {0x41, 10}, 
    {0x42, 11}, 
    {0x43, 12}, 
    {0x44, 13}, 
    {0x45, 14}, 
    {0x46, 15}};

enum crypsi_aes_key {
    CRYPSI_AES_128_KEY = 16,
    CRYPSI_AES_192_KEY = 24,
    CRYPSI_AES_256_KEY = 32
};

enum crypsi_aes_mode {
    CRYPSI_AES_CBC_MODE,
    CRYPSI_AES_GCM_MODE,
};

enum crypsi_digest_alg {
    CRYPSI_MD5,
    CRYPSI_SHA1,
    CRYPSI_SHA256,
    CRYPSI_SHA384,
    CRYPSI_SHA512,
};

enum crypsi_rsa_modulus {
    CRYPSI_RSA_MODULUS_1024 = 1 << 10,
    CRYPSI_RSA_MODULUS_2048 = 1 << 11,
    CRYPSI_RSA_MODULUS_4096 = 1 << 12
};

#ifdef __cplusplus
extern "C" {
#endif

// utilities
int hexencode(const unsigned char* message, size_t message_len, 
    unsigned char** dst, unsigned int* dst_len);
int hexdecode(const unsigned char* message, size_t message_len, 
    unsigned char** dst, unsigned int* dst_len);
unsigned char find_hex_val(unsigned char hx);
static void initialize_hex_lookup();

// AES
static int crypsi_aes_cbc_encrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);
static int crypsi_aes_cbc_decrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);

static int crypsi_aes_gcm_encrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);
static int crypsi_aes_gcm_decrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);

// AES CBC
int crypsi_aes_128_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_192_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_256_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

int crypsi_aes_128_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_192_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_256_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

// AES GCM
int crypsi_aes_128_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_192_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_256_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

int crypsi_aes_128_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_192_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_256_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

// message digest
static int crypsi_digest(enum crypsi_digest_alg alg, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_md5(const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha1(const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha256(const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha384(const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha512(const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);

// hmac
static int crypsi_hmac(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_hmac_md5(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_hmac_sha1(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_hmac_sha256(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_hmac_sha384(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_hmac_sha512(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);

// RSA
int crypsi_rsa_generate_key_pairs(int size, unsigned char** private_key_buf, 
    int* private_key_buf_len, unsigned char** public_key_buf, int* public_key_buf_len);
int crypsi_rsa_load_private_key(const unsigned char* buffer, EVP_PKEY** private_key_dst);
int crypsi_rsa_load_public_key(const unsigned char* buffer, EVP_PKEY** public_key_dst);

// RSA Encryption with OAEP (Optimal Asymmetric Encryption Padding)
static int crypsi_rsa_encrypt_oaep(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_encrypt_oaep_md5(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_encrypt_oaep_sha1(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_encrypt_oaep_sha256(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_encrypt_oaep_sha384(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_encrypt_oaep_sha512(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

static int crypsi_rsa_decrypt_oaep(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_decrypt_oaep_md5(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_decrypt_oaep_sha1(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_decrypt_oaep_sha256(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_decrypt_oaep_sha384(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_decrypt_oaep_sha512(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

// RSA DIGITAL SIGNATURE with PSS padding
static int crypsi_rsa_sign_pss(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_sign_pss_md5(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_sign_pss_sha1(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_sign_pss_sha256(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_sign_pss_sha384(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_rsa_sign_pss_sha512(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

static int crypsi_rsa_verify_sign_pss(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char* signature, size_t signature_len);
int crypsi_rsa_verify_sign_pss_md5(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char* signature, size_t signature_len);
int crypsi_rsa_verify_sign_pss_sha1(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char* signature, size_t signature_len);
int crypsi_rsa_verify_sign_pss_sha256(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char* signature, size_t signature_len);
int crypsi_rsa_verify_sign_pss_sha384(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char* signature, size_t signature_len);
int crypsi_rsa_verify_sign_pss_sha512(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char* signature, size_t signature_len);

#ifdef __cplusplus
}
#endif

static void initialize_hex_lookup() {
    for (int i = 0; i < sizeof(HEX_TABLE) / sizeof(HEX_TABLE[0]); i++) {
        HEX_LOOKUP[HEX_TABLE[i][0]] = HEX_TABLE[i][1];
    }
}

unsigned char find_hex_val(unsigned char hx) {
    return HEX_LOOKUP[hx];
}

int hexencode(const unsigned char* message, size_t message_len, 
    unsigned char** dst, unsigned int* dst_len) {
    
    int ret = -1;
    int result_len = message_len*2+1;
    unsigned char* _dst = (unsigned char*) malloc(result_len);
    if (_dst == NULL) {
        goto cleanup;
    }

    *dst_len = result_len-1;

    for (int i = 0; i < message_len; i++ ) {
        _dst[i+i] = HEX_STRINGS[message[i] >> 0x4];
        _dst[i+i+1] = HEX_STRINGS[message[i] & 0xf];
    }

    _dst[result_len-1] = 0x0;
    *dst = _dst;

    ret = 0;

    cleanup:
        return ret;
}

int hexdecode(const unsigned char* message, size_t message_len, 
    unsigned char** dst, unsigned int* dst_len) {
    
    int ret = -1;

    // Ensure message_len is valid
    // hex string size is always even
    if (message_len == 0 || message_len % 2 != 0) {
        return ret;
    }

    // init hex lookup
    initialize_hex_lookup();
    
    int result_len = message_len/2+1;
    unsigned char* _dst = (unsigned char*) malloc(result_len);
    if (_dst == NULL) {
        goto cleanup;
    }

    *dst_len = result_len-1;

    for (int i = 0; i < result_len - 1; i++ ) {
        unsigned char ca = find_hex_val(message[i+i]);
        unsigned char cb = find_hex_val(message[i+i+1]);

        _dst[i] = (ca << 4) | cb;
    }

    _dst[result_len-1] = 0x0;
    *dst = _dst;

    ret = 0;

    cleanup:
        return ret;
}

// MESSAGE DIGEST
static int crypsi_digest(enum crypsi_digest_alg alg, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_MD_CTX* mdctx = NULL;
    EVP_MD* md = NULL;

    int ret = -1;
    unsigned int dst_len_tmp = 0;
    unsigned char* dst_tmp = NULL;

    switch (alg) {
    case CRYPSI_MD5:
        md = (EVP_MD*) EVP_md5();
        break;
    case CRYPSI_SHA1:
        md = (EVP_MD*) EVP_sha1();
        break;
    case CRYPSI_SHA256:
        md = (EVP_MD*) EVP_sha256();
        break;
    case CRYPSI_SHA384:
        md = (EVP_MD*) EVP_sha384();
        break;
    case CRYPSI_SHA512:
        md = (EVP_MD*) EVP_sha512();
        break;
    default:
        return ret;
    }

    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        goto cleanup;
    }

    if(1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        goto cleanup;
    }

    if(1 != EVP_DigestUpdate(mdctx, message, message_len)) {
        goto cleanup;
    }

    if((dst_tmp = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md))) == NULL) {
        goto cleanup;
    }

    if(1 != EVP_DigestFinal_ex(mdctx, dst_tmp, &dst_len_tmp)) {
        goto cleanup;
    }

    // encode to hex
    if(hexencode(dst_tmp, dst_len_tmp, dst, dst_len) != 0) {
        goto cleanup;
    }

    ret = 0;

    cleanup:
        if (mdctx != NULL) {
            EVP_MD_CTX_free(mdctx);
        }

        if (dst_tmp != NULL) {
            OPENSSL_free(dst_tmp);
        }

        return ret;
}

int crypsi_md5(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_MD5, message, message_len, dst, dst_len);
}

int crypsi_sha1(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA1, message, message_len, dst, dst_len);
}

int crypsi_sha256(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA256, message, message_len, dst, dst_len);
}

int crypsi_sha384(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA384, message, message_len, dst, dst_len);
}

int crypsi_sha512(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA512, message, message_len, dst, dst_len);
}

// HMAC
static int crypsi_hmac(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    
    EVP_MD_CTX* mdctx = NULL;
    EVP_MD* md = NULL;
    EVP_PKEY* pkey = NULL;

    int ret = -1;
    size_t dst_len_tmp = 0;
    unsigned char* dst_tmp = NULL;

    if (strlen((char*) key) < HMAC_KEY_MIN_SIZE) {
        return ret;
    }

    switch (alg) {
    case CRYPSI_MD5:
        md = (EVP_MD*) EVP_md5();
        break;
    case CRYPSI_SHA1:
        md = (EVP_MD*) EVP_sha1();
        break;
    case CRYPSI_SHA256:
        md = (EVP_MD*) EVP_sha256();
        break;
    case CRYPSI_SHA384:
        md = (EVP_MD*) EVP_sha384();
        break;
    case CRYPSI_SHA512:
        md = (EVP_MD*) EVP_sha512();
        break;
    default:
        return ret;
    }

    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        goto cleanup;
    }

    if(!(pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen((char*) key)))) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey)) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignUpdate(mdctx, message, message_len)) {
        goto cleanup;
    }

    if((dst_tmp = (unsigned char*) OPENSSL_malloc(EVP_MD_size(md))) == NULL) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignFinal(mdctx, dst_tmp, &dst_len_tmp)) {
        goto cleanup;
    }

    // encode to hex
    if(hexencode(dst_tmp, dst_len_tmp, dst, dst_len) != 0) {
        goto cleanup;
    }

    ret = 0;

    cleanup:
        if (mdctx != NULL) {
            EVP_MD_CTX_free(mdctx);
        }

        if (pkey != NULL) {
            EVP_PKEY_free(pkey);
        }

        if (dst_tmp != NULL) {
            OPENSSL_free(dst_tmp);
        }

        return ret;
}

int crypsi_hmac_md5(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_hmac(CRYPSI_MD5, key, message, message_len, dst, dst_len);
}

int crypsi_hmac_sha1(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_hmac(CRYPSI_SHA1, key, message, message_len, dst, dst_len);
}

int crypsi_hmac_sha256(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_hmac(CRYPSI_SHA256, key, message, message_len, dst, dst_len);
}

int crypsi_hmac_sha384(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_hmac(CRYPSI_SHA384, key, message, message_len, dst, dst_len);
}

int crypsi_hmac_sha512(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_hmac(CRYPSI_SHA512, key, message, message_len, dst, dst_len);
}

// AES
static int crypsi_aes_cbc_encrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER* cipher = NULL;

    int ret = -1;
    int dst_len_tmp = 0;
    int ciphertext_len = 0;
    int result_len_raw = 0;
    unsigned char* dst_tmp_raw = NULL; 
    unsigned char* dst_tmp = NULL;
    unsigned char iv[AES_BLOCK_SIZE];

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    int raw_ciphertext_len = data_len + (AES_BLOCK_SIZE - data_len%AES_BLOCK_SIZE) + 1;

    switch (aes_key_size) {
    case CRYPSI_AES_128_KEY:
        if (strlen((char*) key) != CRYPSI_AES_128_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_128_cbc();
        break;
    case CRYPSI_AES_192_KEY:
        if (strlen((char*) key) != CRYPSI_AES_192_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_192_cbc();
        break;
    case CRYPSI_AES_256_KEY:
        if (strlen((char*) key) != CRYPSI_AES_256_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_256_cbc();
        break;
    default:
        return ret;
    }

    if((dst_tmp_raw = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        goto cleanup;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto cleanup;
    }
    
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        goto cleanup;
    }
    
    if(EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto cleanup;
    }

    if(EVP_EncryptUpdate(ctx, dst_tmp_raw, &dst_len_tmp, data, data_len) != 1) {
        goto cleanup;
    }
    
    ciphertext_len = dst_len_tmp;

    if(EVP_EncryptFinal_ex(ctx, dst_tmp_raw + dst_len_tmp, &dst_len_tmp) != 1) {
        goto cleanup;
    }

    ciphertext_len += dst_len_tmp;
    dst_tmp_raw[raw_ciphertext_len-1] = 0x0;

    result_len_raw = ciphertext_len + sizeof(iv) + 1;

    if((dst_tmp = (unsigned char*) malloc(result_len_raw)) == NULL) {
        goto cleanup;
    }

    // concat iv with cipher text
    memcpy(dst_tmp, iv, sizeof(iv));
    memcpy(dst_tmp+sizeof(iv), dst_tmp_raw, raw_ciphertext_len-1);

    dst_tmp[result_len_raw-1] = 0x0;
    
    // encode to hex
    if(hexencode(dst_tmp, result_len_raw-1, dst, dst_len) != 0) {
        goto cleanup;
    }

    ret = 0;
    
    /* Clean up */
    cleanup:
        if (ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx);
        }

        if (dst_tmp != NULL) {
            free((void*) dst_tmp);
        }

        if (dst_tmp_raw != NULL) {
            free((void*) dst_tmp_raw);
        }

        return ret;
}

static int crypsi_aes_cbc_decrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER* cipher = NULL;

    int ret = -1;
    int dst_len_tmp = 0;
    int plaintext_len = 0;
    int raw_ciphertext_len = 0;
    unsigned char* ciphertext_raw = NULL; 
    unsigned char* dst_tmp = NULL;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char* dst_decode = NULL;
    unsigned int dst_decode_len = 0;

    switch (aes_key_size) {
    case CRYPSI_AES_128_KEY:
        if (strlen((char*) key) != CRYPSI_AES_128_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_128_cbc();
        break;
    case CRYPSI_AES_192_KEY:
        if (strlen((char*) key) != CRYPSI_AES_192_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_192_cbc();
        break;
    case CRYPSI_AES_256_KEY:
        if (strlen((char*) key) != CRYPSI_AES_256_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_256_cbc();
        break;
    default:
        return ret;
    }
    
    if(hexdecode(data, data_len, &dst_decode, &dst_decode_len) != 0) {
        goto cleanup;
    }
    
    memcpy(iv, dst_decode, sizeof(iv));

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    raw_ciphertext_len = dst_decode_len - sizeof(iv) + 1;

    if((ciphertext_raw = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        goto cleanup;
    }

    memcpy(ciphertext_raw, dst_decode+sizeof(iv), raw_ciphertext_len);
    ciphertext_raw[raw_ciphertext_len-1] = 0x0;

    if((dst_tmp = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        goto cleanup;
    }
    
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto cleanup;
    }
    
    if(EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto cleanup;
    }

    if(EVP_DecryptUpdate(ctx, dst_tmp, &dst_len_tmp, ciphertext_raw, raw_ciphertext_len-1) != 1) {
        goto cleanup;
    }
    
    plaintext_len = dst_len_tmp;
    
    if(EVP_DecryptFinal_ex(ctx, dst_tmp + dst_len_tmp, &dst_len_tmp) != 1) {
        goto cleanup;
    }

    plaintext_len += dst_len_tmp;

    if((*dst = (unsigned char*) malloc(plaintext_len+1)) == NULL) {
        goto cleanup;
    }
   
    memcpy(*dst, dst_tmp, plaintext_len);
    (*dst)[plaintext_len] = 0x0;

    *dst_len = plaintext_len;

    ret = 0;

    /* Clean up */
    cleanup:
        if (ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx);
        }

        if (dst_decode != NULL) {
            free((void*) dst_decode);
        }

        if (ciphertext_raw != NULL) {
            free((void*) ciphertext_raw);
        }

        if (dst_tmp != NULL) {
            free((void*) dst_tmp);
        }

        return ret;
}

static int crypsi_aes_gcm_encrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX* ctx = NULL;
    EVP_CIPHER* cipher = NULL;

    int ret = -1;
    int dst_len_tmp = 0;
    int ciphertext_len = 0;
    int result_len_raw = 0;
    unsigned char* dst_tmp_raw = NULL; 
    unsigned char* dst_tmp = NULL;
    unsigned char iv[AES_GCM_IV_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    int raw_ciphertext_len = data_len + (AES_BLOCK_SIZE - data_len%AES_BLOCK_SIZE) + 1;

    switch (aes_key_size) {
    case CRYPSI_AES_128_KEY:
        if (strlen((char*) key) != CRYPSI_AES_128_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_128_gcm();
        break;
    case CRYPSI_AES_192_KEY:
        if (strlen((char*) key) != CRYPSI_AES_192_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_192_gcm();
        break;
    case CRYPSI_AES_256_KEY:
        if (strlen((char*) key) != CRYPSI_AES_256_KEY) {
            return ret;
        }
        
        cipher = (EVP_CIPHER*) EVP_aes_256_gcm();
        break;
    default:
        return ret;
    }

    if((dst_tmp_raw = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        return -1;
    }
    
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto cleanup;
    }

    // generate iv
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        goto cleanup;
    }

    if(EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto cleanup;
    }

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL) != 1) {
        goto cleanup;
    }

    if(EVP_EncryptUpdate(ctx, dst_tmp_raw, &dst_len_tmp, data, data_len) != 1) {
        goto cleanup;
    }
    
    ciphertext_len = dst_len_tmp;

    if(EVP_EncryptFinal_ex(ctx, dst_tmp_raw + dst_len_tmp, &dst_len_tmp) != 1) {
        goto cleanup;
    }

    ciphertext_len += dst_len_tmp;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        goto cleanup;
    }

    dst_tmp_raw[ciphertext_len] = 0x0;

    result_len_raw = ciphertext_len + sizeof(iv) + sizeof(tag) + 1;

    if((dst_tmp = (unsigned char*) malloc(result_len_raw)) == NULL) {
        goto cleanup;
    }

    // concat iv and tag with cipher text
    memcpy(dst_tmp, iv, sizeof(iv));
    memcpy(dst_tmp+sizeof(iv), dst_tmp_raw, ciphertext_len);
    memcpy(dst_tmp+ciphertext_len+sizeof(iv), tag, sizeof(tag));

    dst_tmp[result_len_raw-1] = 0x0;
    
    // encode to hex
    if(hexencode(dst_tmp, result_len_raw-1, dst, dst_len) != 0) {
        goto cleanup;
    }

    ret = 0;
    
    /* Clean up */
    cleanup:
        if (ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx);
        }

        if (dst_tmp != NULL) {
            free((void*) dst_tmp);
        }

        if (dst_tmp_raw != NULL) {
            free((void*) dst_tmp_raw);
        }

        return ret;
}

static int crypsi_aes_gcm_decrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX* ctx = NULL;
    EVP_CIPHER* cipher = NULL;

    int ret = -1;
    int dst_len_tmp = 0;
    int plaintext_len = 0;
    int raw_ciphertext_len = 0;
    unsigned char* ciphertext_raw = NULL; 
    unsigned char* dst_tmp = NULL;
    unsigned char iv[AES_GCM_IV_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char* dst_decode = NULL;
    unsigned int dst_decode_len = 0;
    
    switch (aes_key_size) {
    case CRYPSI_AES_128_KEY:
        if (strlen((char*) key) != CRYPSI_AES_128_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_128_gcm();
        break;
    case CRYPSI_AES_192_KEY:
        if (strlen((char*) key) != CRYPSI_AES_192_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_192_gcm();
        break;
    case CRYPSI_AES_256_KEY:
        if (strlen((char*) key) != CRYPSI_AES_256_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_256_gcm();
        break;
    default:
        return ret;
    }

    if(hexdecode(data, data_len, &dst_decode, &dst_decode_len) != 0) {
        goto cleanup;
    }
    
    // copy iv
    memcpy(iv, dst_decode, sizeof(iv));

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    raw_ciphertext_len = dst_decode_len - (sizeof(iv)+sizeof(tag)) + 1;

    if((ciphertext_raw = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        goto cleanup;
    }

    // copy raw cipher text
    memcpy(ciphertext_raw, dst_decode+sizeof(iv), raw_ciphertext_len);
    ciphertext_raw[raw_ciphertext_len-1] = 0x0;

    // copy tag
    memcpy(tag, dst_decode+raw_ciphertext_len+sizeof(iv)-1, sizeof(tag));

    if((dst_tmp = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        goto cleanup;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto cleanup;
    }
    
    if(EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag) != 1) {
        goto cleanup;
    }

    if(EVP_DecryptUpdate(ctx, dst_tmp, &dst_len_tmp, ciphertext_raw, raw_ciphertext_len-1) != 1) {
        goto cleanup;
    }
    
    plaintext_len = dst_len_tmp;
    
    if(EVP_DecryptFinal_ex(ctx, dst_tmp + dst_len_tmp, &dst_len_tmp) != 1) {
        goto cleanup;
    }

    plaintext_len += dst_len_tmp;

    if((*dst = (unsigned char*) malloc(plaintext_len+1)) == NULL) {
        goto cleanup;
    }
   
    memcpy(*dst, dst_tmp, plaintext_len);
    (*dst)[plaintext_len] = 0x0;

    *dst_len = plaintext_len;

    ret = 0;

    /* Clean up */
    cleanup:
        if (ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx);
        }

        if (dst_decode != NULL) {
            free((void*) dst_decode);
        }

        if (ciphertext_raw != NULL) {
            free((void*) ciphertext_raw);
        }

        if (dst_tmp != NULL) {
            free((void*) dst_tmp);
        }
        
        return ret;
}

// AES CBC
int crypsi_aes_128_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_encrypt(CRYPSI_AES_128_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_192_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_encrypt(CRYPSI_AES_192_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_256_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_encrypt(CRYPSI_AES_256_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_128_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_decrypt(CRYPSI_AES_128_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_192_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_decrypt(CRYPSI_AES_192_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_256_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_decrypt(CRYPSI_AES_256_KEY, key, data, data_len, dst, dst_len);
}

// AES GCM
int crypsi_aes_128_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_encrypt(CRYPSI_AES_128_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_192_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_encrypt(CRYPSI_AES_192_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_256_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_encrypt(CRYPSI_AES_256_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_128_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_decrypt(CRYPSI_AES_128_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_192_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_decrypt(CRYPSI_AES_192_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_256_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_decrypt(CRYPSI_AES_256_KEY, key, data, data_len, dst, dst_len);
}

// RSA
int crypsi_rsa_generate_key_pairs(int size, unsigned char** private_key_buf, 
    int* private_key_buf_len, unsigned char** public_key_buf, int* public_key_buf_len) {
    int ret = -1;
    EVP_PKEY* pkey = NULL;
    BIO* private_bio = NULL;
    BIO* public_bio = NULL;
    int private_key_len;
    int public_key_len;

    switch (size) {
    case CRYPSI_RSA_MODULUS_1024:
    case CRYPSI_RSA_MODULUS_2048:
    case CRYPSI_RSA_MODULUS_4096:
        break;
    default:
    return ret;
    }

    EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (key_ctx == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(key_ctx) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, size) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_keygen(key_ctx, &pkey) != 1) {
        goto cleanup;
    }

    // extract private key as string
    // create a place to dump the IO, in this case in memory
    private_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(private_bio, pkey, NULL, NULL, 0, 0, NULL);

    // get buffer length
    private_key_len = BIO_pending(private_bio);
    *private_key_buf = (unsigned char*) malloc(private_key_len);
    BIO_read(private_bio, *private_key_buf, private_key_len);

    *private_key_buf_len = private_key_len;
    
    // extract public key as string
    // create a place to dump the IO, in this case in memory
    public_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(public_bio, pkey);

    // get buffer length
    public_key_len = BIO_pending(public_bio);
    *public_key_buf = (unsigned char*) malloc(public_key_len);
    BIO_read(public_bio, *public_key_buf, public_key_len);
    
    *public_key_buf_len = public_key_len;

    ret = 0;

    cleanup:
        if (key_ctx != NULL) {
            EVP_PKEY_CTX_free(key_ctx);
        }

        if (pkey != NULL) {
            EVP_PKEY_free(pkey);
        }

        if (private_bio != NULL) {
            BIO_free(private_bio);
        }

        if (public_bio != NULL) {
            BIO_free(public_bio);
        }

        return ret;
}

int crypsi_rsa_load_private_key(const unsigned char* buffer, EVP_PKEY** private_key_dst) {
    int ret = -1;
    RSA* rsa_private_key = NULL;

    // key sanitizer
    char buffer_tmp[strlen((const char*) buffer)+1];
    int i, j;
    for(i = 0, j = 0 ; buffer[i] != '\0'; i++) {
        if(buffer[i] == '\\' && buffer[i + 1] == 'n') {
            buffer_tmp[j] = '\n';
            i++;
        } else {
            buffer_tmp[j] = buffer[i];
        }
        j++;
    }

    buffer_tmp[j] = 0x0;

    // write char array to BIO
    BIO* rsa_private_bio = BIO_new_mem_buf(buffer_tmp, -1);
    if (rsa_private_bio == NULL) {
        goto cleanup;
    }

    // create a RSA object from private key char array
    if(!PEM_read_bio_RSAPrivateKey(rsa_private_bio, &rsa_private_key, NULL, NULL)) {
        goto cleanup;
    }

    // create private key
    *private_key_dst = EVP_PKEY_new();
    if (*private_key_dst == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_assign_RSA(*private_key_dst, rsa_private_key) != 1) {
        goto cleanup;
    }

    ret = 0;

    // cleanup
    cleanup:
        if (rsa_private_bio != NULL) {
            BIO_free(rsa_private_bio);
        }

        return ret;
}

int crypsi_rsa_load_public_key(const unsigned char* buffer, EVP_PKEY** public_key_dst) {
    int ret = -1;
    RSA* rsa_public_key = NULL;

    // key sanitizer
    char buffer_tmp[strlen((const char*) buffer)+1];
    int i, j;
    for(i = 0, j = 0 ; buffer[i] != '\0'; i++) {
        if (buffer[i] == '\\' && buffer[i + 1] == 'n') {
            buffer_tmp[j] = '\n';
            i++;
        } else {
            buffer_tmp[j] = buffer[i];
        }
        j++;
    }

    buffer_tmp[j] = 0x0;

    // write char array to BIO
    BIO* rsa_public_bio = BIO_new_mem_buf(buffer_tmp, -1);
    if (rsa_public_bio == NULL) {
        goto cleanup;
    }

    // create a RSA object from public key char array
    if(!PEM_read_bio_RSA_PUBKEY(rsa_public_bio, &rsa_public_key, NULL, NULL)) {
        goto cleanup;
    }

    // create public key
    *public_key_dst = EVP_PKEY_new();
    if (*public_key_dst == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_assign_RSA(*public_key_dst, rsa_public_key) != 1) {
        goto cleanup;
    }

    ret = 0;

    // cleanup
    cleanup:
        if (rsa_public_bio != NULL) {
            BIO_free(rsa_public_bio);
        }

        return ret;
}

// RSA Encryption
static int crypsi_rsa_encrypt_oaep(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    
    int ret = -1;
    EVP_MD* md = NULL;
    EVP_PKEY* public_key = NULL;
    EVP_PKEY_CTX* enc_ctx = NULL;
    size_t dst_encrypt_len;
    unsigned char* dst_encrypt = NULL;

    switch (alg) {
    case CRYPSI_MD5:
        md = (EVP_MD*) EVP_md5();
        break;
    case CRYPSI_SHA1:
        md = (EVP_MD*) EVP_sha1();
        break;
    case CRYPSI_SHA256:
        md = (EVP_MD*) EVP_sha256();
        break;
    case CRYPSI_SHA384:
        md = (EVP_MD*) EVP_sha384();
        break;
    case CRYPSI_SHA512:
        md = (EVP_MD*) EVP_sha512();
        break;
    default:
        return ret;
    }

    if (crypsi_rsa_load_public_key(key, &public_key) != 0) {
        goto cleanup;
    }
    
    enc_ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (EVP_PKEY_encrypt_init(enc_ctx) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, md) != 1) {
        goto cleanup;
    }

    // Determine the size of the output
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &dst_encrypt_len, data, data_len) != 1) {
        goto cleanup;
    }

    dst_encrypt = (unsigned char*) malloc((dst_encrypt_len+1)*sizeof(char));
    if (dst_encrypt == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_encrypt(enc_ctx, dst_encrypt, &dst_encrypt_len, data, data_len) != 1) {
        goto cleanup;
    }

    dst_encrypt[dst_encrypt_len] = 0x0;

    if(hexencode(dst_encrypt, dst_encrypt_len, dst, dst_len) != 0) {
        goto cleanup;
    }

    ret = 0;

    cleanup:
        if (enc_ctx != NULL) {
            EVP_PKEY_CTX_free(enc_ctx);
        }

        if (public_key != NULL) {
            EVP_PKEY_free(public_key);
        }
        
        if (dst_encrypt != NULL) {
            free((void*) dst_encrypt);
        }

        return ret;
}

static int crypsi_rsa_decrypt_oaep(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {

    int ret = -1;
    EVP_MD* md = NULL;
    EVP_PKEY* private_key = NULL;
    EVP_PKEY_CTX* dec_ctx = NULL;
    size_t dst_decrypt_len;
    unsigned int dst_decode_len;
    unsigned char* dst_decode = NULL;

    switch (alg) {
    case CRYPSI_MD5:
        md = (EVP_MD*) EVP_md5();
        break;
    case CRYPSI_SHA1:
        md = (EVP_MD*) EVP_sha1();
        break;
    case CRYPSI_SHA256:
        md = (EVP_MD*) EVP_sha256();
        break;
    case CRYPSI_SHA384:
        md = (EVP_MD*) EVP_sha384();
        break;
    case CRYPSI_SHA512:
        md = (EVP_MD*) EVP_sha512();
        break;
    default:
        return ret;
    }

    if(hexdecode(data, data_len, &dst_decode, &dst_decode_len) != 0) {
        goto cleanup;
    }

    if (crypsi_rsa_load_private_key(key, &private_key) != 0) {
        goto cleanup;
    }

    dec_ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (EVP_PKEY_decrypt_init(dec_ctx) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, md) != 1) {
        goto cleanup;
    }

    // Determine the size of the output
    if (EVP_PKEY_decrypt(dec_ctx, NULL, &dst_decrypt_len, dst_decode, dst_decode_len) != 1) {
        goto cleanup;
    }

    *dst = (unsigned char*) malloc((dst_decrypt_len+1)*sizeof(char));
    if (*dst == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_decrypt(dec_ctx, *dst, &dst_decrypt_len, dst_decode, dst_decode_len) != 1) {
        goto cleanup;
    }

    (*dst)[dst_decrypt_len] = 0x0;
    *dst_len = dst_decrypt_len;

    ret = 0;

    cleanup:
        if (dec_ctx != NULL) {
            EVP_PKEY_CTX_free(dec_ctx);
        }

        if (private_key != NULL) {
            EVP_PKEY_free(private_key);
        }

        if (dst_decode != NULL) {
            free((void*) dst_decode);
        }

        return ret;
}

// RSA ENCRYPT
int crypsi_rsa_encrypt_oaep_md5(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_encrypt_oaep(CRYPSI_MD5, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_encrypt_oaep_sha1(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_encrypt_oaep(CRYPSI_SHA1, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_encrypt_oaep_sha256(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_encrypt_oaep(CRYPSI_SHA256, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_encrypt_oaep_sha384(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_encrypt_oaep(CRYPSI_SHA384, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_encrypt_oaep_sha512(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_encrypt_oaep(CRYPSI_SHA512, key, data, data_len, dst, dst_len);
}

// RSA DECRYPT
int crypsi_rsa_decrypt_oaep_md5(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_decrypt_oaep(CRYPSI_MD5, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_decrypt_oaep_sha1(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_decrypt_oaep(CRYPSI_SHA1, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_decrypt_oaep_sha256(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_decrypt_oaep(CRYPSI_SHA256, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_decrypt_oaep_sha384(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_decrypt_oaep(CRYPSI_SHA384, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_decrypt_oaep_sha512(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_decrypt_oaep(CRYPSI_SHA512, key, data, data_len, dst, dst_len);
}

// RSA DIGITAL SIGNATURE
static int crypsi_rsa_sign_pss(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    
    int ret = -1;
    EVP_PKEY* private_key = NULL;
    EVP_MD* md = NULL;
    EVP_PKEY_CTX* sign_pkey_ctx = NULL;
    EVP_MD_CTX* sign_ctx = EVP_MD_CTX_new();
    size_t dst_signature_len;
    unsigned char* dst_signature = NULL;

    switch (alg) {
    case CRYPSI_MD5:
        md = (EVP_MD*) EVP_md5();
        break;
    case CRYPSI_SHA1:
        md = (EVP_MD*) EVP_sha1();
        break;
    case CRYPSI_SHA256:
        md = (EVP_MD*) EVP_sha256();
        break;
    case CRYPSI_SHA384:
        md = (EVP_MD*) EVP_sha384();
        break;
    case CRYPSI_SHA512:
        md = (EVP_MD*) EVP_sha512();
        break;
    default:
        return ret;
    }

    if (crypsi_rsa_load_private_key(key, &private_key) != 0) {
        goto cleanup;
    }

    if (EVP_DigestSignInit(sign_ctx, &sign_pkey_ctx, md, NULL, private_key) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(sign_pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(sign_pkey_ctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(sign_ctx, data, data_len) != 1) {
        goto cleanup;
    }

    // Determine the size of the output
    if (EVP_DigestSignFinal(sign_ctx, NULL, &dst_signature_len) != 1) {
        goto cleanup;
    }

    dst_signature = (unsigned char*) malloc((dst_signature_len+1)*sizeof(char));
    if (dst_signature == NULL) {
        goto cleanup;
    }

    if (EVP_DigestSignFinal(sign_ctx, dst_signature, &dst_signature_len) != 1) {
        goto cleanup;
    }

    dst_signature[dst_signature_len] = 0x0;

    if(hexencode(dst_signature, dst_signature_len, dst, dst_len) != 0) {
        goto cleanup;
    }

    ret = 0;
    cleanup:
        if (sign_ctx != NULL) {
            EVP_MD_CTX_free(sign_ctx);
        }

        if (private_key != NULL) {
            EVP_PKEY_free(private_key);
        }

        if (dst_signature != NULL) {
            free((void*) dst_signature);
        }

        return ret;
}

static int crypsi_rsa_verify_sign_pss(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char* signature, size_t signature_len) {
    
    // this function will return
    // error = -1
    // succeed with invalid signature = 0
    // succeed with valid signature = 1
    int ret = -1;
    EVP_MD* md = NULL;
    EVP_PKEY* public_key = NULL;
    EVP_PKEY_CTX* verify_pkey_ctx = NULL;
    EVP_MD_CTX* verify_ctx = EVP_MD_CTX_new();
    unsigned int dst_decode_len;
    unsigned char* dst_decode = NULL;

    switch (alg) {
    case CRYPSI_MD5:
        md = (EVP_MD*) EVP_md5();
        break;
    case CRYPSI_SHA1:
        md = (EVP_MD*) EVP_sha1();
        break;
    case CRYPSI_SHA256:
        md = (EVP_MD*) EVP_sha256();
        break;
    case CRYPSI_SHA384:
        md = (EVP_MD*) EVP_sha384();
        break;
    case CRYPSI_SHA512:
        md = (EVP_MD*) EVP_sha512();
        break;
    default:
        return ret;
    }

    if (crypsi_rsa_load_public_key(key, &public_key) != 0) {
        goto cleanup;
    }

    if(hexdecode(signature, signature_len, &dst_decode, &dst_decode_len) != 0) {
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(verify_ctx, &verify_pkey_ctx, md, NULL, public_key) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(verify_pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(verify_pkey_ctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(verify_ctx, data, data_len) != 1) {
        goto cleanup;
    }

    ret = EVP_DigestVerifyFinal(verify_ctx, dst_decode, dst_decode_len);

    cleanup:
        if (verify_ctx != NULL) {
            EVP_MD_CTX_free(verify_ctx);
        }

        if (public_key != NULL) {
            EVP_PKEY_free(public_key);
        }

        if (dst_decode != NULL) {
            free((void*) dst_decode);
        }

        return ret;
}

// RSA DIGITAL SIGNATURE (SIGN OPERATION)
int crypsi_rsa_sign_pss_md5(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_sign_pss(CRYPSI_MD5, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_sign_pss_sha1(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_sign_pss(CRYPSI_SHA1, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_sign_pss_sha256(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_sign_pss(CRYPSI_SHA256, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_sign_pss_sha384(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_sign_pss(CRYPSI_SHA384, key, data, data_len, dst, dst_len);
}

int crypsi_rsa_sign_pss_sha512(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_rsa_sign_pss(CRYPSI_SHA512, key, data, data_len, dst, dst_len);
}

// RSA DIGITAL SIGNATURE (VERIFY SIGNATURE OPERATION)
int crypsi_rsa_verify_sign_pss_md5(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char* signature, size_t signature_len) {
    return crypsi_rsa_verify_sign_pss(CRYPSI_MD5, key, data, data_len, signature, signature_len);
}

int crypsi_rsa_verify_sign_pss_sha1(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char* signature, size_t signature_len) {
    return crypsi_rsa_verify_sign_pss(CRYPSI_SHA1, key, data, data_len, signature, signature_len);
}

int crypsi_rsa_verify_sign_pss_sha256(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char* signature, size_t signature_len) {
    return crypsi_rsa_verify_sign_pss(CRYPSI_SHA256, key, data, data_len, signature, signature_len);
}

int crypsi_rsa_verify_sign_pss_sha384(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char* signature, size_t signature_len) {
    return crypsi_rsa_verify_sign_pss(CRYPSI_SHA384, key, data, data_len, signature, signature_len);
}

int crypsi_rsa_verify_sign_pss_sha512(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char* signature, size_t signature_len) {
    return crypsi_rsa_verify_sign_pss(CRYPSI_SHA512, key, data, data_len, signature, signature_len);
}
#endif