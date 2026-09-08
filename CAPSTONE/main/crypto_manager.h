#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <stdint.h>
#include <stddef.h>
#include "mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_DIGEST_SIZE 32
#define SEED_SIZE 32
#define KEY_SIZE 32
#define ROUND_NUM_SIZE 4

#define MLKEM_PUBLIC_KEY_BYTES 800
#define MLKEM_SECRET_KEY_BYTES 1632
#define MLKEM_CIPHERTEXT_BYTES 768
#define MLKEM_SHARED_SECRET_BYTES 32

typedef struct {
    uint8_t pk[MLKEM_PUBLIC_KEY_BYTES];
    uint8_t sk[MLKEM_SECRET_KEY_BYTES];
} mlkem_keypair_t;

typedef enum {
    CRYPTO_OK = 0,
    CRYPTO_ERR_NULL_PTR = -1,
    CRYPTO_ERR_HW_FAIL = -2,
    CRYPTO_ERR_INVALID_LEN = -3
} crypto_err_t;

crypto_err_t crypto_sha256_hw(const uint8_t *input, size_t input_len, uint8_t *output);
crypto_err_t crypto_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output);
crypto_err_t crypto_derive_key_simple(const uint8_t *static_secret, uint32_t round_num, uint8_t *round_key);
crypto_err_t crypto_derive_key_ratchet(const uint8_t *seed, uint32_t round_num, uint8_t *ephemeral_key, uint8_t *next_seed);
crypto_err_t crypto_secure_zeroize(void *ptr, size_t len);
crypto_err_t crypto_generate_random_seed(uint8_t *seed);
int crypto_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len);

crypto_err_t crypto_mlkem_keygen(mlkem_keypair_t *kp);
crypto_err_t crypto_mlkem_encaps(const uint8_t *pk, uint8_t *ciphertext, uint8_t *shared_secret);
crypto_err_t crypto_mlkem_decaps(const uint8_t *sk, const uint8_t *ciphertext, uint8_t *shared_secret);

#ifdef __cplusplus
}
#endif

#endif