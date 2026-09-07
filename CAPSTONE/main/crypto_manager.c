#include "crypto_manager.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "esp_random.h"
#include <string.h>

crypto_err_t crypto_sha256_hw(const uint8_t *input, size_t input_len, uint8_t *output) {
    if (!input || !output) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    int ret = mbedtls_sha256_ret(input, input_len, output, 0);
    if (ret != 0) {
        return CRYPTO_ERR_HW_FAIL;
    }
    return CRYPTO_OK;
}

crypto_err_t crypto_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output) {
    if (!key || !data || !output) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    
    int ret = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return CRYPTO_ERR_HW_FAIL;
    }
    
    ret = mbedtls_md_hmac_starts(&ctx, key, key_len);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return CRYPTO_ERR_HW_FAIL;
    }
    
    ret = mbedtls_md_hmac_update(&ctx, data, data_len);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return CRYPTO_ERR_HW_FAIL;
    }
    
    ret = mbedtls_md_hmac_finish(&ctx, output);
    mbedtls_md_free(&ctx);
    
    if (ret != 0) {
        return CRYPTO_ERR_HW_FAIL;
    }
    return CRYPTO_OK;
}

crypto_err_t crypto_derive_key_simple(const uint8_t *static_secret, uint32_t round_num, uint8_t *round_key) {
    if (!static_secret || !round_key) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    uint8_t buffer[SEED_SIZE + ROUND_NUM_SIZE];
    memcpy(buffer, static_secret, SEED_SIZE);
    
    buffer[SEED_SIZE] = (round_num >> 24) & 0xFF;
    buffer[SEED_SIZE + 1] = (round_num >> 16) & 0xFF;
    buffer[SEED_SIZE + 2] = (round_num >> 8) & 0xFF;
    buffer[SEED_SIZE + 3] = round_num & 0xFF;
    
    crypto_err_t ret = crypto_sha256_hw(buffer, sizeof(buffer), round_key);
    crypto_secure_zeroize(buffer, sizeof(buffer));
    return ret;
}

crypto_err_t crypto_derive_key_ratchet(const uint8_t *seed, uint32_t round_num, uint8_t *ephemeral_key, uint8_t *next_seed) {
    if (!seed || !ephemeral_key || !next_seed) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    uint8_t buffer[SEED_SIZE + ROUND_NUM_SIZE];
    memcpy(buffer, seed, SEED_SIZE);
    
    buffer[SEED_SIZE] = (round_num >> 24) & 0xFF;
    buffer[SEED_SIZE + 1] = (round_num >> 16) & 0xFF;
    buffer[SEED_SIZE + 2] = (round_num >> 8) & 0xFF;
    buffer[SEED_SIZE + 3] = round_num & 0xFF;
    
    crypto_err_t ret = crypto_sha256_hw(buffer, sizeof(buffer), ephemeral_key);
    if (ret != CRYPTO_OK) {
        crypto_secure_zeroize(buffer, sizeof(buffer));
        return ret;
    }
    
    uint8_t ratchet_buffer[SEED_SIZE + KEY_SIZE];
    memcpy(ratchet_buffer, seed, SEED_SIZE);
    memcpy(ratchet_buffer + SEED_SIZE, ephemeral_key, KEY_SIZE);
    
    ret = crypto_sha256_hw(ratchet_buffer, sizeof(ratchet_buffer), next_seed);
    
    crypto_secure_zeroize(buffer, sizeof(buffer));
    crypto_secure_zeroize(ratchet_buffer, sizeof(ratchet_buffer));
    
    return ret;
}

crypto_err_t crypto_secure_zeroize(void *ptr, size_t len) {
    if (!ptr) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    mbedtls_platform_zeroize(ptr, len);
    return CRYPTO_OK;
}

crypto_err_t crypto_generate_random_seed(uint8_t *seed) {
    if (!seed) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    esp_fill_random(seed, SEED_SIZE);
    return CRYPTO_OK;
}

int crypto_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b) {
        return -1;
    }
    
    return mbedtls_ct_memcmp(a, b, len);
}