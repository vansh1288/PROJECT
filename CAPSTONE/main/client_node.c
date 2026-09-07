#include "client_node.h"
#include "crypto_manager.h"
#include <string.h>
#include <stdio.h>

crypto_err_t client_node_init(client_node_t *node, secagg_method_t method, const uint8_t *client_id) {
    if (!node || !client_id) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    memset(node, 0, sizeof(client_node_t));
    node->method = method;
    node->current_round = 0;
    node->state = CLIENT_STATE_INIT;
    memcpy(node->client_id, client_id, CLIENT_ID_SIZE);
    
    if (method == METHOD_SIMPLE_SECAGG) {
        crypto_generate_random_seed(node->static_secret);
    } else {
        crypto_generate_random_seed(node->current_seed);
        memcpy(node->seeds_history[0], node->current_seed, SEED_SIZE);
    }
    
    node->state = CLIENT_STATE_READY;
    return CRYPTO_OK;
}

crypto_err_t client_node_start_round(client_node_t *node, uint32_t round_num) {
    if (!node) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    if (round_num >= MAX_ROUNDS) {
        return CRYPTO_ERR_INVALID_LEN;
    }
    
    node->current_round = round_num;
    node->state = CLIENT_STATE_ROUND_ACTIVE;
    return CRYPTO_OK;
}

crypto_err_t client_node_compute_key(client_node_t *node, uint32_t round_num, uint8_t *key_out) {
    if (!node || !key_out) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    if (round_num >= MAX_ROUNDS) {
        return CRYPTO_ERR_INVALID_LEN;
    }
    
    if (node->method == METHOD_SIMPLE_SECAGG) {
        return crypto_derive_key_simple(node->static_secret, round_num, key_out);
    } else {
        if (round_num == 0) {
            uint8_t temp_key[KEY_SIZE];
            crypto_err_t ret = crypto_derive_key_ratchet(node->current_seed, round_num, temp_key, node->seeds_history[1]);
            if (ret == CRYPTO_OK) {
                memcpy(key_out, temp_key, KEY_SIZE);
                memcpy(node->round_keys[round_num], temp_key, KEY_SIZE);
                crypto_secure_zeroize(temp_key, KEY_SIZE);
            }
            return ret;
        } else {
            uint8_t temp_key[KEY_SIZE];
            crypto_err_t ret = crypto_derive_key_ratchet(node->seeds_history[round_num], round_num, temp_key, node->seeds_history[round_num + 1]);
            if (ret == CRYPTO_OK) {
                memcpy(key_out, temp_key, KEY_SIZE);
                memcpy(node->round_keys[round_num], temp_key, KEY_SIZE);
                crypto_secure_zeroize(temp_key, KEY_SIZE);
            }
            return ret;
        }
    }
}

crypto_err_t client_node_create_payload(client_node_t *node, const uint8_t *model_update, client_payload_t *payload) {
    if (!node || !model_update || !payload) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    uint8_t key[KEY_SIZE];
    crypto_err_t ret = client_node_compute_key(node, node->current_round, key);
    if (ret != CRYPTO_OK) {
        return ret;
    }
    
    payload->round_num = node->current_round;
    memcpy(payload->ephemeral_key, key, KEY_SIZE);
    memcpy(payload->model_update, model_update, MODEL_UPDATE_SIZE);
    memcpy(payload->client_id, node->client_id, CLIENT_ID_SIZE);
    
    uint8_t mac_input[KEY_SIZE + MODEL_UPDATE_SIZE + CLIENT_ID_SIZE + 4];
    memcpy(mac_input, key, KEY_SIZE);
    memcpy(mac_input + KEY_SIZE, model_update, MODEL_UPDATE_SIZE);
    memcpy(mac_input + KEY_SIZE + MODEL_UPDATE_SIZE, node->client_id, CLIENT_ID_SIZE);
    mac_input[KEY_SIZE + MODEL_UPDATE_SIZE + CLIENT_ID_SIZE] = (node->current_round >> 24) & 0xFF;
    mac_input[KEY_SIZE + MODEL_UPDATE_SIZE + CLIENT_ID_SIZE + 1] = (node->current_round >> 16) & 0xFF;
    mac_input[KEY_SIZE + MODEL_UPDATE_SIZE + CLIENT_ID_SIZE + 2] = (node->current_round >> 8) & 0xFF;
    mac_input[KEY_SIZE + MODEL_UPDATE_SIZE + CLIENT_ID_SIZE + 3] = node->current_round & 0xFF;
    
    ret = crypto_hmac_sha256(key, KEY_SIZE, mac_input + KEY_SIZE, MODEL_UPDATE_SIZE + CLIENT_ID_SIZE + 4, payload->mac);
    crypto_secure_zeroize(key, KEY_SIZE);
    crypto_secure_zeroize(mac_input, sizeof(mac_input));
    
    return ret;
}

crypto_err_t client_node_simulate_compromise(client_node_t *node, uint32_t compromise_round) {
    if (!node) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    if (compromise_round >= MAX_ROUNDS) {
        return CRYPTO_ERR_INVALID_LEN;
    }
    
    node->state = CLIENT_STATE_COMPROMISED;
    
    if (node->method == METHOD_SIMPLE_SECAGG) {
    } else {
        if (compromise_round < MAX_ROUNDS) {
            memcpy(node->current_seed, node->seeds_history[compromise_round], SEED_SIZE);
        }
    }
    
    return CRYPTO_OK;
}

crypto_err_t client_node_backtrack_key(client_node_t *node, uint32_t target_round, uint8_t *key_out) {
    if (!node || !key_out) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    if (target_round >= MAX_ROUNDS) {
        return CRYPTO_ERR_INVALID_LEN;
    }
    
    if (node->method == METHOD_SIMPLE_SECAGG) {
        return crypto_derive_key_simple(node->static_secret, target_round, key_out);
    } else {
        if (node->state != CLIENT_STATE_COMPROMISED) {
            return CRYPTO_ERR_INVALID_LEN;
        }
        
        uint8_t temp_seed[SEED_SIZE];
        memcpy(temp_seed, node->current_seed, SEED_SIZE);
        
        for (uint32_t r = 0; r <= target_round; r++) {
            uint8_t temp_key[KEY_SIZE];
            uint8_t next_seed[SEED_SIZE];
            
            crypto_err_t ret = crypto_derive_key_ratchet(temp_seed, r, temp_key, next_seed);
            if (ret != CRYPTO_OK) {
                crypto_secure_zeroize(temp_seed, SEED_SIZE);
                return ret;
            }
            
            if (r == target_round) {
                memcpy(key_out, temp_key, KEY_SIZE);
            }
            
            memcpy(temp_seed, next_seed, SEED_SIZE);
            crypto_secure_zeroize(temp_key, KEY_SIZE);
            crypto_secure_zeroize(next_seed, SEED_SIZE);
        }
        
        crypto_secure_zeroize(temp_seed, SEED_SIZE);
        return CRYPTO_OK;
    }
}

crypto_err_t client_node_get_state_dump(client_node_t *node, uint8_t *state_buffer, size_t *state_len) {
    if (!node || !state_buffer || !state_len) {
        return CRYPTO_ERR_NULL_PTR;
    }
    
    size_t required = SEED_SIZE + MAX_ROUNDS * KEY_SIZE + (MAX_ROUNDS + 1) * SEED_SIZE + sizeof(uint32_t) + sizeof(secagg_method_t);
    if (*state_len < required) {
        *state_len = required;
        return CRYPTO_ERR_INVALID_LEN;
    }
    
    size_t offset = 0;
    if (node->method == METHOD_SIMPLE_SECAGG) {
        memcpy(state_buffer + offset, node->static_secret, SEED_SIZE);
    } else {
        memcpy(state_buffer + offset, node->current_seed, SEED_SIZE);
    }
    offset += SEED_SIZE;
    
    memcpy(state_buffer + offset, node->round_keys, MAX_ROUNDS * KEY_SIZE);
    offset += MAX_ROUNDS * KEY_SIZE;
    
    memcpy(state_buffer + offset, node->seeds_history, (MAX_ROUNDS + 1) * SEED_SIZE);
    offset += (MAX_ROUNDS + 1) * SEED_SIZE;
    
    memcpy(state_buffer + offset, &node->current_round, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(state_buffer + offset, &node->method, sizeof(secagg_method_t));
    offset += sizeof(secagg_method_t);
    
    *state_len = offset;
    return CRYPTO_OK;
}

void client_node_print_keys(const client_node_t *node) {
    printf("\n=== Client Node Key Trace ===\n");
    printf("Method: %s\n", node->method == METHOD_SIMPLE_SECAGG ? "Simple SecAgg" : "PQC Ratcheting");
    printf("Client ID: ");
    for (int i = 0; i < CLIENT_ID_SIZE; i++) {
        printf("%02x", node->client_id[i]);
    }
    printf("\n");
    
    if (node->method == METHOD_SIMPLE_SECAGG) {
        printf("Static Secret: ");
        for (int i = 0; i < SEED_SIZE; i++) {
            printf("%02x", node->static_secret[i]);
        }
        printf("\n");
    } else {
        printf("Initial Seed: ");
        for (int i = 0; i < SEED_SIZE; i++) {
            printf("%02x", node->seeds_history[0][i]);
        }
        printf("\n");
    }
    
    printf("\nRound Keys:\n");
    for (int r = 0; r < MAX_ROUNDS; r++) {
        printf("  Round %d: ", r);
        for (int i = 0; i < KEY_SIZE; i++) {
            printf("%02x", node->round_keys[r][i]);
        }
        printf("\n");
    }
    
    if (node->method == METHOD_PQC_RATCHETING) {
        printf("\nSeed Chain:\n");
        for (int r = 0; r <= MAX_ROUNDS; r++) {
            printf("  Seed[%d]: ", r);
            for (int i = 0; i < SEED_SIZE; i++) {
                printf("%02x", node->seeds_history[r][i]);
            }
            printf("\n");
        }
    }
    printf("============================\n\n");
}

void client_node_cleanup(client_node_t *node) {
    if (!node) {
        return;
    }
    
    crypto_secure_zeroize(node->static_secret, SEED_SIZE);
    crypto_secure_zeroize(node->current_seed, SEED_SIZE);
    crypto_secure_zeroize(node->round_keys, MAX_ROUNDS * KEY_SIZE);
    crypto_secure_zeroize(node->seeds_history, (MAX_ROUNDS + 1) * SEED_SIZE);
    memset(node, 0, sizeof(client_node_t));
}