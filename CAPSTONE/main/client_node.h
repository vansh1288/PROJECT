#ifndef CLIENT_NODE_H
#define CLIENT_NODE_H

#include <stdint.h>
#include <stddef.h>
#include "crypto_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ROUNDS 10
#define MODEL_UPDATE_SIZE 64
#define CLIENT_ID_SIZE 8

typedef enum {
    METHOD_SIMPLE_SECAGG = 0,
    METHOD_PQC_RATCHETING = 1
} secagg_method_t;

typedef enum {
    CLIENT_STATE_INIT = 0,
    CLIENT_STATE_READY = 1,
    CLIENT_STATE_ROUND_ACTIVE = 2,
    CLIENT_STATE_COMPROMISED = 3,
    CLIENT_STATE_DONE = 4
} client_state_t;

typedef struct {
    uint8_t static_secret[SEED_SIZE];
    uint8_t current_seed[SEED_SIZE];
    uint8_t round_keys[MAX_ROUNDS][KEY_SIZE];
    uint8_t seeds_history[MAX_ROUNDS + 1][SEED_SIZE];
    uint32_t current_round;
    secagg_method_t method;
    client_state_t state;
    uint8_t client_id[CLIENT_ID_SIZE];
} client_node_t;

typedef struct {
    uint32_t round_num;
    uint8_t ephemeral_key[KEY_SIZE];
    uint8_t model_update[MODEL_UPDATE_SIZE];
    uint8_t client_id[CLIENT_ID_SIZE];
    uint8_t mac[SHA256_DIGEST_SIZE];
} client_payload_t;

crypto_err_t client_node_init(client_node_t *node, secagg_method_t method, const uint8_t *client_id);
crypto_err_t client_node_start_round(client_node_t *node, uint32_t round_num);
crypto_err_t client_node_compute_key(client_node_t *node, uint32_t round_num, uint8_t *key_out);
crypto_err_t client_node_create_payload(client_node_t *node, const uint8_t *model_update, client_payload_t *payload);
crypto_err_t client_node_simulate_compromise(client_node_t *node, uint32_t compromise_round);
crypto_err_t client_node_backtrack_key(client_node_t *node, uint32_t target_round, uint8_t *key_out);
crypto_err_t client_node_get_state_dump(client_node_t *node, uint8_t *state_buffer, size_t *state_len);
void client_node_print_keys(const client_node_t *node);
void client_node_cleanup(client_node_t *node);

#ifdef __cplusplus
}
#endif

#endif