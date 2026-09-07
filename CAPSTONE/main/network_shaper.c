#include "network_shaper.h"
#include "crypto_manager.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex_out[i * 2] = hex_chars[bytes[i] >> 4];
        hex_out[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex_out[len * 2] = '\0';
}

net_err_t network_serialize_payload(const client_payload_t *payload, network_buffer_t *out_buffer) {
    if (!payload || !out_buffer) {
        return NET_ERR_NULL_PTR;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NET_ERR_JSON_CREATE;
    }
    
    cJSON_AddNumberToObject(root, "round", payload->round_num);
    
    char key_hex[KEY_SIZE * 2 + 1];
    bytes_to_hex(payload->ephemeral_key, KEY_SIZE, key_hex);
    cJSON_AddStringToObject(root, "ephemeral_key", key_hex);
    
    char update_hex[MODEL_UPDATE_SIZE * 2 + 1];
    bytes_to_hex(payload->model_update, MODEL_UPDATE_SIZE, update_hex);
    cJSON_AddStringToObject(root, "model_update", update_hex);
    
    char id_hex[CLIENT_ID_SIZE * 2 + 1];
    bytes_to_hex(payload->client_id, CLIENT_ID_SIZE, id_hex);
    cJSON_AddStringToObject(root, "client_id", id_hex);
    
    char mac_hex[SHA256_DIGEST_SIZE * 2 + 1];
    bytes_to_hex(payload->mac, SHA256_DIGEST_SIZE, mac_hex);
    cJSON_AddStringToObject(root, "mac", mac_hex);
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    if (!json_str) {
        return NET_ERR_JSON_CREATE;
    }
    
    size_t json_len = strlen(json_str);
    if (json_len >= MAX_PAYLOAD_SIZE) {
        free(json_str);
        return NET_ERR_BUFFER_SMALL;
    }
    
    memcpy(out_buffer->buffer, json_str, json_len);
    out_buffer->length = json_len;
    out_buffer->buffer[json_len] = '\0';
    
    free(json_str);
    return NET_OK;
}

net_err_t network_deserialize_payload(const network_buffer_t *in_buffer, client_payload_t *payload) {
    if (!in_buffer || !payload || in_buffer->length == 0) {
        return NET_ERR_NULL_PTR;
    }
    
    cJSON *root = cJSON_ParseWithLength((const char *)in_buffer->buffer, in_buffer->length);
    if (!root) {
        return NET_ERR_JSON_PARSE;
    }
    
    cJSON *round_item = cJSON_GetObjectItemCaseSensitive(root, "round");
    if (!cJSON_IsNumber(round_item)) {
        cJSON_Delete(root);
        return NET_ERR_JSON_PARSE;
    }
    payload->round_num = (uint32_t)round_item->valuedouble;
    
    cJSON *key_item = cJSON_GetObjectItemCaseSensitive(root, "ephemeral_key");
    if (!cJSON_IsString(key_item) || strlen(key_item->valuestring) != KEY_SIZE * 2) {
        cJSON_Delete(root);
        return NET_ERR_JSON_PARSE;
    }
    for (int i = 0; i < KEY_SIZE; i++) {
        sscanf(key_item->valuestring + i * 2, "%2hhx", &payload->ephemeral_key[i]);
    }
    
    cJSON *update_item = cJSON_GetObjectItemCaseSensitive(root, "model_update");
    if (!cJSON_IsString(update_item) || strlen(update_item->valuestring) != MODEL_UPDATE_SIZE * 2) {
        cJSON_Delete(root);
        return NET_ERR_JSON_PARSE;
    }
    for (int i = 0; i < MODEL_UPDATE_SIZE; i++) {
        sscanf(update_item->valuestring + i * 2, "%2hhx", &payload->model_update[i]);
    }
    
    cJSON *id_item = cJSON_GetObjectItemCaseSensitive(root, "client_id");
    if (!cJSON_IsString(id_item) || strlen(id_item->valuestring) != CLIENT_ID_SIZE * 2) {
        cJSON_Delete(root);
        return NET_ERR_JSON_PARSE;
    }
    for (int i = 0; i < CLIENT_ID_SIZE; i++) {
        sscanf(id_item->valuestring + i * 2, "%2hhx", &payload->client_id[i]);
    }
    
    cJSON *mac_item = cJSON_GetObjectItemCaseSensitive(root, "mac");
    if (!cJSON_IsString(mac_item) || strlen(mac_item->valuestring) != SHA256_DIGEST_SIZE * 2) {
        cJSON_Delete(root);
        return NET_ERR_JSON_PARSE;
    }
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        sscanf(mac_item->valuestring + i * 2, "%2hhx", &payload->mac[i]);
    }
    
    cJSON_Delete(root);
    return NET_OK;
}

net_err_t network_apply_padding(network_buffer_t *buffer) {
    if (!buffer) {
        return NET_ERR_NULL_PTR;
    }
    
    size_t padding_needed = PADDING_BLOCK_SIZE - (buffer->length % PADDING_BLOCK_SIZE);
    if (padding_needed == 0) {
        padding_needed = PADDING_BLOCK_SIZE;
    }
    
    if (buffer->length + padding_needed > MAX_PAYLOAD_SIZE) {
        return NET_ERR_BUFFER_SMALL;
    }
    
    for (size_t i = 0; i < padding_needed; i++) {
        buffer->buffer[buffer->length + i] = (uint8_t)padding_needed;
    }
    buffer->length += padding_needed;
    
    return NET_OK;
}

net_err_t network_remove_padding(network_buffer_t *buffer) {
    if (!buffer || buffer->length == 0) {
        return NET_ERR_NULL_PTR;
    }
    
    uint8_t padding_value = buffer->buffer[buffer->length - 1];
    if (padding_value == 0 || padding_value > PADDING_BLOCK_SIZE || padding_value > buffer->length) {
        return NET_ERR_PADDING;
    }
    
    for (size_t i = 1; i <= padding_value; i++) {
        if (buffer->buffer[buffer->length - i] != padding_value) {
            return NET_ERR_PADDING;
        }
    }
    
    buffer->length -= padding_value;
    return NET_OK;
}

net_err_t network_create_key_trace_json(const client_node_t *node, char **json_string) {
    if (!node || !json_string) {
        return NET_ERR_NULL_PTR;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NET_ERR_JSON_CREATE;
    }
    
    cJSON_AddStringToObject(root, "method", node->method == METHOD_SIMPLE_SECAGG ? "Simple_SecAgg" : "PQC_Ratcheting");
    
    char id_hex[CLIENT_ID_SIZE * 2 + 1];
    bytes_to_hex(node->client_id, CLIENT_ID_SIZE, id_hex);
    cJSON_AddStringToObject(root, "client_id", id_hex);
    
    if (node->method == METHOD_SIMPLE_SECAGG) {
        char secret_hex[SEED_SIZE * 2 + 1];
        bytes_to_hex(node->static_secret, SEED_SIZE, secret_hex);
        cJSON_AddStringToObject(root, "static_secret", secret_hex);
    } else {
        char seed_hex[SEED_SIZE * 2 + 1];
        bytes_to_hex(node->seeds_history[0], SEED_SIZE, seed_hex);
        cJSON_AddStringToObject(root, "initial_seed", seed_hex);
    }
    
    cJSON *keys_array = cJSON_CreateArray();
    for (int r = 0; r < MAX_ROUNDS; r++) {
        char key_hex[KEY_SIZE * 2 + 1];
        bytes_to_hex(node->round_keys[r], KEY_SIZE, key_hex);
        cJSON_AddItemToArray(keys_array, cJSON_CreateString(key_hex));
    }
    cJSON_AddItemToObject(root, "round_keys", keys_array);
    
    if (node->method == METHOD_PQC_RATCHETING) {
        cJSON *seeds_array = cJSON_CreateArray();
        for (int r = 0; r <= MAX_ROUNDS; r++) {
            char seed_hex[SEED_SIZE * 2 + 1];
            bytes_to_hex(node->seeds_history[r], SEED_SIZE, seed_hex);
            cJSON_AddItemToArray(seeds_array, cJSON_CreateString(seed_hex));
        }
        cJSON_AddItemToObject(root, "seed_chain", seeds_array);
    }
    
    *json_string = cJSON_Print(root);
    cJSON_Delete(root);
    
    if (!*json_string) {
        return NET_ERR_JSON_CREATE;
    }
    
    return NET_OK;
}

net_err_t network_create_compromise_report_json(uint32_t compromise_round, const uint8_t *state, size_t state_len, char **json_string) {
    if (!state || !json_string) {
        return NET_ERR_NULL_PTR;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NET_ERR_JSON_CREATE;
    }
    
    cJSON_AddNumberToObject(root, "compromise_round", compromise_round);
    cJSON_AddNumberToObject(root, "state_size", state_len);
    
    char *state_hex = malloc(state_len * 2 + 1);
    if (!state_hex) {
        cJSON_Delete(root);
        return NET_ERR_JSON_CREATE;
    }
    bytes_to_hex(state, state_len, state_hex);
    cJSON_AddStringToObject(root, "compromised_state", state_hex);
    free(state_hex);
    
    *json_string = cJSON_Print(root);
    cJSON_Delete(root);
    
    if (!*json_string) {
        return NET_ERR_JSON_CREATE;
    }
    
    return NET_OK;
}

net_err_t network_create_backtrack_result_json(uint32_t target_round, const uint8_t *original_key, const uint8_t *backtracked_key, int match, char **json_string) {
    if (!original_key || !backtracked_key || !json_string) {
        return NET_ERR_NULL_PTR;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NET_ERR_JSON_CREATE;
    }
    
    cJSON_AddNumberToObject(root, "target_round", target_round);
    
    char orig_hex[KEY_SIZE * 2 + 1];
    bytes_to_hex(original_key, KEY_SIZE, orig_hex);
    cJSON_AddStringToObject(root, "original_key", orig_hex);
    
    char back_hex[KEY_SIZE * 2 + 1];
    bytes_to_hex(backtracked_key, KEY_SIZE, back_hex);
    cJSON_AddStringToObject(root, "backtracked_key", back_hex);
    
    cJSON_AddBoolToObject(root, "keys_match", match);
    cJSON_AddStringToObject(root, "forward_privacy", match ? "BROKEN" : "PRESERVED");
    
    *json_string = cJSON_Print(root);
    cJSON_Delete(root);
    
    if (!*json_string) {
        return NET_ERR_JSON_CREATE;
    }
    
    return NET_OK;
}

void network_free_json_string(char *json_string) {
    if (json_string) {
        free(json_string);
    }
}