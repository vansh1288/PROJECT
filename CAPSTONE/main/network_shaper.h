#ifndef NETWORK_SHAPER_H
#define NETWORK_SHAPER_H

#include <stdint.h>
#include <stddef.h>
#include "client_node.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PAYLOAD_SIZE 512
#define PADDING_BLOCK_SIZE 16

typedef enum {
    NET_OK = 0,
    NET_ERR_NULL_PTR = -1,
    NET_ERR_BUFFER_SMALL = -2,
    NET_ERR_JSON_CREATE = -3,
    NET_ERR_JSON_PARSE = -4,
    NET_ERR_PADDING = -5
} net_err_t;

typedef struct {
    uint8_t buffer[MAX_PAYLOAD_SIZE];
    size_t length;
} network_buffer_t;

net_err_t network_serialize_payload(const client_payload_t *payload, network_buffer_t *out_buffer);
net_err_t network_deserialize_payload(const network_buffer_t *in_buffer, client_payload_t *payload);
net_err_t network_apply_padding(network_buffer_t *buffer);
net_err_t network_remove_padding(network_buffer_t *buffer);
net_err_t network_create_key_trace_json(const client_node_t *node, char **json_string);
net_err_t network_create_compromise_report_json(uint32_t compromise_round, const uint8_t *state, size_t state_len, char **json_string);
net_err_t network_create_backtrack_result_json(uint32_t target_round, const uint8_t *original_key, const uint8_t *backtracked_key, int match, char **json_string);
void network_free_json_string(char *json_string);

#ifdef __cplusplus
}
#endif

#endif