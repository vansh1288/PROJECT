#include "app_main.h"
#include "client_node.h"
#include "network_shaper.h"
#include "crypto_manager.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "CAPSTONE_SECAgg";

#define SIMULATE_MODEL_UPDATE_ROUND(round, buffer) \
    do { \
        for (int i = 0; i < MODEL_UPDATE_SIZE; i++) { \
            buffer[i] = (uint8_t)(round * 31 + i * 17 + 0x5A); \
        } \
    } while(0)

static void run_simple_secagg_simulation(void) {
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, "Starting Simple SecAgg Simulation (Method A)");
    ESP_LOGI(TAG, "============================================");
    
    client_node_t node;
    uint8_t client_id[CLIENT_ID_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t model_update[MODEL_UPDATE_SIZE];
    client_payload_t payload;
    network_buffer_t net_buffer;
    char *json_str = NULL;
    
    crypto_err_t ret = client_node_init(&node, METHOD_SIMPLE_SECAGG, client_id);
    if (ret != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to initialize Simple SecAgg client: %d", ret);
        return;
    }
    
    for (uint32_t round = 0; round < MAX_ROUNDS; round++) {
        SIMULATE_MODEL_UPDATE_ROUND(round, model_update);
        
        ret = client_node_start_round(&node, round);
        if (ret != CRYPTO_OK) {
            ESP_LOGE(TAG, "Failed to start round %lu: %d", round, ret);
            break;
        }
        
        uint8_t key[KEY_SIZE];
        ret = client_node_compute_key(&node, round, key);
        if (ret != CRYPTO_OK) {
            ESP_LOGE(TAG, "Failed to compute key for round %lu: %d", round, ret);
            break;
        }
        memcpy(node.round_keys[round], key, KEY_SIZE);
        crypto_secure_zeroize(key, KEY_SIZE);
        
        ret = client_node_create_payload(&node, model_update, &payload);
        if (ret != CRYPTO_OK) {
            ESP_LOGE(TAG, "Failed to create payload for round %lu: %d", round, ret);
            break;
        }
        
        ret = network_serialize_payload(&payload, &net_buffer);
        if (ret != NET_OK) {
            ESP_LOGE(TAG, "Failed to serialize payload for round %lu: %d", round, ret);
            break;
        }
        
        ESP_LOGI(TAG, "Round %lu: Payload created (%d bytes)", round, net_buffer.length);
    }
    
    client_node_print_keys(&node);
    
    ESP_LOGI(TAG, "\n--- Simulating Compromise at Round 5 ---");
    ret = client_node_simulate_compromise(&node, 5);
    if (ret != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to simulate compromise: %d", ret);
    }
    
    ESP_LOGI(TAG, "\n--- Backtracking to Round 2 ---");
    uint8_t backtracked_key[KEY_SIZE];
    ret = client_node_backtrack_key(&node, 2, backtracked_key);
    if (ret != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to backtrack key: %d", ret);
    } else {
        int match = crypto_constant_time_compare(node.round_keys[2], backtracked_key, KEY_SIZE);
        ESP_LOGI(TAG, "Original Round 2 Key:   ");
        for (int i = 0; i < KEY_SIZE; i++) {
            printf("%02x", node.round_keys[2][i]);
        }
        printf("\n");
        ESP_LOGI(TAG, "Backtracked Round 2 Key:");
        for (int i = 0; i < KEY_SIZE; i++) {
            printf("%02x", backtracked_key[i]);
        }
        printf("\n");
        ESP_LOGI(TAG, "Keys Match: %s", match == 0 ? "YES (Forward Privacy BROKEN)" : "NO");
        
        ret = network_create_backtrack_result_json(2, node.round_keys[2], backtracked_key, match == 0, &json_str);
        if (ret == NET_OK && json_str) {
            ESP_LOGI(TAG, "Backtrack Result JSON: %s", json_str);
            network_free_json_string(json_str);
        }
    }
    
    ret = network_create_key_trace_json(&node, &json_str);
    if (ret == NET_OK && json_str) {
        ESP_LOGI(TAG, "\nFull Key Trace JSON:\n%s", json_str);
        network_free_json_string(json_str);
    }
    
    client_node_cleanup(&node);
}

static void run_pqc_ratcheting_simulation(void) {
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, "Starting PQC Hash-Chain Ratcheting (Method B)");
    ESP_LOGI(TAG, "============================================");
    
    client_node_t node;
    uint8_t client_id[CLIENT_ID_SIZE] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t model_update[MODEL_UPDATE_SIZE];
    client_payload_t payload;
    network_buffer_t net_buffer;
    char *json_str = NULL;
    
    crypto_err_t ret = client_node_init(&node, METHOD_PQC_RATCHETING, client_id);
    if (ret != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to initialize PQC Ratcheting client: %d", ret);
        return;
    }
    
    for (uint32_t round = 0; round < MAX_ROUNDS; round++) {
        SIMULATE_MODEL_UPDATE_ROUND(round, model_update);
        
        ret = client_node_start_round(&node, round);
        if (ret != CRYPTO_OK) {
            ESP_LOGE(TAG, "Failed to start round %lu: %d", round, ret);
            break;
        }
        
        ret = client_node_create_payload(&node, model_update, &payload);
        if (ret != CRYPTO_OK) {
            ESP_LOGE(TAG, "Failed to create payload for round %lu: %d", round, ret);
            break;
        }
        
        ret = network_serialize_payload(&payload, &net_buffer);
        if (ret != NET_OK) {
            ESP_LOGE(TAG, "Failed to serialize payload for round %lu: %d", round, ret);
            break;
        }
        
        ESP_LOGI(TAG, "Round %lu: Payload created (%d bytes)", round, net_buffer.length);
    }
    
    client_node_print_keys(&node);
    
    ESP_LOGI(TAG, "\n--- Simulating Compromise at Round 5 ---");
    ret = client_node_simulate_compromise(&node, 5);
    if (ret != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to simulate compromise: %d", ret);
    }
    
    ESP_LOGI(TAG, "\n--- Backtracking to Round 2 ---");
    uint8_t backtracked_key[KEY_SIZE];
    ret = client_node_backtrack_key(&node, 2, backtracked_key);
    if (ret != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to backtrack key: %d", ret);
    } else {
        int match = crypto_constant_time_compare(node.round_keys[2], backtracked_key, KEY_SIZE);
        ESP_LOGI(TAG, "Original Round 2 Key:   ");
        for (int i = 0; i < KEY_SIZE; i++) {
            printf("%02x", node.round_keys[2][i]);
        }
        printf("\n");
        ESP_LOGI(TAG, "Backtracked Round 2 Key:");
        for (int i = 0; i < KEY_SIZE; i++) {
            printf("%02x", backtracked_key[i]);
        }
        printf("\n");
        ESP_LOGI(TAG, "Keys Match: %s", match == 0 ? "YES (Forward Privacy BROKEN)" : "NO (Forward Privacy PRESERVED)");
        
        ret = network_create_backtrack_result_json(2, node.round_keys[2], backtracked_key, match == 0, &json_str);
        if (ret == NET_OK && json_str) {
            ESP_LOGI(TAG, "Backtrack Result JSON: %s", json_str);
            network_free_json_string(json_str);
        }
    }
    
    ret = network_create_key_trace_json(&node, &json_str);
    if (ret == NET_OK && json_str) {
        ESP_LOGI(TAG, "\nFull Key Trace JSON:\n%s", json_str);
        network_free_json_string(json_str);
    }
    
    client_node_cleanup(&node);
}

static void print_final_comparison(void) {
    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, "FINAL COMPARISON PROOF");
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Method A (Simple SecAgg):");
    ESP_LOGI(TAG, "  - Uses static_secret || round_num -> SHA256");
    ESP_LOGI(TAG, "  - Compromise at Round 5 reveals static_secret");
    ESP_LOGI(TAG, "  - Adversary can compute ANY past/future round key");
    ESP_LOGI(TAG, "  - Result: Forward Privacy BROKEN");
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Method B (PQC Hash-Chain Ratcheting):");
    ESP_LOGI(TAG, "  - Uses unidirectional hash chain: seed_t -> ephemeral_key -> seed_t+1");
    ESP_LOGI(TAG, "  - Compromise at Round 5 reveals seed_5 only");
    ESP_LOGI(TAG, "  - Cannot reverse SHA256 to get seed_4, seed_3, ... seed_2");
    ESP_LOGI(TAG, "  - Result: Forward Privacy PRESERVED");
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Core Result: Hash-chain ratcheting provides");
    ESP_LOGI(TAG, "forward privacy; static key derivation does not.");
    ESP_LOGI(TAG, "============================================");
}

void app_main(void) {
    ESP_LOGI(TAG, "CAPSTONE SecAgg Forward Privacy Demo Starting...");
    ESP_LOGI(TAG, "Target: Seeed Studio XIAO ESP32-C3");
    ESP_LOGI(TAG, "FreeRTOS Heap: %zu bytes free", esp_get_free_heap_size());
    
    run_simple_secagg_simulation();
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    run_pqc_ratcheting_simulation();
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    print_final_comparison();
    
    ESP_LOGI(TAG, "Demo complete. Free heap: %zu bytes", esp_get_free_heap_size());
    
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}