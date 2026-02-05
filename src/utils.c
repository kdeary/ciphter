#include "utils.h"

int verbose_flag = 0;

#include <ctype.h>

#include <math.h>

#include <string.h>

#include <stdio.h>

#include <stdlib.h>

#include "../lib/sds/sds.h"

#include "solvers/solver_registry.h"

// ==========================================
// Data Structures & Constants (from utils.h)
// ==========================================

static unsigned char decoding_table[256];
static int table_built = 0;

// ==========================================
// Helper Implementations (from utils.h)
// ==========================================

int hex_char_to_int(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + (c - 'a');
    if ('A' <= c && c <= 'F') return 10 + (c - 'A');
    return -1;
}

float fitness_heuristic(sds data) {
    int len = sdslen(data);
    float score = 0.0f;
    for (int i = 0; i < len; i++) {
        if (isprint(data[i])) score += 1.0f;
    }

    if (len > 0) {
        float ratio = score / len;
        // Exponential punishment for non-printable characters
        return (float) pow(ratio, 8.0);
    } else {
        return 0.0f;
    }
}

unsigned char * hex_to_bytes(const char * hex, int * out_len) {
    unsigned char * bytes = malloc(strlen(hex) / 2); // max possible size
    if (!bytes) return NULL;

    int byte_index = 0;
    int nibble = -1;

    for (int i = 0; hex[i] != '\0'; i++) {
        int val = hex_char_to_int(hex[i]);
        if (val == -1) continue; // skip non-hex

        if (nibble == -1) {
            nibble = val; // store first nibble
        } else {
            bytes[byte_index++] = (nibble << 4) | val;
            nibble = -1; // reset for next pair
        }
    }

    * out_len = byte_index;
    return bytes;
}

unsigned char * binary_to_bytes(const char * bin, int * out_len) {
    int len = strlen(bin);
    unsigned char * bytes = malloc(len / 8 + 1); // Approximation
    if (!bytes) return NULL;

    int byte_index = 0;
    int bit_count = 0;
    unsigned char current_byte = 0;

    for (int i = 0; bin[i] != '\0'; i++) {
        if (bin[i] == '0' || bin[i] == '1') {
            current_byte = (current_byte << 1) | (bin[i] - '0');
            bit_count++;
            if (bit_count == 8) {
                bytes[byte_index++] = current_byte;
                bit_count = 0;
                current_byte = 0;
            }
        }
    }

    * out_len = byte_index;
    return bytes;
}

unsigned char * octal_to_bytes(const char * oct, int * out_len) {
    int len = strlen(oct);
    unsigned char * bytes = malloc(len + 1);
    if (!bytes) return NULL;

    int byte_index = 0;
    int digit_count = 0;
    int current_val = 0;

    for (int i = 0; oct[i] != '\0'; i++) {
        if (oct[i] >= '0' && oct[i] <= '7') {
            current_val = (current_val * 8) + (oct[i] - '0');
            digit_count++;

            // If we hit 3 digits, we MUST flush because max octal byte is 3 digits (377)
            if (digit_count == 3) {
                if (current_val <= 255) {
                    bytes[byte_index++] = (unsigned char) current_val;
                }
                current_val = 0;
                digit_count = 0;
            }
        } else {
            // Delimiter. If we have leftover digits, flush them.
            if (digit_count > 0) {
                if (current_val <= 255) {
                    bytes[byte_index++] = (unsigned char) current_val;
                }
                current_val = 0;
                digit_count = 0;
            }
        }
    }
    // Flush trailing
    if (digit_count > 0) {
        if (current_val <= 255) {
            bytes[byte_index++] = (unsigned char) current_val;
        }
    }

    * out_len = byte_index;
    return bytes;
}

static void build_decoding_table() {
    for (int i = 0; i < 64; i++) {
        decoding_table[(unsigned char)
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" [i])] = i;
    }
    table_built = 1;
}

unsigned char * base64_decode(const char * data, size_t input_len, size_t * output_len) {
    if (!table_built) build_decoding_table();

    if (input_len % 4 != 0) return NULL;

    size_t alloc_len = input_len / 4 * 3;
    if (data[input_len - 1] == '=') alloc_len--;
    if (data[input_len - 2] == '=') alloc_len--;

    unsigned char * decoded_data = malloc(alloc_len);
    if (!decoded_data) return NULL;

    for (size_t i = 0, j = 0; i < input_len;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char) data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char) data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char) data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char) data[i++]];

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < alloc_len) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < alloc_len) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < alloc_len) decoded_data[j++] = triple & 0xFF;
    }

    * output_len = alloc_len;
    return decoded_data;
}

// ==========================================
// Main Logic Helpers (from main.c)
// ==========================================

void free_result(solver_result_t * result) {
    for (size_t j = 0; j < result -> len; ++j) {
        sdsfree(result -> outputs[j].method);
        sdsfree(result -> outputs[j].data);
    }

    free(result -> outputs);
    result -> outputs = NULL;
}

void free_output(solver_output_t * output) {
    sdsfree(output -> method);
    sdsfree(output -> data);
}

void free_heap_output(void * key, void * value) {
    solver_output_t * output = (solver_output_t * ) value;
    if (output) {
        free_output(output);
        free(output);
    }
}

int output_compare_fn(void * output1, void * output2) {
    solver_output_t * o1 = (solver_output_t * ) output1;
    solver_output_t * o2 = (solver_output_t * ) output2;

    // Normalize by depth to prevent Depth-First Search behavior from dominating
    float score1 = o1 -> cumulative_fitness / (o1 -> depth + 1.0f);
    float score2 = o2 -> cumulative_fitness / (o2 -> depth + 1.0f);

    if (score1 > score2) return -1; // o1 is "smaller" (top of heap/best)
    if (score1 < score2) return 1;

    // Tie-break: favor higher cumulative fitness (deeper paths with same average quality)
    if (o1 -> cumulative_fitness > o2 -> cumulative_fitness) return -1;
    if (o1 -> cumulative_fitness < o2 -> cumulative_fitness) return 1;

    return 0;
}


