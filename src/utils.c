#include "utils.h"

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

// English letter frequencies (normalized to sum to 1.0)
// Source: https://en.wikipedia.org/wiki/Letter_frequency
static
const float english_freq[26] = {
    0.08167, // A
    0.01492, // B
    0.02782, // C
    0.04253, // D
    0.12702, // E
    0.02228, // F
    0.02015, // G
    0.06094, // H
    0.06966, // I
    0.00153, // J
    0.00772, // K
    0.04025, // L
    0.02406, // M
    0.06749, // N
    0.07507, // O
    0.01929, // P
    0.00095, // Q
    0.05987, // R
    0.06327, // S
    0.09056, // T
    0.02758, // U
    0.00978, // V
    0.02360, // W
    0.00150, // X
    0.01974, // Y
    0.00074 // Z
};

// ==========================================
// Helper Implementations (from utils.h)
// ==========================================

int hex_char_to_int(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + (c - 'a');
    if ('A' <= c && c <= 'F') return 10 + (c - 'A');
    return -1;
}

float fitness_english_freq(sds data) {
    int len = sdslen(data);
    if (len == 0) return 0.0f;

    int letter_counts[26] = {
        0
    };
    int total_letters = 0;

    for (int i = 0; i < len; i++) {
        if (isalpha(data[i])) {
            char ch = tolower(data[i]);
            letter_counts[ch - 'a']++;
            total_letters++;
        }
    }

    if (total_letters == 0) return 0.0f;

    // Calculate chi-squared score
    float score = 0.0f;
    for (int i = 0; i < 26; i++) {
        float observed = (float) letter_counts[i];
        float expected = english_freq[i] * total_letters;
        if (expected > 0.0f) {
            float diff = observed - expected;
            score += (diff * diff) / expected;
        }
    }

    // Lower chi-squared score means better match; invert it to match higher-is-better pattern
    return 1.0f / (1.0f + score);
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

int output_compare_fn(void * output1, void * output2) {
    solver_output_t * o1 = (solver_output_t * ) output1;
    solver_output_t * o2 = (solver_output_t * ) output2;

    // Normalize by depth to prevent Depth-First Search behavior from dominating
    float score1 = o1 -> cumulative_fitness / (o1 -> depth + 1.0f);
    float score2 = o2 -> cumulative_fitness / (o2 -> depth + 1.0f);

    if (score1 > score2) return -1; // o1 is "smaller" (top of heap/best)
    if (score1 < score2) return 1;
    return 0;
}

// Top 5 Helpers
#define TOP_N 5
static solver_output_t * top_results[TOP_N] = {
    0
};

solver_output_t * clone_output(solver_output_t * src) {
    solver_output_t * dst = malloc(sizeof(solver_output_t));
    * dst = * src;
    dst -> method = sdsdup(src -> method);
    dst -> data = sdsdup(src -> data);
    dst -> last_solver = src -> last_solver; // pointer copy for static string
    return dst;
}

float get_score(solver_output_t * o) {
    return o -> cumulative_fitness / (o -> depth + 1.0f);
}

int update_top_results(solver_output_t * candidate) {
    float score = get_score(candidate);
    int insert_idx = -1;

    // Top 5 sorted descending: [0] Best ... [4] Worst
    for (int i = 0; i < TOP_N; i++) {
        if (top_results[i] == NULL) {
            insert_idx = i;
            break;
        }
        if (score > get_score(top_results[i])) {
            insert_idx = i;
            break;
        }
    }

    if (insert_idx != -1) {
        if (top_results[TOP_N - 1]) {
            free_output(top_results[TOP_N - 1]);
            free(top_results[TOP_N - 1]);
        }
        for (int j = TOP_N - 1; j > insert_idx; j--) {
            top_results[j] = top_results[j - 1];
        }
        top_results[insert_idx] = clone_output(candidate);
        return 1; // Changed
    }
    return 0; // Not changed
}

void print_top_results(int * lines_printed) {
    if ( * lines_printed > 0) {
        // Move cursor up
        printf("\033[%dA", * lines_printed);
    }

    int count = 0;
    for (int i = TOP_N - 1; i >= 0; i--) {
        if (top_results[i]) {
            float display_fitness = top_results[i] -> fitness;
            float display_agg = top_results[i] -> cumulative_fitness;

            if (display_fitness > 5000.0f) display_fitness -= 10000.0f;
            if (display_agg > 5000.0f) display_agg -= 10000.0f;

            printf("\033[K"); // Clear line
            printf("[%d][%.0f%%][Agg:%.2f]\t [OUTPUT] \"%.20s...\" - Method: \"%s\"\n",
                top_results[i] -> depth,
                display_fitness * 100,
                display_agg,
                top_results[i] -> data,
                top_results[i] -> method);
            count++;
        }
    }
    * lines_printed = count;
}

void reset_top_results() {
    for (int i = 0; i < TOP_N; i++) {
        top_results[i] = NULL;
    }
}

solver_output_t * get_best_result() {
    return top_results[0];
}

void free_top_results() {
    for (int i = 0; i < TOP_N; i++) {
        if (top_results[i]) {
            free_output(top_results[i]);
            free(top_results[i]);
            top_results[i] = NULL;
        }
    }
}
