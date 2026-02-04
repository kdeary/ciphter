#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <string.h>

#include "../lib/sds/sds.h"

static unsigned char decoding_table[256];
static int table_built = 0;

// Convert hex char to int
extern int hex_char_to_int(char c) {
	if ('0' <= c && c <= '9') return c - '0';
	if ('a' <= c && c <= 'f') return 10 + (c - 'a');
	if ('A' <= c && c <= 'F') return 10 + (c - 'A');
	return -1;
}

// English letter frequencies (normalized to sum to 1.0)
// Source: https://en.wikipedia.org/wiki/Letter_frequency
static const float english_freq[26] = {
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
	0.00074  // Z
};

extern float fitness_english_freq(sds data) {
	int len = sdslen(data);
	if (len == 0) return 0.0f;

	int letter_counts[26] = {0};
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
		float observed = (float)letter_counts[i];
		float expected = english_freq[i] * total_letters;
		if (expected > 0.0f) {
			float diff = observed - expected;
			score += (diff * diff) / expected;
		}
	}

	// Lower chi-squared score means better match; invert it to match higher-is-better pattern
	return 1.0f / (1.0f + score);
}

extern float fitness_heuristic(sds data) {
	int len = sdslen(data);
	float score = 0.0f;
	for (int i = 0; i < len; i++) {
		if (isprint(data[i])) score += 1.0f;
	}

	if (len > 0) {
		float ratio = score / len;
        // Exponential punishment for non-printable characters
        // 95% printable = 0.66
        // 90% printable = 0.43
        // 80% printable = 0.16
		return (float)pow(ratio, 8.0);
	} else {
		return 0.0f;
	}
}

// Convert hex string to bytes
extern unsigned char *hex_to_bytes(const char *hex, int *out_len) {
	unsigned char *bytes = malloc(strlen(hex) / 2); // max possible size
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

	*out_len = byte_index;
	return bytes;
}

// Convert binary string (0s and 1s, ignoring other chars) to bytes
extern unsigned char *binary_to_bytes(const char *bin, int *out_len) {
    int len = strlen(bin);
    unsigned char *bytes = malloc(len / 8 + 1); // Approximation
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

    *out_len = byte_index;
    return bytes;
}

// Convert octal string (0-7, ignoring other chars) to bytes
// Assumes 3 digits per byte (e.g. 101 => 65 'A')
extern unsigned char *octal_to_bytes(const char *oct, int *out_len) {
    int len = strlen(oct);
    unsigned char *bytes = malloc(len + 1);
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
                    bytes[byte_index++] = (unsigned char)current_val;
                 }
                 current_val = 0;
                 digit_count = 0;
            }
        } else {
             // Delimiter. If we have leftover digits, flush them.
             if (digit_count > 0) {
                 if (current_val <= 255) {
                    bytes[byte_index++] = (unsigned char)current_val;
                 }
                 current_val = 0;
                 digit_count = 0;
             }
        }
    }
    // Flush trailing
    if (digit_count > 0) {
         if (current_val <= 255) {
            bytes[byte_index++] = (unsigned char)current_val;
         }
    }

    *out_len = byte_index;
    return bytes;
}

static void build_decoding_table() {
	for (int i = 0; i < 64; i++) {
		decoding_table[(unsigned char)
			("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i])] = i;
	}
	table_built = 1;
}

extern unsigned char *base64_decode(const char *data, size_t input_len, size_t *output_len) {
	if (!table_built) build_decoding_table();

	if (input_len % 4 != 0) return NULL;

	size_t alloc_len = input_len / 4 * 3;
	if (data[input_len - 1] == '=') alloc_len--;
	if (data[input_len - 2] == '=') alloc_len--;

	unsigned char *decoded_data = malloc(alloc_len);
	if (!decoded_data) return NULL;

	for (size_t i = 0, j = 0; i < input_len;) {
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];

		uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

		if (j < alloc_len) decoded_data[j++] = (triple >> 16) & 0xFF;
		if (j < alloc_len) decoded_data[j++] = (triple >> 8) & 0xFF;
		if (j < alloc_len) decoded_data[j++] = triple & 0xFF;
	}

	*output_len = alloc_len;
	return decoded_data;
}

#endif // UTILS_H