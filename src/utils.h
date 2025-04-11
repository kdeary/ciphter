#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>

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

extern float fitness_heuristic(sds data) {
	int len = sdslen(data);
	float score = 0.0f;
	for (int i = 0; i < len; i++) {
		if (isprint(data[i])) score += 1.0f;
	}
	return score / len;
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