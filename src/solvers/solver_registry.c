#include <ctype.h>
#include <string.h>
#include "../../lib/sds/sds.h"
#include "solver_registry.h"
#include "xor.h"
#include "../utils.h"
#include "../english_detector.h"

#define solver_fn(fn_label) static solver_result_t solve_ ## fn_label (sds input, keychain_t *keychain)
#define SOLVER(fn_label) { .label = #fn_label, .popularity = 0.5, .fn = solve_ ## fn_label }
#define DEBUG 1
#define ALPHABET_SIZE 26

// hex string to bytes
solver_fn(HEX) {
	int len = sdslen(input);
	unsigned char *data = hex_to_bytes(input, &len);

	solver_result_t result = {
		.len = 0,
		.outputs = NULL,
	};

	if (!data) return result;

	result.outputs = malloc(sizeof(solver_output_t));
	result.len = 1;

	result.outputs[0].data = sdsnewlen(data, len);
	result.outputs[0].method = sdsnew("HEX");
	result.outputs[0].fitness = score_english_combined(result.outputs[0].data, sdslen(result.outputs[0].data)) + 0.01f;

	return result;
}

solver_fn(BASE64) {
	solver_result_t result = {0};
	size_t decoded_len;
	unsigned char *decoded = base64_decode(input, sdslen(input), &decoded_len);
	if (!decoded) {
		free(result.outputs);
		result.outputs = NULL;
		result.len = 0;
		return result;
	}

	result.outputs = malloc(sizeof(solver_output_t));
	result.len = 1;

	result.outputs[0].data = sdsnewlen(decoded, decoded_len);
	result.outputs[0].method = sdsnew("BASE64");
	result.outputs[0].fitness = score_english_combined(result.outputs[0].data, sdslen(result.outputs[0].data)) + 0.01f;

	free(decoded);
	return result;
}

int mod_inverse(int a, int m) {
	for (int i = 1; i < m; i++) {
		if ((a * i) % m == 1) return i;
	}
	return -1;
}

int is_coprime(int a, int m) {
	int t;
	while (m != 0) {
		t = a % m;
		a = m;
		m = t;
	}
	return a == 1;
}

char *affine_decrypt(sds text, int a, int b) {
	int a_inv = mod_inverse(a, ALPHABET_SIZE);
	if (a_inv == -1) return NULL;

	size_t len = sdslen(text);
	sds out = malloc(len + 1);
	if (!out) return NULL;

	for (size_t i = 0; i < len; i++) {
		char c = text[i];
		if (isalpha(c)) {
			char base = isupper(c) ? 'A' : 'a';
			out[i] = (char)(((a_inv * ((c - base - b + ALPHABET_SIZE)) % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE + base);
		} else {
			out[i] = c; // Leave non-alphabet characters untouched
		}
	}
	out[len] = '\0';
	return out;
}

solver_fn(AFFINE) {
	solver_result_t result = {
		.len = 0,
		.outputs = NULL,
	};

	int candidates = 0;

	for (int a = 1; a < ALPHABET_SIZE; a++) {
		if (!is_coprime(a, ALPHABET_SIZE)) continue;

		for (int b = 0; b < ALPHABET_SIZE; b++) {
			sds plain = affine_decrypt(input, a, b);
			if (!plain) continue;

			sds decrypted = sdsnew(plain);
			float fitness = score_english_combined(decrypted, sdslen(decrypted));
			free(plain);

			if (fitness < 0.5) {
				sdsfree(decrypted);
				continue;
			}

			result.outputs = realloc(result.outputs, sizeof(solver_output_t) * (candidates + 1));
			result.outputs[candidates].data = decrypted;
			result.outputs[candidates].method = sdscatprintf(sdsempty(), "AFFINE a=%d b=%d", a, b);
			result.outputs[candidates].fitness = fitness;
			candidates++;
		}
	}

	result.len = candidates;
	return result;
}

char *caesar_decrypt(sds text, int shift) {
	size_t len = sdslen(text);
	sds out = sdsnewlen("", len);
	if (!out) return NULL;

	for (size_t i = 0; i < len; i++) {
		char c = text[i];
		if (isalpha(c)) {
			char base = isupper(c) ? 'A' : 'a';
			out[i] = (char)(((c - base - shift + ALPHABET_SIZE) % ALPHABET_SIZE) + base);
		} else {
			out[i] = c; // Leave non-alphabet characters untouched
		}
	}

	out[len] = '\0';
	return out;
}

solver_fn(CAESAR) {
	solver_result_t result = {
		.len = 0,
		.outputs = NULL,
	};

	int candidates = 0;

	for (int shift = 1; shift < ALPHABET_SIZE; shift++) {
		sds plain = caesar_decrypt(input, shift);
		if (!plain) continue;

		sds decrypted = sdsnew(plain);
		float fitness = score_english_combined(decrypted, sdslen(decrypted));
		free(plain);

		if (fitness < 0.5) {
			sdsfree(decrypted);
			continue;
		}

		result.outputs = realloc(result.outputs, sizeof(solver_output_t) * (candidates + 1));
		result.outputs[candidates].data = decrypted;
		result.outputs[candidates].method = sdscatprintf(sdsempty(), "CAESAR shift=%d", shift);
		result.outputs[candidates].fitness = fitness;
		candidates++;
	}

	result.len = candidates;
	return result;
}

// Ordered by popularity/commonness
solver_t solvers[] = {
	SOLVER(HEX),
	SOLVER(BASE64),
	SOLVER(AFFINE),
	SOLVER(CAESAR),
};

size_t solvers_count = sizeof(solvers) / sizeof(solver_t);