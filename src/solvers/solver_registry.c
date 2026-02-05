#include <ctype.h>
#include <string.h>
#include "../../lib/sds/sds.h"
#include "solver_registry.h"
#include "xor.h"
#include "../utils.h"
#include "../english_detector.h"

#define solver_fn(fn_label) static solver_result_t solve_ ## fn_label (sds input, keychain_t *keychain)
#define SOLVER(fn_label, p_score, consecutive) { .label = #fn_label, .popularity = p_score, .prevent_consecutive = consecutive, .fn = solve_ ## fn_label }
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
    result.outputs[0].fitness = score_combined(result.outputs[0].data, len);
    // Removed length penalty

	return result;
}

solver_fn(BASE64) {
	size_t out_len;
	unsigned char *decoded = base64_decode(input, sdslen(input), &out_len);

	solver_result_t result = {
		.len = 0,
		.outputs = NULL,
	};

	if (!decoded) return result;

	// Ignore empty results
	if (out_len == 0) {
		free(decoded);
		return result;
	}

	result.outputs = malloc(sizeof(solver_output_t));
	result.len = 1;

	result.outputs[0].data = sdsnewlen(decoded, out_len);
	result.outputs[0].method = sdsnew("BASE64");
	result.outputs[0].fitness = score_combined(result.outputs[0].data, out_len);

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
		// if (!is_coprime(a, ALPHABET_SIZE)) continue;

		for (int b = 0; b < ALPHABET_SIZE; b++) {
			sds plain = affine_decrypt(input, a, b);
			if (!plain) continue;

			sds decrypted = sdsnew(plain);
			float fitness = fitness_heuristic(decrypted);
			free(plain);

			// Heuristic: Penalize complex keys.
            // Start with base fitness, then subtract a tiny amount based on 'a' and 'b'.
            // This ensures "a=1 b=0" (simpler) > "a=3 b=10" (complex) given equal valid English output.
			if (fitness > 0) {
                // User requested priority: a=1 (all b), then a=higher.
                // Since max b=25, weighting a by 30 ensures a dominates b.
				float penalty = ((float)a * 30.0f + (float)b) / 2000.0f; 
				fitness = fitness - (penalty * 0.01f);
				if (fitness < 0) fitness = 0.001f; // Don't allow negative or zero if it was valid
			} else {
                fitness = 0.0f;
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



solver_fn(BINARY) {
    int len = 0;
    unsigned char *data = binary_to_bytes(input, &len);
    
    solver_result_t result = {
        .len = 0,
        .outputs = NULL,
    };

    if (!data) return result;
    if (len == 0) {
        free(data);
        return result;
    }

    result.outputs = malloc(sizeof(solver_output_t));
    result.len = 1;

    result.outputs[0].data = sdsnewlen(data, len);
    result.outputs[0].method = sdsnew("BINARY");
    result.outputs[0].fitness = score_combined(result.outputs[0].data, len);
    // Removed length penalty

    free(data);
    return result;
}

solver_fn(OCTAL) {
    int len = 0;
    unsigned char *data = octal_to_bytes(input, &len);
    
    solver_result_t result = {
        .len = 0,
        .outputs = NULL,
    };

    if (!data) return result;
    if (len == 0) {
        free(data);
        return result;
    }

    result.outputs = malloc(sizeof(solver_output_t));
    result.len = 1;

    result.outputs[0].data = sdsnewlen(data, len);
    result.outputs[0].method = sdsnew("OCTAL");
    result.outputs[0].fitness = score_combined(result.outputs[0].data, len);
    // Removed length penalty

    free(data);
    return result;
}

// Ordered by popularity/commonness

static solver_result_t solve_VIGENERE(sds input, keychain_t *keychain) {
	solver_result_t result = {
		.len = 0,
		.outputs = NULL,
	};
    
    if (keychain == NULL || keychain->len == 0) return result;

    int candidates = 0;
    int input_len = sdslen(input);
    
    // Vigenere requires alpha only? Or we skip non-alpha.
    // Standard implementation: skip non-alpha in plaintext, rotate by key.
    // Decryption: P = (C - K + 26) % 26
    
    for (int k = 0; k < keychain->len; k++) {
        sds key = keychain->keys[k];
        int key_len = sdslen(key);
        if (key_len == 0) continue;
        
        sds output = sdsdup(input);
        int key_idx = 0;
        
        for (int i = 0; i < input_len; i++) {
            if (isalpha(output[i])) {
                char base = isupper(output[i]) ? 'A' : 'a';
                
                char k_char = key[key_idx % key_len];
                int shift = 0;
                if (isupper(k_char)) shift = k_char - 'A';
                else if (islower(k_char)) shift = k_char - 'a';
                
                // Decrypt: (C - base - shift + 26) % 26 + base
                int c_val = output[i] - base;
                int p_val = (c_val - shift + 26) % 26;
                output[i] = p_val + base;
                
                key_idx++;
            }
        }
        
        float fitness = fitness_english_freq(output);
        
        if (fitness > 0.05f) {
           result.outputs = realloc(result.outputs, sizeof(solver_output_t) * (candidates + 1));
           result.outputs[candidates].data = output;
           result.outputs[candidates].method = sdscatprintf(sdsempty(), "VIGENERE(key=%s)", key);
           result.outputs[candidates].fitness = fitness;
           candidates++;
        } else {
            sdsfree(output);
        }
    }
    
    result.len = candidates;
    return result;
}
solver_t solvers[] = {
	SOLVER(HEX, 1, 0),
	SOLVER(BASE64, 1, 0),
    SOLVER(BINARY, 0.75, 0),
    SOLVER(OCTAL, 0.75, 0),
	SOLVER(AFFINE, 0.5, 1),
	SOLVER(VIGENERE, 0.5, 1),
};



size_t solvers_count = sizeof(solvers) / sizeof(solver_t);

solver_t *get_solvers(const char *algorithms, size_t *count) {
    // TODO: Implement filtering based on 'algorithms' string
    *count = solvers_count;
    return solvers;
}