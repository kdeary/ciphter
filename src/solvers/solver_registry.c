#include <ctype.h>

#include <string.h>

#include "../../lib/sds/sds.h"

#include "solver_registry.h"

#include "../utils.h"

#include "../english_detector.h"

#define solver_fn(fn_label) static solver_result_t solve_ ## fn_label(sds input, keychain_t * keychain)
#define SOLVER(fn_label, p_score, consecutive) { .label = #fn_label, .popularity = p_score, .prevent_consecutive = consecutive, .fn = solve_ ## fn_label }
#define DEBUG 1
#define ALPHABET_SIZE 26

// Solver Constants
#define VIGENERE_THRESHOLD 0.01f

// Affine, Railfence, Vigenere fitness have lower base scores because its outputs always have only printable characters
#define BASIC_DEFAULT_FITNESS 0.75f
#define PENALTY_FACTOR 0.01f

// hex string to bytes
solver_fn(HEX) {
    int len = sdslen(input);
    unsigned char * data = hex_to_bytes(input, & len);

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

    free(data);
    return result;
}

solver_fn(BASE64) {
    size_t out_len;
    unsigned char * decoded = base64_decode(input, sdslen(input), & out_len);

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

solver_fn(BINARY) {
    int len = 0;
    unsigned char * data = binary_to_bytes(input, & len);

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

    free(data);
    return result;
}

solver_fn(OCTAL) {
    int len = 0;
    unsigned char * data = octal_to_bytes(input, & len);

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

    free(data);
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

char * affine_decrypt(sds text, int a, int b) {
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
        for (int b = 0; b < ALPHABET_SIZE; b++) {
            sds plain = affine_decrypt(input, a, b);
            if (!plain) continue;

            sds decrypted = sdsnew(plain);
            free(plain);

            float penalty = ((float) a * ALPHABET_SIZE + (float) b) / (ALPHABET_SIZE * ALPHABET_SIZE);
            float fitness = BASIC_DEFAULT_FITNESS - (penalty * PENALTY_FACTOR);

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

static solver_result_t solve_VIGENERE(sds input, keychain_t * keychain) {
    solver_result_t result = {
        .len = 0,
        .outputs = NULL,
    };

    if (keychain == NULL || keychain -> len == 0) return result;

    int candidates = 0;
    int input_len = sdslen(input);

    // Vigenere requires alpha only? Or we skip non-alpha.
    // Standard implementation: skip non-alpha in plaintext, rotate by key.
    // Decryption: P = (C - K + 26) % 26

    for (int k = 0; k < keychain -> len; k++) {
        sds key = keychain -> keys[k];
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

        float penalty = ((float) k) / keychain -> len;
        float fitness = BASIC_DEFAULT_FITNESS - (penalty * PENALTY_FACTOR);

        result.outputs = realloc(result.outputs, sizeof(solver_output_t) * (candidates + 1));
        result.outputs[candidates].data = output;
        result.outputs[candidates].method = sdscatprintf(sdsempty(), "VIGENERE(%s)", key);
        result.outputs[candidates].fitness = fitness;
        candidates++;
    }

    result.len = candidates;
    return result;
}




solver_fn(RAILFENCE) {
    solver_result_t result = {
        .len = 0,
        .outputs = NULL,
    };

    int candidates = 0;
    int len = sdslen(input);
    if (len < 2) return result;

    int max_rails = len > 32 ? 32 : (len < 4 ? len : len/2 + 2);

    for (int k = 2; k < max_rails; k++) {
        int cycle_len = 2 * k - 2;
        for (int o = 0; o < cycle_len; o++) {
            // Rail Fence Decryption with Offset
            // 1. Mark spots
            char *matrix = calloc(k * len, sizeof(char));
            if (!matrix) continue;

            for (int i = 0; i < len; i++) {
                int cycle_pos = (i + o) % cycle_len;
                int row = cycle_pos < k ? cycle_pos : cycle_len - cycle_pos;
                matrix[row * len + i] = '*'; // marker
            }

            // 2. Fill spots with ciphertext
            int idx = 0;
            for (int r = 0; r < k; r++) {
                for (int c = 0; c < len; c++) {
                    if (matrix[r * len + c] == '*' && idx < len) {
                        matrix[r * len + c] = input[idx++];
                    }
                }
            }

            // 3. Read zigzag
            sds plain = sdsnewlen(NULL, len);
            for (int i = 0; i < len; i++) {
                int cycle_pos = (i + o) % cycle_len;
                int row = cycle_pos < k ? cycle_pos : cycle_len - cycle_pos;
                plain[i] = matrix[row * len + i];
            }

            free(matrix);

            float penalty = ((float) k) / max_rails;
            float fitness = BASIC_DEFAULT_FITNESS - (penalty * PENALTY_FACTOR);

            result.outputs = realloc(result.outputs, sizeof(solver_output_t) * (candidates + 1));
            result.outputs[candidates].data = plain;
            result.outputs[candidates].method = sdscatprintf(sdsempty(), "RAILFENCE (k=%d, o=%d)", k, o);
            result.outputs[candidates].fitness = fitness;
            candidates++;
        }
    }

    result.len = candidates;
    return result;
}

solver_fn(BASE) {
    solver_result_t result = {
        .len = 0,
        .outputs = NULL,
    };

    int candidates = 0;
    int len = sdslen(input);
    if (len == 0) return result;

    // Try bases 2 through 36
    for (int base = 2; base <= 36; base++) {
        // Validate if input is valid for this base
        int is_valid = 1;
        for (int i = 0; i < len; i++) {
            int val = -1;
            char c = input[i];
            
            if (isdigit(c)) val = c - '0';
            else if (islower(c)) val = c - 'a' + 10;
            else if (isupper(c)) val = c - 'A' + 10;

            if (val == -1 || val >= base) {
                is_valid = 0;
                break;
            }
        }

        if (!is_valid) continue;

        // Perform base conversion to decimal using unsigned long long
        unsigned long long acc = 0;
        int overflow = 0;

        for (int i = 0; i < len; i++) {
            char c = input[i];
            int val = 0;
            if (isdigit(c)) val = c - '0';
            else if (islower(c)) val = c - 'a' + 10;
            else if (isupper(c)) val = c - 'A' + 10;

            // Check overflow: acc * base + val > ULLONG_MAX
            if (acc > (0xFFFFFFFFFFFFFFFFULL - val) / base) {
                overflow = 1;
                break;
            }

            acc = acc * base + val;
        }

        if (overflow) {
            continue;
        }

        float penalty = ((float) base) / 36.0f;
        float fitness = BASIC_DEFAULT_FITNESS - (penalty * PENALTY_FACTOR);
        
        sds decimal_str = sdsfromlonglong(acc);

        result.outputs = realloc(result.outputs, sizeof(solver_output_t) * (candidates + 1));
        result.outputs[candidates].data = decimal_str;
        result.outputs[candidates].method = sdscatprintf(sdsempty(), "BASE (base %d)", base);
        result.outputs[candidates].fitness = fitness;
        candidates++;
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
    SOLVER(VIGENERE, 0.5, 0),
    SOLVER(BASE, 0.5, 0),
    SOLVER(RAILFENCE, 0.5, 0),
};

size_t solvers_count = sizeof(solvers) / sizeof(solver_t);

solver_t * get_solvers(const char * algorithms, size_t * count) {
    // TODO: Implement filtering based on 'algorithms' string
    * count = solvers_count;
    return solvers;
}
