#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <float.h>
#include <math.h>

#define MAX_KEYSIZE 40
#define NUM_KEYSIZE_CANDIDATES 3

// XOR two bytes and count differing bits
int hamming_distance(const unsigned char *a, const unsigned char *b, int len) {
	int dist = 0;
	for (int i = 0; i < len; i++) {
		unsigned char val = a[i] ^ b[i];
		while (val) {
			dist += val & 1;
			val >>= 1;
		}
	}
	return dist;
}

// Score plaintext for likelihood of being English
float score_printable(const unsigned char *data, int len) {
    float score = 0.0;
    for (int i = 0; i < len; i++) {
        if (isprint(data[i]))
            score += 1.0;
        else
            score -= 2.0;
    }
    return score;
}

// Guess key size based on normalized hamming distance
void guess_key_sizes(const unsigned char *data, int len, int *out_keysizes) {
	double scores[MAX_KEYSIZE + 1] = {0};

	for (int keysize = 2; keysize <= MAX_KEYSIZE; keysize++) {
		int num_blocks = len / keysize;
		if (num_blocks < 2) continue;

		double total = 0;
		for (int i = 0; i < num_blocks - 1; i++) {
			const unsigned char *a = data + i * keysize;
			const unsigned char *b = data + (i + 1) * keysize;
			int dist = hamming_distance(a, b, keysize);
			total += (double)dist / keysize;
		}
		scores[keysize] = total / (num_blocks - 1);
	}

	// Get top N lowest scores (most likely key sizes)
	for (int i = 0; i < NUM_KEYSIZE_CANDIDATES; i++) {
		double min_score = DBL_MAX;
		int best_keysize = 0;
		for (int k = 2; k <= MAX_KEYSIZE; k++) {
			if (scores[k] < min_score) {
				min_score = scores[k];
				best_keysize = k;
			}
		}
		out_keysizes[i] = best_keysize;
		scores[best_keysize] = DBL_MAX;
	}
}

// Brute-force single-byte XOR
unsigned char guess_single_byte_xor(const unsigned char *block, int len, double *out_score) {
	double best_score = -DBL_MAX;
	unsigned char best_key = 0;

	for (int k = 0; k < 256; k++) {
		unsigned char *decoded = malloc(len);
		for (int i = 0; i < len; i++) {
			decoded[i] = block[i] ^ k;
		}
		double score = score_english(decoded, len);
		if (score > best_score) {
			best_score = score;
			best_key = k;
		}
		free(decoded);
	}

	*out_score = best_score;
	return best_key;
}

// Break repeating-key XOR
void break_xor(const unsigned char *data) {
	int keysizes[NUM_KEYSIZE_CANDIDATES];
	int len = strlen((const char *)data);
	guess_key_sizes(data, len, keysizes);

	for (int i = 0; i < NUM_KEYSIZE_CANDIDATES; i++) {
		int keysize = keysizes[i];
		unsigned char *key = malloc(keysize);
		double total_score = 0;

		for (int j = 0; j < keysize; j++) {
			int block_len = (len - j + keysize - 1) / keysize;
			unsigned char *block = malloc(block_len);
			for (int k = 0; k < block_len; k++) {
				block[k] = data[j + k * keysize];
			}

			double block_score;
			key[j] = guess_single_byte_xor(block, block_len, &block_score);
			total_score += block_score;
			free(block);
		}

		// Decrypt
		unsigned char *plaintext = malloc(len + 1);
		for (int j = 0; j < len; j++) {
			plaintext[j] = data[j] ^ key[j % keysize];
		}
		plaintext[len] = '\0';

		printf("\n[*] Key size: %d\n", keysize);
		printf("[*] Key: ");
		for (int j = 0; j < keysize; j++) printf("%c", isprint(key[j]) ? key[j] : '.');
		printf("\n[*] Score: %.2f\n", total_score);
		printf("[*] Decrypted: %s\n", plaintext);

		free(plaintext);
		free(key);
	}
}

solver_fn(XOR) {
	static solve_result_t results[NUM_KEYSIZE_CANDIDATES + 32]; // reserve for bruteforce + keys[]
	int result_count = 0;

	int data_len = strlen(input);

	// First: try all keys from the keys[] array
	if (keys) {
		for (int i = 0; keys[i] != NULL && result_count < 32; i++) {
			const char *key = keys[i];
			int keylen = strlen(key);
			char *output = malloc(data_len + 1);
			for (int j = 0; j < data_len; j++) {
				output[j] = input[j] ^ key[j % keylen];
			}
			output[data_len] = '\0';

			results[result_count].fitness = score_english((unsigned char *)output, data_len);
			results[result_count].key = key;
			results[result_count].output = output;
			result_count++;
		}
	}

	// Second: automatic key length guessing + brute-force
	int keysizes[NUM_KEYSIZE_CANDIDATES];
	guess_key_sizes(input, data_len, keysizes);

	for (int i = 0; i < NUM_KEYSIZE_CANDIDATES && result_count < sizeof(results)/sizeof(results[0]); i++) {
		int keysize = keysizes[i];
		unsigned char *keybuf = malloc(keysize + 1);
		double total_score = 0;

		for (int j = 0; j < keysize; j++) {
			int block_len = (data_len - j + keysize - 1) / keysize;
			unsigned char *block = malloc(block_len);
			for (int k = 0; k < block_len; k++) {
				block[k] = input[j + k * keysize];
			}

			double block_score;
			keybuf[j] = guess_single_byte_xor(block, block_len, &block_score);
			total_score += block_score;
			free(block);
		}

		keybuf[keysize] = '\0';

		char *output = malloc(data_len + 1);
		for (int j = 0; j < data_len; j++) {
			output[j] = input[j] ^ keybuf[j % keysize];
		}
		output[data_len] = '\0';

		// Allocate a copy of key for result struct
		char *final_key = malloc(keysize + 1);
		memcpy(final_key, keybuf, keysize + 1);

		results[result_count].fitness = total_score;
		results[result_count].key = final_key;
		results[result_count].output = output;
		result_count++;

		free(keybuf);
	}

	return results;
}
