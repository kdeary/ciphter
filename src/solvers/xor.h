#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include "../../lib/sds/sds.h"
#include "../utils.h"

#define MAX_KEYS 1024
#define MAX_KEY_LENGTH 40
#define KNOWN_KEY_LENGTH 5  // substitute with actual value or global config

typedef struct {
	uint8_t** keys;  // array of key byte arrays
	int count;
	int key_length;
} KeyList;

typedef struct {
	uint8_t key[MAX_KEY_LENGTH];  // actual key bytes
	char source_char;             // character used to guess this key
} KeySource;

typedef struct {
	KeySource sources[MAX_KEYS];
	int count;
} KeyMap;

typedef struct {
	int key_length;
	double fitness;
} Fitness;

int chars_count_at_offset(const sds text, int key_length, int offset) {
	int counts[256] = {0};  // ASCII frequency table
	int len = sdslen(text);

	for (int pos = offset; pos < len; pos += key_length) {
		unsigned char c = (unsigned char)text[pos];
		counts[c]++;
	}

	// Find the maximum frequency
	int max_count = 0;
	for (int i = 0; i < 256; ++i) {
		if (counts[i] > max_count) {
			max_count = counts[i];
		}
	}

	return max_count;
}

int count_equals(const sds text, int key_length) {
	int len = sdslen(text);
	if (key_length >= len) {
		return 0;
	}

	int equals_count = 0;
	for (int offset = 0; offset < key_length; ++offset) {
		int max_count = chars_count_at_offset(text, key_length, offset);
		equals_count += max_count - 1;  // Python version had this adjustment
	}

	return equals_count;
}

Fitness* calculate_fitnesses(sds text, int* out_count) {
	double prev = 0;
	double pprev = 0;
	int capacity = 10;
	int count = 0;

	Fitness* fitnesses = malloc(capacity * sizeof(Fitness));
	if (!fitnesses) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
	}

	for (int key_length = 1; key_length <= MAX_KEY_LENGTH; ++key_length) {
		int raw_fitness = count_equals(text, key_length);
		double fitness = (double)raw_fitness / (MAX_KEY_LENGTH + pow(key_length, 1.5));

		if (pprev < prev && prev > fitness) {
			// Local maximum
			if (count >= capacity) {
				capacity *= 2;
				fitnesses = realloc(fitnesses, capacity * sizeof(Fitness));
				if (!fitnesses) {
					perror("realloc failed");
					exit(EXIT_FAILURE);
				}
			}
			fitnesses[count++] = (Fitness){key_length - 1, prev};
		}

		pprev = prev;
		prev = fitness;
	}

	// Check for last local maximum
	if (pprev < prev) {
		if (count >= capacity) {
			capacity += 1;
			fitnesses = realloc(fitnesses, capacity * sizeof(Fitness));
			if (!fitnesses) {
				perror("realloc failed");
				exit(EXIT_FAILURE);
			}
		}
		fitnesses[count++] = (Fitness){MAX_KEY_LENGTH, prev};
	}

	*out_count = count;
	return fitnesses;
}

int get_max_fitnessed_key_length(Fitness* fitnesses, int count) {
	double max_fitness = 0.0;
	int max_fitnessed_key_length = 0;

	for (int i = 0; i < count; ++i) {
		if (fitnesses[i].fitness > max_fitness) {
			max_fitness = fitnesses[i].fitness;
			max_fitnessed_key_length = fitnesses[i].key_length;
		}
	}

	return max_fitnessed_key_length;
}

int guess_key_length(sds text) {
	int fitness_count = 0;
	Fitness* fitnesses = calculate_fitnesses(text, &fitness_count);

	int best_key_length = get_max_fitnessed_key_length(fitnesses, fitness_count);

	free(fitnesses);  // clean up allocated memory
	return best_key_length;
}

KeyList all_keys(uint8_t** key_possible_bytes, int key_length, int offset, uint8_t* partial_key) {
	KeyList result = { .keys = malloc(MAX_KEYS * sizeof(uint8_t*)), .count = 0, .key_length = key_length };

	if (offset == key_length) {
		uint8_t* key = malloc(key_length);
		memcpy(key, partial_key, key_length);
		result.keys[result.count++] = key;
		return result;
	}

	for (int i = 0; key_possible_bytes[offset][i] != 0xFF; ++i) {
		partial_key[offset] = key_possible_bytes[offset][i];
		KeyList sub = all_keys(key_possible_bytes, key_length, offset + 1, partial_key);
		for (int j = 0; j < sub.count; ++j) {
			result.keys[result.count++] = sub.keys[j];
		}
		free(sub.keys);
	}

	return result;
}

KeyList guess_keys(sds text, char most_char) {
	int key_length = KNOWN_KEY_LENGTH;
	uint8_t* key_possible_bytes[MAX_KEY_LENGTH] = {0};

	for (int i = 0; i < key_length; ++i) {
		int counts[256] = {0};
		int len = sdslen(text);

		// Count characters at this offset
		for (int pos = i; pos < len; pos += key_length) {
			unsigned char c = text[pos];
			counts[c]++;
		}

		// Find max count
		int max_count = 0;
		for (int j = 0; j < 256; ++j) {
			if (counts[j] > max_count) {
				max_count = counts[j];
			}
		}

		// Collect bytes that match max count
		key_possible_bytes[i] = malloc(256);
		int index = 0;
		for (int j = 0; j < 256; ++j) {
			if (counts[j] == max_count) {
				key_possible_bytes[i][index++] = j ^ most_char;
			}
		}
		key_possible_bytes[i][index] = 0xFF;  // sentinel
	}

	uint8_t partial_key[MAX_KEY_LENGTH] = {0};
	KeyList result = all_keys(key_possible_bytes, key_length, 0, partial_key);

	for (int i = 0; i < key_length; ++i) {
		free(key_possible_bytes[i]);
	}

	return result;
}

KeyList guess_probable_keys_for_chars(sds text, const char* try_chars) {
	KeyList total_keys = { .keys = malloc(MAX_KEYS * sizeof(uint8_t*)), .count = 0, .key_length = KNOWN_KEY_LENGTH };
	KeyMap* key_map = malloc(sizeof(KeyMap));
	key_map->count = 0;

	for (int i = 0; try_chars[i] != '\0'; ++i) {
		char c = try_chars[i];
		KeyList keys = guess_keys(text, c);

		for (int j = 0; j < keys.count; ++j) {
			// Check if already added
			int exists = 0;
			for (int k = 0; k < total_keys.count; ++k) {
				if (memcmp(total_keys.keys[k], keys.keys[j], KNOWN_KEY_LENGTH) == 0) {
					exists = 1;
					break;
				}
			}

			if (!exists) {
				total_keys.keys[total_keys.count] = keys.keys[j];
				memcpy(key_map->sources[key_map->count].key, keys.keys[j], KNOWN_KEY_LENGTH);
				key_map->sources[key_map->count].source_char = c;
				key_map->count++;
				total_keys.count++;
			} else {
				free(keys.keys[j]);  // avoid memory leak
			}
		}

		free(keys.keys);
	}

	free(key_map);  // clean up key_map

	return total_keys;
}
