#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <string.h>
#include "../lib/sds/sds.h"
#include "solvers/solver_registry.h" 

#define PRINTABLE_PENALTY_POWER 0.5f
#define ENGLISH_FREQ_POWER 8.0f

extern int verbose_flag;
#define debug_log(fmt, ...) do { if (verbose_flag) { printf("[DEBUG] " fmt, ##__VA_ARGS__); } } while (0)

// Converters
int hex_char_to_int(char c);
unsigned char *hex_to_bytes(const char *hex, int *out_len);
unsigned char *binary_to_bytes(const char *bin, int *out_len);
unsigned char *octal_to_bytes(const char *oct, int *out_len);
unsigned char *base64_decode(const char *data, size_t input_len, size_t *output_len);

// Fitness / Scoring
float fitness_heuristic(sds data);

// Helpers
void free_result(solver_result_t *result);
void free_output(solver_output_t *output);
void free_heap_output(void *key, void *value);
int output_compare_fn(void *output1, void *output2);

#endif // UTILS_H
