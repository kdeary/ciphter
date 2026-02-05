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

// Converters
int hex_char_to_int(char c);
unsigned char *hex_to_bytes(const char *hex, int *out_len);
unsigned char *binary_to_bytes(const char *bin, int *out_len);
unsigned char *octal_to_bytes(const char *oct, int *out_len);
unsigned char *base64_decode(const char *data, size_t input_len, size_t *output_len);

// Fitness / Scoring
float fitness_english_freq(sds data);
float fitness_heuristic(sds data);

// Helpers
void free_result(solver_result_t *result);
void free_output(solver_output_t *output);
int output_compare_fn(void *output1, void *output2);

// Top 5 Helpers
void reset_top_results();
int update_top_results(solver_output_t *candidate);
void print_top_results(int *lines_printed);
solver_output_t *get_best_result();
void free_top_results();

#endif // UTILS_H