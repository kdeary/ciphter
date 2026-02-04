#ifndef SOLVER_REGISTRY_H
#define SOLVER_REGISTRY_H

#include "../../lib/sds/sds.h"

typedef struct {
	int len;
	sds *keys;
} keychain_t;

typedef struct {
	float fitness;
    float cumulative_fitness;
	int depth;
	sds method;
	sds data;
	const char *last_solver;
} solver_output_t;

typedef struct {
	int len;
	solver_output_t *outputs;
} solver_result_t;

typedef struct {
	const char *label;

	// 1 = popular, 0.75 = common, 0.5 = uncommon, 0.25 = rare, 0 = special
	float popularity;

	int prevent_consecutive;
	
	solver_result_t (*fn)(sds input, keychain_t *keychain);
} solver_t;

extern solver_t solvers[];
extern size_t solvers_count;
extern solver_t *get_solvers(const char *algorithms, size_t *count);

#endif // SOLVER_REGISTRY_H