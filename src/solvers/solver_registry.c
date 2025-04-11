#include <ctype.h>
#include <string.h>
#include "../../lib/sds/sds.h"
#include "solver_registry.h"
#include "../utils.h"

#define solver_fn(fn_label) static solver_result_t solve_ ## fn_label (sds input, keychain_t *keychain)
#define SOLVER(fn_label) { .label = #fn_label, .popularity = 0.5, .fn = solve_ ## fn_label }

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
	result.outputs[0].method = "N/A";
	result.outputs[0].fitness = fitness_heuristic(result.outputs[0].data);

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
	result.outputs[0].method = "N/A";
	result.outputs[0].fitness = fitness_heuristic(result.outputs[0].data);

	free(decoded);
	return result;
}

// Ordered by popularity/commonness
solver_t solvers[] = {
	SOLVER(HEX),
	SOLVER(BASE64),
};

size_t solvers_count = sizeof(solvers) / sizeof(solver_t);