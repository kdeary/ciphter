#include <argp.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/sds/sds.h"
#include <stdio.h>
#include "analyzers/analysis_registry.h"
#include "solvers/solver_registry.h"

#define PROBABILITY_THRESHOLD 0.01f

const char *argp_program_version = "ciphter v0.1";
const char *argp_program_bug_address = "<korbin.deary45@gmail.com>";
static char doc[] = "ciphter — cryptography analysis and processing tool";
static char args_doc[] = "";

// Program options
static struct argp_option options[] = {
	{ "task", 't', "TYPE", 0, "Task type: A for analyze, S for solve" },
	{ "input", 'i', "STRING", 0, "Input ciphertext or filename" },
	{ "probability", 'p', "INT", 0, "Probability threshold (0-100) [analyze only]" },
	{ "algorithms", 'a', "STRING", 0, "Algorithms to use [process only]" },
	{ "depth", 'd', "INT", 0, "Depth of algorithm combinations [process only]" },
	{ "keys", 'k', "STRING", 0, "Keys or key file [process only]" },
	{ 0 }
};

// Struct to hold parsed options
struct arguments {
	char *subcommand;
	char *input;
	char *algorithms;
	int depth;
	char *keys;
	int probability_threshold;
};

// Parser function
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;

	switch (key) {
	case 't':
		if (strcasecmp(arg, "A") == 0)
			arguments->subcommand = "analyze";
		else if (strcasecmp(arg, "S") == 0)
			arguments->subcommand = "solve";
		else
			argp_error(state, "Unknown task type: %s", arg);
		break;
	case 'i':
		arguments->input = arg;
		break;
	case 'p':
		arguments->probability_threshold = atoi(arg);
		if (arguments->probability_threshold < 0 || arguments->probability_threshold > 100) {
			argp_error(state, "Probability threshold must be between 0 and 100.");
		}
		break;
	case 'a':
		arguments->algorithms = arg;
		break;
	case 'd':
		arguments->depth = atoi(arg);
		break;
	case 'k':
		arguments->keys = arg;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

void analyze(sds input, float probability_threshold) {
	printf("[INFO] Running analysis on input: \"%s\"\n", input);
	int found = 0;
	for (size_t i = 0; i < analyzers_count; ++i) {
		analyzer_t analyzer = analyzers[i];
		analysis_result_t result = analyzer.fn(input);
		if (result.probability >= probability_threshold) {
			printf("[%.0f%%]\t [%s] %s\n", result.probability * 100, analyzer.label, result.message);
			found++;
		}
	}
	if (!found) {
		printf("[INFO] No high-probability analysis results found.\n");
	}
}

void solve(sds input, const char *algorithms, int depth, keychain_t *keychain) {
	printf("[INFO] Running solving on input: \"%s\"\n", input);
	int found = 0;
	for (size_t i = 0; i < solvers_count; ++i) {
		solver_t solver = solvers[i];
		solver_result_t result = solver.fn(input, keychain);
		for (size_t j = 0; j < result.len; ++j) {
			printf("[%.0f%%]\t [%s] \"%s\" - Method: \"%s\"\n", result.outputs[j].fitness * 100, solver.label, result.outputs[j].data, result.outputs[j].method);
			found++;
		}
	}
	if (!found) {
		printf("[INFO] No high-probability solving results found.\n");
	}
}

int main(int argc, char *argv[]) {
	struct arguments args = {
		.subcommand = NULL,
		.input = NULL,
		.algorithms = "common",
		.depth = 1,
		.keys = "",
		.probability_threshold = (int)(PROBABILITY_THRESHOLD * 100)
	};

	struct argp argp = { options, parse_opt, args_doc, doc };
	argp_parse(&argp, argc, argv, 0, 0, &args);

	// Dispatch logic
	if (!args.input) {
		fprintf(stderr, "ERROR: Missing required input.\n");
		argp_help(&argp, stderr, ARGP_HELP_STD_ERR, argv[0]);
		return 1;
	}
	if (!args.subcommand) {
		fprintf(stderr, "ERROR: Missing required subcommand.\n");
		argp_help(&argp, stderr, ARGP_HELP_STD_ERR, argv[0]);
		return 1;
	}

	if (strcmp(args.subcommand, "analyze") == 0) {
		analyze(sdsnew(args.input), args.probability_threshold / 100.0f);
	} else if (strcmp(args.subcommand, "solve") == 0) {
		// split keys by | into array
		sds raw_keys = sdsnew(args.keys);
		int count = 0;
		sds *tokens = sdssplitlen(raw_keys, sdslen(raw_keys), "|", 1, &count);

		printf("[DEBUG] Processing input: %s\n", args.input);
		printf("[DEBUG] Algorithms: %s\n", args.algorithms);
		printf("[DEBUG] Depth: %d\n", args.depth);

		printf("[DEBUG] Keys: ");
		for (int i = 0; i < count; i++) {
			printf("%s / ", tokens[i]);
		}
		printf("\n");

		keychain_t keychain = {
			.len = count,
			.keys = tokens
		};
		
		solve(sdsnew(args.input), args.algorithms, args.depth, &keychain);
	}

	return 0;
}
