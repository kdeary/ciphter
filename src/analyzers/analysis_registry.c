#include <ctype.h>
#include <string.h>
#include "analysis_registry.h"
#include "../../lib/sds/sds.h"
#include "../fitness.h"

#define analysis_fn(fn_label) static analysis_result_t check_ ## fn_label (sds input)
#define ANALYZER(fn_label) { .label = #fn_label, .popularity = 0.5, .fn = check_ ## fn_label }

analysis_fn(HEX) {
	int len = sdslen(input);
	if (len % 2 != 0) {
		return (analysis_result_t){ .probability = 0.0, .message = "Invalid string length" };
	}

	size_t hex_count = 0;
	for (size_t i = 0; i < len; ++i) {
		if (isxdigit((unsigned char)input[i])) {
			hex_count++;
		}
	}

	float prob = (float)hex_count / (float)(len);
	const char *msg = "Possible hex encoding";
	return (analysis_result_t){ .probability = prob, .message = msg };
}

analysis_fn(ENGLISH) {
	int len = sdslen(input);
	float prob = score_english_detailed(input, len);
	const char *msg = "Possible English text";
	return (analysis_result_t){ .probability = prob, .message = msg };
}

analysis_fn(BASE64) {
	int len = sdslen(input);
	// Check if the string length is a multiple of 4
	if (len % 4 != 0) {
		return (analysis_result_t){ .probability = 0.0, .message = "Invalid string length" };
	}

	// Check for invalid characters
	for (size_t i = 0; i < len; ++i) {
		if (!isalnum((unsigned char)input[i]) && input[i] != '+' && input[i] != '/' && input[i] != '=') {
			return (analysis_result_t){ .probability = 0.0, .message = "Invalid character" };
		}
	}

	size_t base64ish = 0;
	for (size_t i = 0; i < len; ++i) {
		if (isalnum((unsigned char)input[i]) || input[i] == '+' || input[i] == '/' || input[i] == '=') {
			base64ish++;
		}
	}

	float prob = (float)base64ish / (float)(len);
	const char *msg = "Possible Base64 encoding";
	return (analysis_result_t){ .probability = prob, .message = msg };
}

analysis_fn(SHA256) {
	int len = sdslen(input);
	if (len != 64) {
		return (analysis_result_t){ .probability = 0.0, .message = "Invalid length" };
	}

	size_t hex_count = 0;
	for (size_t i = 0; i < len; ++i) {
		if (isxdigit((unsigned char)input[i])) {
			hex_count++;
		}
	}

	float prob = (float)hex_count / (float)(len);
	const char *msg = "Possible SHA-256 hash";
	return (analysis_result_t){ .probability = prob, .message = msg };
}

analysis_fn(MD5) {
	int len = sdslen(input);
	if (len != 32) {
		return (analysis_result_t){ .probability = 0.0, .message = "Invalid length" };
	}

	size_t hex_count = 0;
	for (size_t i = 0; i < len; ++i) {
		if (isxdigit((unsigned char)input[i])) {
			hex_count++;
		}
	}

	float prob = (float)hex_count / (float)(len);
	const char *msg = "Possible MD5 hash";
	return (analysis_result_t){ .probability = prob, .message = msg };
}

// Ordered by popularity/commonness
analyzer_t analyzers[] = {
	ANALYZER(ENGLISH),
	ANALYZER(HEX),
	ANALYZER(BASE64),
	ANALYZER(SHA256),
	ANALYZER(MD5),
};

size_t analyzers_count = sizeof(analyzers) / sizeof(analyzer_t);
