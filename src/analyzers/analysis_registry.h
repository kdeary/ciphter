#ifndef ANALYSIS_REGISTRY_H
#define ANALYSIS_REGISTRY_H

#include "../../lib/sds/sds.h"

typedef struct {
	float probability;
	const char *message;
} analysis_result_t;

typedef struct {
	const char *label;

	// 1 = popular, 0.75 = common, 0.5 = uncommon, 0.25 = rare, 0 = special
	float popularity;
	
	analysis_result_t (*fn)(sds input);
} analyzer_t;

extern analyzer_t analyzers[];
extern size_t analyzers_count;

#endif // ANALYSIS_REGISTRY_H
