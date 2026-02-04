#ifndef ENGLISH_DETECTOR_H
#define ENGLISH_DETECTOR_H

#include <stddef.h>

// Score text based on English bigram frequency. Higher is better.
float score_english_bigram(const char *text, size_t len);

// Score text based on correct casing (capitalization). Higher is better.
float score_english_casing(const char *text, size_t len);

// Combined score using all available metrics. Higher is better.
float score_english_combined(const char *text, size_t len);

#endif // ENGLISH_DETECTOR_H
