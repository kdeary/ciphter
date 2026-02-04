#ifndef ENGLISH_DETECTOR_H
#define ENGLISH_DETECTOR_H

#include <stddef.h>

// Score text based on English bigram frequency. Higher is better.
extern float score_english_bigram(const char *text, size_t len);

// Score text based on correct casing (capitalization). Higher is better.
extern float score_english_casing(const char *text, size_t len);

// Detailed English score (bigrams, casing, freq, etc.) for filtering output
extern float score_english_detailed(const char *text, size_t len);

// Combined fitness score for solver pathfinding (Printability only)
extern float score_combined(const char *text, size_t len);

extern float score_base64_like(const char *text, size_t len);

#endif // ENGLISH_DETECTOR_H
