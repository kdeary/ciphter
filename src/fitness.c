#include "fitness.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <math.h>

// Top 100 English Bigrams
// Source: http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
static const char *COMMON_BIGRAMS[] = {
	"TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
	"TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
	"ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE",
	"VE", "CO", "ME", "DE", "HI", "RI", "RO", "IC", "NE", "EA",
	"RA", "CE", "LI", "CH", "LL", "BE", "MA", "SI", "OM", "UR",
	"CA", "EL", "TA", "LA", "NS", "DI", "FO", "HO", "PE", "EC",
	"PR", "NO", "CT", "US", "OT", "IL", "TR", "NC", "AC", "RS",
	"LO", "AI", "LY", "IE", "GE", "UT", "SO", "RT", "WI", "UN",
	"EM", "WH", "AD", "OL", "PO", "WE", "UL", "ID", "EE", "EY",
	"SS", "OO", "FF", "OW", "LS", "EI", "RN", "AB", "PL", "TT",
	"EW", "IF", "EX", "SP", "UA", "MY", "IV", "DA", "CK", "FT",
	"GH", "KE", "RM", "SW", "SU", "EP", "CI", "BL", "RY", "EF",
	"OP", "SH", "UP", "IP", "IM", "GR", "TY", "NK", "OY", "AY",
	"PT", "DR", "AM", "OS", "AP", "AG", "OD", "AV", "IB", "KN"
};
#define NUM_BIGRAMS (sizeof(COMMON_BIGRAMS) / sizeof(char*))

static int is_bigram_match(const char *b1, const char *b2) {
	for (int i = 0; i < 2; i++) {
		if (toupper((unsigned char)b1[i]) != b2[i]) return 0;
	}
	return 1;
}

float score_english_bigram(const char *text, size_t len) {
	if (len < 2) return 0.0f;

	int match_count = 0;
	int total_bigrams = len - 1;

	for (int i = 0; i < total_bigrams; i++) {
		// Check if the current bigram in text matches any of the common ones
		for (int j = 0; j < NUM_BIGRAMS; j++) {
			if (is_bigram_match(&text[i], COMMON_BIGRAMS[j])) {
				match_count++;
				break; // Found a match
			}
		}
	}

	float density = (float)match_count / total_bigrams;
	
	// Logic: In proper English, common bigrams make up a HUGE portion of text.
	// If we are seeing less than 30% common bigrams from top 88 list, it's widely likely not English
	// or very strange English.
	// Random text will have (1/26 * 1/26) probability for specific bigram roughly.
	// With 140 bigrams, random text chance is 140/676 ~= 20%.
	// English text usually is > 50-60%.
	
	// We want to penalize anything close to random (20%).
	// Use 0.28 as cut-off.
	
	float score = 0.0f;
	if (density < 0.28f) {
		score = 0.0f; // Strongly penalize
	} else {
		// Map 0.28 -> 0.55 to 0.0 -> 1.0
		score = (density - 0.28f) / (0.55f - 0.28f);
		if (score > 1.0f) score = 1.0f;
	}
	
	return score;
}

float score_english_casing(const char *text, size_t len) {
	if (len == 0) return 0.0f;

	int total_chars = 0;
	int upper_count = 0;
	int sentence_start_checks = 0;
	int sentence_start_hits = 0;
	
	int expect_capital = 1; // Expect start of string to be capital

	for (size_t i = 0; i < len; i++) {
		char c = text[i];
		if (isalpha((unsigned char)c)) {
			total_chars++;
			if (isupper((unsigned char)c)) {
				upper_count++;
				if (expect_capital) {
					sentence_start_hits++;
				}
			}
			if (expect_capital) {
				 sentence_start_checks++;
				 expect_capital = 0; 
			}
		}

		// Reset expectation after sentence terminators
		if (c == '.' || c == '!' || c == '?') {
			// Check ahead for next alpha char
			expect_capital = 1;
		}
	}

	if (total_chars == 0) return 0.0f;

	float casing_ratio = (float)upper_count / total_chars;
	
	float casing_score = 0.0f;
	
	// Stricter casing rules, but relaxed for short strings (e.g. names)
	float max_ratio = (len < 25) ? 0.40f : 0.20f;
	
	if (casing_ratio > 0.01f && casing_ratio < max_ratio) {
		casing_score = 1.0f;
	} else if (casing_ratio == 0.0f) {
		casing_score = 0.2f; // Punish all lowercase more
	} else {
		// If it's short, don't zero it out completely, just penalize
		if (len < 25 && casing_ratio < 0.60f) {
			 casing_score = 0.5f;
		} else {
			 casing_score = 0.0f; // Punish all caps or random caps heavily
		}
	}

	float sentence_score = 0.0f;
	if (sentence_start_checks > 0) {
		sentence_score = (float)sentence_start_hits / sentence_start_checks;
	} else {
		sentence_score = 0.5f; 
	}

	// Heavier weight on casing ratio than sentence start
	return (casing_score * 0.6f) + (sentence_score * 0.4f);
}

// Scoring Constants
#define BIGRAM_CUTOFF 0.28f
#define BIGRAM_RANGE (0.55f - 0.28f)

#define CASING_MAX_RATIO_SHORT 0.40f
#define CASING_MAX_RATIO_LONG 0.20f
#define CASING_PENALTY_LOWERCASE 0.2f
#define CASING_PENALTY_SHORT_NON_IDEAL 0.5f

#define SENTENCE_WEIGHT 0.4f
#define CASING_WEIGHT 0.6f

static const float ENGLISH_FREQ[26] = {
	0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
	0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 
	0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 
	0.01974, 0.00074 
};

static float score_letter_frequency(const char *text, size_t len) {
	int counts[26] = {0};
	int total = 0;
	for(size_t i=0; i<len; i++) {
		if(isalpha((unsigned char)text[i])) {
			counts[tolower((unsigned char)text[i]) - 'a']++;
			total++;
		}
	}
	if(total == 0) return 0.0f;
	
	float chi_sq = 0.0f;
	for(int i=0; i<26; i++) {
		float expected = ENGLISH_FREQ[i] * total;
		float diff = counts[i] - expected;
		chi_sq += (diff * diff) / (expected + 0.0001f);
	}
	
	// Stricter frequency curve
	return 50.0f / (50.0f + chi_sq);
}

// Uses weights defined in utils.h
float score_english_detailed(const char *text, size_t len) {
	float s_bigram = score_english_bigram(text, len);
	float s_casing = score_english_casing(text, len);
	float s_freq = score_letter_frequency(text, len);

	return (s_freq * WEIGHT_FREQ) + (s_bigram * WEIGHT_BIGRAM) + (s_casing * WEIGHT_CASING);
}

// Shannon Entropy Calculation
float score_shannon_entropy(const char *text, size_t len) {
    if (len == 0) return 0.0f;

    int counts[256] = {0};
    for (size_t i = 0; i < len; ++i) {
        counts[(unsigned char)text[i]]++;
    }

    float entropy = 0.0f;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            float p = (float)counts[i] / len;
            entropy -= p * log2f(p);
        }
    }

    // Normalize entropy (0-8) to 0.0-1.0 range (higher is better structure)
    // 8.0 is max entropy (random bytes), 0.0 is min entropy (single repeated char)
    return entropy;
}

float score_combined(const char *text, size_t len, int force_shannon) {
	if (len == 0) return 0.0f;
	
	int non_printable = 0;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)text[i];
		// Check for printable (including standard whitespace)
		if (!isprint(c) && c != '\n' && c != '\r' && c != '\t') {
			non_printable = 1;
			break;
		}
	}

	// Formula: (1/2)^N
	if (!force_shannon && non_printable == 0) {
		return 1.0f;
	}

	float ent = score_shannon_entropy(text, len);
	float ent_score = (8.0f - ent) / 8.0f;
	if (ent_score < 0) ent_score = 0;
	return ent_score;
}