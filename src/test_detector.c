#include <stdio.h>
#include <string.h>
#include "english_detector.h"

void check(const char *name, const char *text, float expected_min, float expected_max) {
    float score = score_english_combined(text, strlen(text));
    printf("[%s] Score: %.4f ", name, score);
    if (score >= expected_min && score <= expected_max) {
        printf("PASS\n");
    } else {
        printf("FAIL (Expected %.2f-%.2f)\n", expected_min, expected_max);
    }
}

int main() {
    printf("Testing English Detector (Bigram & Strict Mode)...\n");

    const char *english_text = "The quick brown fox jumps over the lazy dog. This is a simple sentence to test the detector.";
    check("Good English", english_text, 0.6f, 1.0f);

    const char *random_text = "akjsdhf kajshdf kjh sdfkjah sdlkfh alsdfjkh asldkfj hasldkf jhalskdfj h";
    // Should be strictly punished now, likely 0.0 or very close
    check("Random Text", random_text, 0.0f, 0.1f);
    
    // Low bigram count text
    const char *garbage_text = "!!!!!! @@@@@ #### $$$$$ %%%%%";
    check("Garbage Text", garbage_text, 0.0f, 0.1f);
    
    const char *semi_random = "ThIs Is NoT vErY gOoD eNgLiSh BuT rEaDaBlE";
    // Check if casing penalty works but bigrams save it slightly -> actually with strict casing this might be low
    // Bigrams are: TH IS IS NO OT VE ER RY GO OO OD ...
    // Most are valid bigrams. Casing is 50% mixed, which is bad.
    check("Weird Casing", semi_random, 0.2f, 0.9f);

    // Test bigram heavy 
    const char *bigrams = "THE AND ING ENT ION HER FOR THA";
    check("Bigram List", bigrams, 0.5f, 1.0f);

    // Punish test: text with valid letters but nonsense/rare bigrams
    // "qzx jq kz xv qj zx"
    const char *rare_bigrams = "qzxjq kz xv qj zx";
    check("Rare Bigrams", rare_bigrams, 0.0f, 0.15f);

    // Regression test for user report
    const char *base64_fp = "YXNobGV5IExFRQ==";
    check("Base64 FP", base64_fp, 0.0f, 0.1f);

    const char *short_text = "ashley LEE";
    check("Short Text", short_text, 0.7f, 1.0f);

    return 0;
}
