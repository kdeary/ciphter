#ifndef UI_H
#define UI_H

#include "../lib/sds/sds.h"

// Initialize the UI module.
// silent_mode: 1 to disable the Top 5 view entirely (useful for scripts/pipes).
void ui_init(int silent_mode);

// Submit a new path to the Top 5 tracker.
// The UI module tracks the top 5 distinct paths with highest fitness.
void ui_update_top5(float fitness, float cumulative_fitness, const char *data, const char *method, int depth);

// Check for user input (non-blocking).
// Specifically listens for SPACE bar to update the view.
void ui_check_input();

// Replacement for printf to handle log/view coexistence.
// Clears the view if active, prints the log, and schedules a view repaint.
void ui_log(const char *fmt, ...);

// Cleanup resources.
void ui_cleanup();

#endif // UI_H
