#include "ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #define PLATFORM_WINDOWS 1
#else
    #include <sys/time.h>
    #include <termios.h>
    #include <unistd.h>
    #include <fcntl.h>
    #define PLATFORM_POSIX 1
#endif

#define TOP_N 5

typedef struct {
    float fitness;
    float cumulative_fitness;
    sds data;
    sds method;
    int depth;
    int active; // 1 if this slot is populated
} top5_entry_t;

static top5_entry_t top5[TOP_N];
static int ui_silent_mode = 0;
static int view_visible = 0; // Has the view been printed at least once?

#ifdef PLATFORM_POSIX
static void set_nonblock(int state);
#endif

void ui_init(int silent_mode) {
    ui_silent_mode = silent_mode;
    view_visible = 0;
    for (int i = 0; i < TOP_N; i++) {
        top5[i].active = 0;
        top5[i].data = NULL;
        top5[i].method = NULL;
    }
    
    // Setup terminal if not silent
    if (!silent_mode) {
        #ifdef PLATFORM_POSIX
        set_nonblock(1);
        #endif
        // Windows console usually is in the right mode, but we might want to ensure processed input?
        // Default is fine for PeekConsoleInput.
    }
}

// Helper to clear the lines consumed by the live view
static void clear_view() {
    if (!view_visible || ui_silent_mode) return;
    
    // Move up TOP_N lines
    printf("\033[%dA", TOP_N);
    // Clear each line
    for (int i = 0; i < TOP_N; i++) {
        printf("\033[K\n");
    }
    // Move up TOP_N lines again to be back at the start
    printf("\033[%dA", TOP_N);
}

static void print_view() {
    if (ui_silent_mode) return;

    // Print the top 5
    // If fewer than 5, print empty lines to maintain height
    for (int i = 0; i < TOP_N; i++) {
        if (top5[i].active) {
            printf("\033[36m[%d]\033[0m \033[32m[%.0f%%]\033[0m \033[33m[Agg:%.2f]\033[0m \"%.20s\" \033[90m(%s)\033[0m\n", 
                top5[i].depth, 
                top5[i].fitness * 100, 
                top5[i].cumulative_fitness, 
                top5[i].data, 
                top5[i].method);
        } else {
            printf("\033[K\n"); // Empty line (cleared)
        }
    }
    view_visible = 1;
}

void ui_update_top5(float fitness, float cumulative_fitness, const char *data, const char *method, int depth) {
    if (ui_silent_mode) return;

    // Check if this specific data is already in the list
    int existing_idx = -1;
    for (int i = 0; i < TOP_N; i++) {
        if (top5[i].active && strcmp(top5[i].data, data) == 0) {
            existing_idx = i;
            break;
        }
    }

    if (existing_idx != -1) {
        // If new version is better (higher cumulative fitness), update it.
        if (cumulative_fitness > top5[existing_idx].cumulative_fitness) {
            top5[existing_idx].fitness = fitness;
            top5[existing_idx].cumulative_fitness = cumulative_fitness;
            top5[existing_idx].depth = depth;
            sdsfree(top5[existing_idx].method);
            top5[existing_idx].method = sdsnew(method);
        } else {
            return; 
        }
    } else {
        int worst_idx = -1;
        float min_fit = 1000000.0f;
        int count = 0;
        
        for (int i = 0; i < TOP_N; i++) {
            if (!top5[i].active) {
                worst_idx = i;
                min_fit = -1.0f; // Any real fitness will beat this
                break;
            }
            count++;
            if (top5[i].cumulative_fitness < min_fit) {
                min_fit = top5[i].cumulative_fitness;
                worst_idx = i;
            }
        }

        if (count < TOP_N) {
            // Found empty slot
        } else {
            // Full. Compare with worst cumulative fitness
            if (cumulative_fitness <= min_fit) {
                return;
            }
        }
        
        if (top5[worst_idx].active) {
            sdsfree(top5[worst_idx].data);
            sdsfree(top5[worst_idx].method);
        }
        
        top5[worst_idx].active = 1;
        top5[worst_idx].fitness = fitness;
        top5[worst_idx].cumulative_fitness = cumulative_fitness;
        top5[worst_idx].depth = depth;
        top5[worst_idx].data = sdsnew(data);
        top5[worst_idx].method = sdsnew(method);
    }
    
    // Bubble sort by cumulative_fitness
    for (int i = 0; i < TOP_N - 1; i++) {
        for (int j = 0; j < TOP_N - i - 1; j++) {
            int swap = 0;
            if (top5[j+1].active && !top5[j].active) swap = 1;
            else if (top5[j+1].active && top5[j].active && top5[j+1].cumulative_fitness > top5[j].cumulative_fitness) swap = 1;
            
            if (swap) {
                top5_entry_t temp = top5[j];
                top5[j] = top5[j+1];
                top5[j+1] = temp;
            }
        }
    }
}

// --- Platform Specific Input ---

#ifdef PLATFORM_WINDOWS

static int win_key_pressed = 0;

static int kbhit_windows() {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    INPUT_RECORD irInputRecord;
    DWORD dwEventsRead;
    
    // Peek events
    DWORD evtCount = 0;
    GetNumberOfConsoleInputEvents(hStdin, &evtCount);
    if (evtCount == 0) return 0;
    
    // Look for KeyDown events
    INPUT_RECORD *buffer = malloc(sizeof(INPUT_RECORD) * evtCount);
    DWORD read = 0;
    PeekConsoleInput(hStdin, buffer, evtCount, &read);
    
    int hasKey = 0;
    for (DWORD i = 0; i < read; i++) {
        if (buffer[i].EventType == KEY_EVENT && buffer[i].Event.KeyEvent.bKeyDown) {
            // Check if it's a real char (SPACE)
            if (buffer[i].Event.KeyEvent.uChar.AsciiChar == ' ') {
                 hasKey = 1;
                 break;
            }
        }
    }
    free(buffer);
    return hasKey;
}

static void flush_windows_input() {
    // Consume the input so we don't spam
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    INPUT_RECORD irInputRecord;
    DWORD dwEventsRead;
    
    // Read and discard strictly the Keys we care about? 
    // Or just FlushConsoleInputBuffer? 
    // Flush is dangerous if user typed ahead.
    // Ideally we just read one event.
    // Since we check for ANY space, let's just ReadConsoleInput to consume whatever head is.
    ReadConsoleInput(hStdin, &irInputRecord, 1, &dwEventsRead);
}

#else

static int kbhit_posix() {
    struct timeval tv;
    fd_set fds;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
    return FD_ISSET(STDIN_FILENO, &fds);
}

static int getch_posix() {
    int r;
    unsigned char c;
    if ((r = read(STDIN_FILENO, &c, sizeof(c))) < 0) {
        return 0;
    } else {
        return c;
    }
}

static void set_nonblock(int state) {
    struct termios ttystate;
    tcgetattr(STDIN_FILENO, &ttystate);

    if (state) {
        ttystate.c_lflag &= ~(ICANON | ECHO);
        ttystate.c_cc[VMIN] = 1;
    } else {
        ttystate.c_lflag |= (ICANON | ECHO);
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &ttystate);
}

#endif


void ui_check_input() {
    if (ui_silent_mode) return;
    
#ifdef PLATFORM_WINDOWS
    if (kbhit_windows()) {
        // flush one event/key
        flush_windows_input();
        
        // Action
        if (view_visible) {
             clear_view();
        }
        print_view();
    }
#else
    if (kbhit_posix()) {
        int ch = getch_posix(); 
        if (ch == ' ') {
            if (view_visible) {
                 clear_view();
            }
            print_view();
        }
    }
#endif
}

void ui_log(const char *fmt, ...) {
    va_list args;
    
    if (view_visible) {
        clear_view();
    }
    
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    
    print_view();
}

void ui_cleanup() {
#ifdef PLATFORM_POSIX
    set_nonblock(0);
#endif

    for (int i = 0; i < TOP_N; i++) {
        if (top5[i].active) {
            sdsfree(top5[i].data);
            sdsfree(top5[i].method);
        }
    }
}
