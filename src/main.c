#include <argp.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "../lib/minheap/heap.h"
#include "../lib/sds/sds.h"

#include "analyzers/analysis_registry.h"
#include "solvers/solver_registry.h"
#include "utils.h"
#include "english_detector.h"

#define PROBABILITY_THRESHOLD 0.01f

const char * argp_program_version = "ciphter v0.1";
const char * argp_program_bug_address = "<korbin.deary45@gmail.com>";
static char doc[] = "ciphter - cryptography analysis and processing tool";
static char args_doc[] = "";

// Program options
static struct argp_option options[] = {
    {
        "task", 't', "TYPE", 0, "Task type: A for analyze, S for solve"
    },
    {
        "input", 'i', "STRING", 0, "Inline ciphertext input"
    },
    {
        "input-file", 'I', "FILE", 0, "Ciphertext input from file"
    },
    {
        "probability", 'p', "INT", 0, "Probability/Fitness threshold (0-100)"
    },
    {
        "english", 'E', "INT", 0, "English quality threshold (0-100) for output filtering"
    },
    {
        "monitor", 'm', "STRING", 0, "Monitor specific path substring (debug logging)"
    },
    {
        "algorithms", 'a', "STRING", 0, "Algorithms to use [process only] (default: common)"
    },
    {
        "depth", 'd', "INT", 0, "Depth of algorithm combinations [process only] (default: 1)"
    },
    {
        "keys", 'k', "STRING", 0, "Keys (raw)"
    },
    {
        "keyfile", 'K', "FILE", 0, "Key file"
    },
    {
        "crib", 'c', "STRING", 0, "Known string to search for (filters output)"
    },
    {
        "output", 'O', "FILE", 0, "Output file to dump results"
    },
    {
        "silent", 's', 0, 0, "Silent mode (hide top 5 view)"
    },
    {
        "timeout", 'T', "INT", 0, "Timeout in seconds for solving (default: 10)"
    },
    {
        "verbose", 'v', 0, 0, "Produce verbose output"
    },
    {
        "heap-size", 'H', "INT", 0, "Max heap size for solving"
    },
    {0}
};

// Struct to hold parsed options
struct arguments {
    char * subcommand;
    sds input;
    char * algorithms;
    int depth;
    sds keys;
    char * crib;
    int probability_threshold;
    int english_threshold; // -1 if disabled
    char * monitor_path; // NULL if disabled
    char * output_file;
    int p_set;
    int silent;
    int timeout;
    int max_heap_size;
};

// Parser function
static error_t parse_opt(int key, char * arg, struct argp_state * state) {
    struct arguments * arguments = state -> input;

    switch (key) {
    case 't':
        if (strcasecmp(arg, "A") == 0)
            arguments -> subcommand = "analyze";
        else if (strcasecmp(arg, "S") == 0)
            arguments -> subcommand = "solve";
        else
            argp_error(state, "Unknown task type: %s", arg);
        break;
    case 'i':
        if (arguments -> input) sdsfree(arguments -> input);
        arguments -> input = sdsnew(arg);
        break;
    case 'I': {
        FILE * f = fopen(arg, "r");
        if (f) {
            if (arguments -> input) sdsfree(arguments -> input);
            arguments -> input = sdsempty();
            char buf[4096];
            size_t nread;
            while ((nread = fread(buf, 1, sizeof(buf), f)) > 0) {
                arguments -> input = sdscatlen(arguments -> input, buf, nread);
            }
            fclose(f);
            sdstrim(arguments -> input, " \r\n\t");
        } else {
            argp_error(state, "Could not open input file: %s", arg);
        }
        break;
    }
    case 'p':
        arguments -> p_set = 1;
        arguments -> probability_threshold = atoi(arg);
        if (arguments -> probability_threshold < 0 || arguments -> probability_threshold > 100) {
            argp_error(state, "Probability threshold must be between 0 and 100.");
        }
        break;
    case 'E':
        arguments -> english_threshold = atoi(arg);
        if (arguments -> english_threshold < 0 || arguments -> english_threshold > 100) {
            argp_error(state, "English threshold must be between 0 and 100.");
        }
        break;
    case 'm':
        arguments -> monitor_path = arg;
        break;
    case 'a':
        arguments -> algorithms = arg;
        break;
    case 'd':
        arguments -> depth = atoi(arg);
        break;
    case 'k':
        arguments -> keys = sdscat(arguments -> keys, arg);
        arguments -> keys = sdscat(arguments -> keys, "|");
        break;
    case 'K': {
        FILE * f = fopen(arg, "r");
        if (f) {
            char line[1024];
            while (fgets(line, sizeof(line), f)) {
                line[strcspn(line, "\r\n")] = 0; // Strip newline
                if (strlen(line) > 0) {
                    arguments -> keys = sdscat(arguments -> keys, line);
                    arguments -> keys = sdscat(arguments -> keys, "|");
                }
            }
            fclose(f);
        } else {
            argp_error(state, "Could not open key file: %s", arg);
        }
        break;
    }
    case 'c':
        arguments -> crib = arg;
        break;
    case 'O':
        arguments -> output_file = arg;
        break;
    case 's':
        arguments -> silent = 1;
        break;
    case 'T':
        arguments -> timeout = atoi(arg);
        if (arguments -> timeout < 0) {
            argp_error(state, "Timeout must be a non-negative integer.");
        }
        break;
    case 'v':
        verbose_flag = 1;
        break;
    case 'H':
        arguments -> max_heap_size = atoi(arg);
        if (arguments -> max_heap_size <= 0) {
            argp_error(state, "Heap size must be a positive integer.");
        }
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
        if (result.probability < probability_threshold) continue;
        printf("[%.0f%%]\t [%s] %s\n", result.probability * 100, analyzer.label, result.message);
        found++;
    }
    if (!found) {
        printf("[INFO] No high-probability analysis results found.\n");
    }
    sdsfree(input);
}

static void ui_log_result(FILE *f_out, int p_set, int depth, float fitness, float cumulative_fitness, 
                         const char *label, const char *data, const char *method, 
                         int english_threshold, float eng_score, int force_stdout) {
    char truncated_data[65]; // 61 + "..." + null terminator
    const char *display_data = data;
    
    if (strlen(data) > 61) {
        strncpy(truncated_data, data, 58);
        truncated_data[58] = '\0';
        strcat(truncated_data, "...");
        display_data = truncated_data;
    }

    const char *fmt = "[%d][%.0f%%][Agg:%.2f]\t [%s] \"%s\" - Method: \"%s\"\n";
    
    if (f_out) {
        fprintf(f_out, fmt, depth, fitness * 100, cumulative_fitness, label, display_data, method);
        if (english_threshold >= 0.0f) {
            fprintf(f_out, "\t [ENG: %.2f%%]\n", eng_score * 100);
        }
    }
    
    if (force_stdout || p_set || english_threshold >= 0.0f) {
        printf(fmt, depth, fitness * 100, cumulative_fitness, label, display_data, method);
        if (english_threshold >= 0.0f) {
            printf("\t [ENG: %.2f%%]\n", eng_score * 100);
        }
    }
}

static int prune_compare_wrapper(const void * a, const void * b) {
    const heap_entry * ea = a;
    const heap_entry * eb = b;
    return output_compare_fn(ea -> key, eb -> key);
}

void prune_heap(heap * h, int max_size) {
    if (h -> active_entries <= max_size) return;

    // Sort the entire table
    // Since output_compare_fn returns -1 for "better", qsort will put better items at the start
    qsort(h -> table, h -> active_entries, sizeof(heap_entry), prune_compare_wrapper);

    // Free the entries we are pruning
    for (int i = max_size; i < h -> active_entries; i++) {
        free_heap_output(h -> table[i].key, h -> table[i].value);
    }

    h -> active_entries = max_size;
}

void solve(sds input, float fitness_threshold,
    const char * algorithms, int depth, keychain_t * keychain,
    const char * crib, float english_threshold,
    const char * monitor_path, char * output_file, int p_set, int silent, int timeout, int max_heap_size) {
    sds displayed_input = sdsdup(input);
    if (sdslen(displayed_input) > 61) {
        sdsrange(displayed_input, 0, 57);
        displayed_input = sdscat(displayed_input, "...");
    }
    printf("[INFO] Running solving on input: \"%s\" (Timeout: %ds)\n", displayed_input, timeout);
    sdsfree(displayed_input);
    int found = 0;

    time_t start_time = time(NULL);

    FILE * f_out = NULL;
    if (output_file) {
        f_out = fopen(output_file, "w");
        if (!f_out) {
            printf("[ERROR] Could not open output file: %s\n", output_file);
        }
    }

    // Parse algorithm string or use default
    size_t solvers_count = 0;
    solver_t * solvers = get_solvers(algorithms, & solvers_count);

    printf("[INFO] Loaded %zu algorithms: ", solvers_count);
    for (size_t i = 0; i < solvers_count; ++i) {
        printf("%s", solvers[i].label);
        if (i < solvers_count - 1) printf(", ");
    }
    printf("\n");

    int lines_printed = 0;

    solver_output_t input_res = {
        .fitness = 1,
        .cumulative_fitness = 1, // Start with base fitness
        .method = sdsnew("CIPHERTEXT"),
        .data = sdsdup(input),
        .depth = 0,
        .last_solver = NULL
    };

    int is_eng_set = english_threshold >= 0.0f;

    heap path_heap = {
        0
    };

    heap_create( & path_heap, 0, * output_compare_fn);
    heap_insert( & path_heap, & input_res, & input_res);

    solver_output_t best_res = {
        .fitness = input_res.fitness,
        .cumulative_fitness = input_res.cumulative_fitness,
        .method = sdsdup(input_res.method),
        .data = sdsdup(input_res.data),
        .depth = input_res.depth,
        .last_solver = input_res.last_solver
    };

    printf("[INFO] Running solvers...\n");

    while (heap_size( & path_heap) > 0) {
        // Check timeout
        if (timeout > 0 && difftime(time(NULL), start_time) >= timeout) {
            printf("[INFO] Timeout reached (%ds). Stopping...\n", timeout);
            break;
        }
        // CRITICAL: Do NOT malloc here. heap_min retrieves a pointer already stored in the heap.
        // If we malloc, we leak that memory immediately when current is overwritten by heap_min.
        solver_output_t * current = NULL; 
        int status = heap_min( & path_heap, (void ** )( & current), (void ** )( & current));
        heap_delmin( & path_heap, (void ** )( & current), (void ** )( & current));


        if (status == 0) {
            // No need to free current here as it was never allocated in this scope
            break;
        }

        // Monitor logs
        if (monitor_path && strstr(current -> method, monitor_path) != NULL) {
            printf("[MONITOR] [%d]\t [Agg:%.2f] [Fit:%.2f] \"%s\" - Method: \"%s\"\n",
                current -> depth,
                current -> cumulative_fitness,
                current -> fitness,
                current -> data,
                current -> method);
        }

        float eng_score = 0.0f;
        if (english_threshold >= 0.0f) {
            eng_score = score_english_detailed(current -> data, sdslen(current -> data));
        }

        int p_set_flag = p_set && current -> fitness > fitness_threshold;
        int eng_flag = is_eng_set && eng_score > english_threshold;

        if (p_set_flag || eng_flag) {
            ui_log_result(f_out, p_set, current -> depth, current -> fitness, current -> cumulative_fitness,
                         "OUTPUT", current -> data, current -> method, english_threshold, eng_score, 0);
        }

        if (crib && strstr(current -> data, crib) != NULL) {
            current -> fitness += 2.0f;
            current -> cumulative_fitness += 9999.0f;
        }

        // Track best result

        if(is_eng_set) {
            if (eng_score + 1 > best_res.cumulative_fitness) {
                free_output( & best_res);
                best_res.fitness = current -> fitness;
                best_res.cumulative_fitness = eng_score + 1;
                best_res.method = sdsdup(current -> method);
                best_res.data = sdsdup(current -> data);
                best_res.depth = current -> depth;
                best_res.last_solver = current -> last_solver;
            }
        } else if (current -> cumulative_fitness > best_res.cumulative_fitness) {
            free_output( & best_res);
            best_res.fitness = current -> fitness;
            best_res.cumulative_fitness = current -> cumulative_fitness;
            best_res.method = sdsdup(current -> method);
            best_res.data = sdsdup(current -> data);
            best_res.depth = current -> depth;
            best_res.last_solver = current -> last_solver;
        }

        // Prioritize crib matches
        if (crib && strstr(current -> data, crib) != NULL) {
            // Always print crib found
            // Handled by ui_log which handles the view clearing so we don't need manual line clearing logic here anymore
            
            ui_log_result(f_out, p_set, current -> depth, current -> fitness, current -> cumulative_fitness,
                         "CRIB FOUND", current -> data, current -> method, -1, 0, 1);
            
            free_output(current);
            continue; // Stop recursion
        }

        if (current -> depth >= depth) {
            free_output(current);
            continue;
        }

        if (max_heap_size > 0) {
            if(heap_size(&path_heap) > max_heap_size) {
                // debug_log("Pruning heap from %zu to %d\n", heap_size( & path_heap), max_heap_size);
                prune_heap(&path_heap, max_heap_size);
            }
        }

        for (size_t i = 0; i < solvers_count; ++i) {
            solver_t solver = solvers[i];

            if (current -> last_solver && strcmp(current -> last_solver, solver.label) == 0 && solver.prevent_consecutive) {
                continue;
            }

            // printf("[SOLVER] test: %s\n", solver.label);

            solver_result_t result = solver.fn(current -> data, keychain);

            for (size_t j = 0; j < result.len; ++j) {
                if (strcmp(current -> data, result.outputs[j].data) == 0) {
                    continue;
                }

                solver_output_t * saved_output = malloc(sizeof(solver_output_t));
                saved_output -> fitness = result.outputs[j].fitness;
                saved_output -> cumulative_fitness = current -> cumulative_fitness + result.outputs[j].fitness;

                // Prioritize crib matches immediately
                if (crib && strstr(result.outputs[j].data, crib) != NULL) {
                    saved_output -> fitness = 1.0f; // Max priority
                    saved_output -> cumulative_fitness += 1.0f; // Also boost accumulator
                }

                saved_output -> method = sdscatprintf(sdsempty(), "%s -> %s", current -> method, result.outputs[j].method);
                saved_output -> data = sdsdup(result.outputs[j].data);
                saved_output -> depth = current -> depth + 1;
                saved_output -> last_solver = solver.label;

                // if(
                //     strstr(saved_output -> method, "AFFINE") != NULL && strstr(saved_output -> method, "CIPHERTEXT -> BINARY -> MORSE -> RAILFENCE (k=3, o=0) -> HEX -> BASE64") != NULL) {
                //     printf("[DEBUG] [%d]\t [Agg:%.2f] [Fit:%.2f] '%s' (%s) [%s]\n",
                //         saved_output -> depth,
                //         saved_output -> cumulative_fitness,
                //         saved_output -> fitness,
                //         saved_output -> data,
                //         saved_output -> method,
                //         saved_output -> last_solver
                //     );
                // }

                heap_insert( & path_heap, saved_output, saved_output);
            }
            
            // CLEANUP: Free the result structure and its contents
            for(size_t j=0; j<result.len; j++) {
                sdsfree(result.outputs[j].data);
                sdsfree(result.outputs[j].method);
            }
            if (result.outputs) free(result.outputs);
        }
        found++;
        if (current != &input_res) {
            free_output(current);
            free(current);
        }

        if (max_heap_size > 0) {
            if(heap_size(&path_heap) > max_heap_size) {
                // debug_log("Pruning heap from %zu to %d\n", heap_size( & path_heap), max_heap_size);
                prune_heap(&path_heap, max_heap_size);
            }
        }
    } // End of while loop

    heap_foreach(&path_heap, free_heap_output);
    heap_destroy( & path_heap);
    
    free_output(&input_res);

    if (f_out) fclose(f_out);

    if (!found) {
        printf("[INFO] No high-probability solving results found.\n");
    }
    
    // Always print the best result found so far
    printf("\n--- Best Result (Agg:%.2f) IS_ENGLISH_MODE=%d ---\n", best_res.cumulative_fitness, is_eng_set);
    printf("[%d][%.0f%%]\t \"%s\"\nMethod: \"%s\"\n",
        best_res.depth, best_res.fitness * 100, best_res.data, best_res.method);
    printf("----------------------------------\n\n");
    
    printf("[INFO] Solving process finished.\n");
    free_output( & best_res);
    sdsfree(input);
}

int main(int argc, char * argv[]) {
    struct arguments args = {
        .input = NULL,
        .algorithms = "common",
        .depth = 1,
        .keys = sdsnew(""),
        .probability_threshold = (int)(PROBABILITY_THRESHOLD * 100),
        .english_threshold = -1,
        .output_file = NULL,
        .p_set = 0,
        .silent = 0,
        .timeout = 10,
        .max_heap_size = 10000
    };

    struct argp argp = {
        options,
        parse_opt,
        args_doc,
        doc
    };
    argp_parse( & argp, argc, argv, 0, 0, & args);

    // Dispatch logic
    if (!args.input) {
        fprintf(stderr, "ERROR: Missing required input.\n");
        argp_help( & argp, stderr, ARGP_HELP_STD_ERR, argv[0]);
        return 1;
    }
    if (!args.subcommand) {
        fprintf(stderr, "ERROR: Missing required subcommand.\n");
        argp_help( & argp, stderr, ARGP_HELP_STD_ERR, argv[0]);
        return 1;
    }

    if (strcmp(args.subcommand, "analyze") == 0) {
        analyze(args.input, args.probability_threshold / 100.0f);
        args.input = NULL; // analyze frees it
    } else if (strcmp(args.subcommand, "solve") == 0) {
        // split keys by | into array
        sds raw_keys = args.keys;
        int count = 0;
        sds * tokens = sdssplitlen(raw_keys, sdslen(raw_keys), "|", 1, & count);

        debug_log("Algorithms: %s\n", args.algorithms);
        debug_log("Depth: %d\n", args.depth);

        debug_log("Keys: ");
        for (int i = 0; i < count; i++) {
            debug_log("%s / ", tokens[i]);
        }
        debug_log("\n");

        keychain_t keychain = {
            .len = count,
            .keys = tokens
        };

        debug_log("Probability Threshold: %f\n", args.probability_threshold / 100.0f);
        debug_log("English Threshold: %f\n", args.english_threshold / 100.0f);
        debug_log("Max Heap Size: %d\n", args.max_heap_size);

        solve(args.input, args.probability_threshold / 100.0f, args.algorithms, args.depth, & keychain, args.crib, args.english_threshold / 100.0f, args.monitor_path, args.output_file, args.p_set, args.silent, args.timeout, args.max_heap_size);
        args.input = NULL; // solve frees it
        sdsfreesplitres(tokens, count);
    }

    if (args.input) sdsfree(args.input);
    sdsfree(args.keys);
    return 0;
}
