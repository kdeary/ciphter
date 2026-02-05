#include <argp.h>

#include <stdlib.h>

#include <string.h>

#include "../lib/sds/sds.h"

#include <stdio.h>

#include "analyzers/analysis_registry.h"

#include "solvers/solver_registry.h"

#include "english_detector.h"

#include <ctype.h>
#include "../lib/minheap/heap.h"

#define PROBABILITY_THRESHOLD 0.01f

const char * argp_program_version = "ciphter v0.1";
const char * argp_program_bug_address = "<korbin.deary45@gmail.com>";
static char doc[] = "ciphter - cryptography analysis and processing tool";
static char args_doc[] = "";

// Program options
static struct argp_option options[] = {
    {
        "task",
        't',
        "TYPE",
        0,
        "Task type: A for analyze, S for solve"
    },
    {
        "input",
        'i',
        "STRING",
        0,
        "Input ciphertext or filename"
    },
    {
        "probability",
        'p',
        "INT",
        0,
        "Probability/Fitness (Printable) threshold (0-100)"
    },
    {
        "english",
        'E',
        "INT",
        0,
        "English quality threshold (0-100) for output filtering"
    },
    {
        "monitor",
        'm',
        "STRING",
        0,
        "Monitor specific path substring (debug logging)"
    },
    {
        "algorithms",
        'a',
        "STRING",
        0,
        "Algorithms to use [process only]"
    },
    {
        "depth",
        'd',
        "INT",
        0,
        "Depth of algorithm combinations [process only]"
    },
    {
        "keys",
        'k',
        "STRING",
        0,
        "Keys (raw)"
    },
    {
        "keyfile",
        'K',
        "FILE",
        0,
        "Key file"
    },
    {
        "crib",
        'c',
        "STRING",
        0,
        "Known string to search for (filters output)"
    },
    {
        "output",
        'O',
        "FILE",
        0,
        "Output file to dump results"
    },
    {
        "silent",
        's',
        0,
        0,
        "Silent mode (hide top 5 view)"
    },
    {
        "timeout",
        'T',
        "INT",
        0,
        "Timeout in seconds for solving (default: 3)"
    },
    {
        0
    }
};

// Struct to hold parsed options
struct arguments {
    char * subcommand;
    char * input;
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
        arguments -> input = arg;
        break;
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

#include <time.h>
#include "utils.h"

void solve(sds input, float fitness_threshold,
    const char * algorithms, int depth, keychain_t * keychain,
    const char * crib, int english_threshold,
    const char * monitor_path, char * output_file, int p_set, int silent, int timeout) {
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



    heap path_heap = {
        0
    };

    heap_create( & path_heap, 0, * output_compare_fn);
    heap_insert( & path_heap, & input_res, & input_res);

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

        // Prioritize crib matches
        if (crib && strstr(current -> data, crib) != NULL) {
            // Always print crib found
            // Handled by ui_log which handles the view clearing so we don't need manual line clearing logic here anymore
            
            float display_fitness = current -> fitness;
            float display_agg = current -> cumulative_fitness;

            printf("[%d][%.0f%%][Agg:%.2f]\t [CRIB FOUND] \"%s\" - Method: \"%s\"\n",
                current -> depth, display_fitness * 100, display_agg, current -> data, current -> method);
            if (f_out) fprintf(f_out, "[%d][%.0f%%][Agg:%.2f]\t [CRIB FOUND] \"%s\" - Method: \"%s\"\n",
                current -> depth, display_fitness * 100, display_agg, current -> data, current -> method);
            
            free_output(current);
            continue; // Stop recursion
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

        // Only print if fitness is high enough AND english threshold met (if enabled)
        if (current -> fitness > fitness_threshold) {
            int show = 1;
            if (english_threshold >= 0) {
                float eng_score = score_english_detailed(current -> data, sdslen(current -> data));
                if (eng_score * 100 < english_threshold) {
                    show = 0;
                }
            }

            if (show) {
                if (f_out) {
                    fprintf(f_out, "[%d][%.0f%%][Agg:%.2f]\t [OUTPUT] \"%s\" - Method: \"%s\"\n",
                        current -> depth,
                        current -> fitness * 100,
                        current -> cumulative_fitness,
                        current -> data,
                        current -> method);
                }

                if (p_set || english_threshold >= 0) {
                    // Regular verbose output
                    printf("[%d][%.0f%%][Agg:%.2f]\t [OUTPUT] \"%s\" - Method: \"%s\"\n",
                        current -> depth,
                        current -> fitness * 100,
                        current -> cumulative_fitness,
                        current -> data,
                        current -> method);
                }
            }
        }

        if (current -> depth >= depth) {
            free_output(current);
            continue;
        }

        for (size_t i = 0; i < solvers_count; ++i) {
            solver_t solver = solvers[i];

            if (current -> last_solver && strcmp(current -> last_solver, solver.label) == 0 && solver.prevent_consecutive) {
                continue;
            }

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
    } // End of while loop

    heap_foreach(&path_heap, free_heap_output);
    heap_destroy( & path_heap);
    
    free_output(&input_res);

    if (f_out) fclose(f_out);

    if (!found) {
        printf("[INFO] No high-probability solving results found.\n");
    }
    
    printf("[INFO] Solving process finished.\n");
    sdsfree(input);
}

int main(int argc, char * argv[]) {
    struct arguments args = {
        .subcommand = NULL,
        .input = NULL,
        .algorithms = "common",
        .depth = 1,
        .keys = sdsnew(""),
        .probability_threshold = (int)(PROBABILITY_THRESHOLD * 100),
        .english_threshold = -1,
        .output_file = NULL,
        .p_set = 0,
        .silent = 0,
        .timeout = 3
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
        analyze(sdsnew(args.input), args.probability_threshold / 100.0f);
    } else if (strcmp(args.subcommand, "solve") == 0) {
        // split keys by | into array
        sds raw_keys = args.keys;
        int count = 0;
        sds * tokens = sdssplitlen(raw_keys, sdslen(raw_keys), "|", 1, & count);

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

        solve(sdsnew(args.input), args.probability_threshold / 100.0f, args.algorithms, args.depth, & keychain, args.crib, args.english_threshold, args.monitor_path, args.output_file, args.p_set, args.silent, args.timeout);
        sdsfreesplitres(tokens, count);
    }

    sdsfree(args.keys);
    return 0;
}
