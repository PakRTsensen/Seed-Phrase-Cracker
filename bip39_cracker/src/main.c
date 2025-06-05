#include "config.h"
#include "bip39_utils.h"
#include "crypto_utils.h" // Not directly used in main, but worker needs it
#include "combinatorics.h"
#include "worker.h"

#include <stdio.h>
#include <stdlib.h> // For exit, atoi
#include <string.h>
#include <pthread.h>
#include <unistd.h> // For sysconf (optional, can hardcode cores)
#include <time.h>   // For timing

// --- Global Variable Definitions (already declared via extern in config.h) ---
char bip39_word_list[BIP39_WORD_LIST_SIZE][MAX_WORD_LENGTH];
char known_words[NUM_KNOWN_WORDS][MAX_WORD_LENGTH];
char target_address[TARGET_ADDRESS_MAX_LEN];
const char passphrase[] = ""; // BIP39 passphrase, empty by default
volatile int found_flag = 0;
pthread_mutex_t found_mutex;
char found_mnemonic_buffer[MAX_MNEMONIC_LENGTH];

// --- Struct to pass data to permutation_callback ---
typedef struct {
    int missing_pos1;
    int missing_pos2;
    int num_cores;
    // known_words are global for this context or could be passed
    // target_address is global
} permutation_user_data_t;

// --- Struct to pass data to combination_callback ---
// (No extra data needed beyond what generate_combinations provides directly to its callback's params for this specific use case)
// If we needed to pass num_cores or known_words list further down, we'd use it.
// For now, permutation_user_data will be populated inside the combination_callback.

// --- Static counters for progress reporting ---
static long long total_permutations_processed = 0; // For global count across all combinations
static long long current_permutation_count_for_combination = 0; // For count within a combination

// Helper to calculate factorial for total permutations
long long factorial(int n) {
    long long res = 1;
    for (int i = 2; i <= n; i++) res *= i;
    return res;
}

// --- Callback for generate_permutations ---
static void process_permutation_callback(char current_known_words_perm[][MAX_WORD_LENGTH], int n_val, void* user_data) {
    if (found_flag) {
        return; // Solution already found by another path
    }
    // Increment for the current combination
    current_permutation_count_for_combination++;
    // Increment global counter
    total_permutations_processed++;

    permutation_user_data_t* data = (permutation_user_data_t*)user_data;

    // Calculate total expected permutations for this set of known words (n_val!)
    long long total_expected_perms_for_this_call = factorial(n_val);

    // Print current permutation being processed, and its progress within this combination
    // This might be too verbose if printed for every permutation.
    // Consider printing every Nth permutation or when a certain time has passed.
    // For now, let's print every Kth permutation for this specific combination call.
    // Define K (e.g., 1000 or based on total_expected_perms_for_this_call / some_factor)
    long K_perm_print_interval = 1; // Print every permutation for now, can be adjusted
    if (total_expected_perms_for_this_call > 10000) K_perm_print_interval = total_expected_perms_for_this_call / 100;
    else if (total_expected_perms_for_this_call > 1000) K_perm_print_interval = 10;

    if (K_perm_print_interval == 0) K_perm_print_interval = 1;


    if (current_permutation_count_for_combination % K_perm_print_interval == 0 || current_permutation_count_for_combination == 1 || current_permutation_count_for_combination == total_expected_perms_for_this_call ) {
        printf("Comb (%d,%d) - Permutation %lld / %lld : ",
               data->missing_pos1, data->missing_pos2,
               current_permutation_count_for_combination, total_expected_perms_for_this_call);
        for(int i=0; i < NUM_KNOWN_WORDS; ++i) {
            printf("%s ", current_known_words_perm[i]);
        }
        printf("\n");
    }

    pthread_t threads[data->num_cores];
    worker_args_t thread_args[data->num_cores];
    // Initialize thread_args to ensure no stale data if fewer threads are created than num_cores
    memset(thread_args, 0, sizeof(thread_args));


    int chunk_size = (BIP39_WORD_LIST_SIZE + data->num_cores - 1) / data->num_cores;
    int active_threads = 0;

    for (int i = 0; i < data->num_cores; ++i) {
        if (found_flag) break; // Check before spawning more threads

        thread_args[i].pos1 = data->missing_pos1;
        thread_args[i].pos2 = data->missing_pos2;
        memcpy(thread_args[i].known_words_perm, current_known_words_perm, sizeof(char) * NUM_KNOWN_WORDS * MAX_WORD_LENGTH);
        thread_args[i].word1_start_idx = i * chunk_size;
        thread_args[i].word1_end_idx = (i + 1) * chunk_size;

        if (thread_args[i].word1_end_idx > BIP39_WORD_LIST_SIZE) {
            thread_args[i].word1_end_idx = BIP39_WORD_LIST_SIZE;
        }

        if (thread_args[i].word1_start_idx >= thread_args[i].word1_end_idx) {
            // No work for this thread slot if start_idx is past or at end_idx
            continue;
        }

        if (pthread_create(&threads[i], NULL, check_mnemonic_candidate_worker, &thread_args[i]) != 0) {
            perror("Failed to create thread");
            // Potentially handle this more gracefully
        } else {
            active_threads++;
        }
    }

    for (int i = 0; i < data->num_cores; ++i) {
        // Only join threads that were actually created and had work
        if (thread_args[i].word1_start_idx < thread_args[i].word1_end_idx) {
            if (pthread_join(threads[i], NULL) != 0) {
                perror("Failed to join thread");
            }
        }
    }
}

// --- Callback for generate_combinations ---
static void process_combination_callback(int* combination, int k_val, void* user_data) {
    if (found_flag) {
        return; // Solution already found
    }
    if (k_val != NUM_MISSING_WORDS) { // Should be 2
        fprintf(stderr, "Combination callback received k=%d, expected %d\n", k_val, NUM_MISSING_WORDS);
        return;
    }

    // Reset permutation counter for this new combination
    current_permutation_count_for_combination = 0;
    // total_permutations_processed continues to increment globally.

    int num_cores = *(int*)user_data; // User data is just num_cores here

    permutation_user_data_t perm_data;
    perm_data.missing_pos1 = combination[0];
    perm_data.missing_pos2 = combination[1];
    perm_data.num_cores = num_cores;

    printf("\nProcessing combination for missing positions: %d, %d. (Overall perms so far: %lld)\n",
           perm_data.missing_pos1, perm_data.missing_pos2, total_permutations_processed);

    // Create a mutable copy of known_words for generate_permutations, as it permutes in-place.
    char current_known_words_copy[NUM_KNOWN_WORDS][MAX_WORD_LENGTH];
    memcpy(current_known_words_copy, known_words, sizeof(known_words));

    generate_permutations(current_known_words_copy, NUM_KNOWN_WORDS, process_permutation_callback, &perm_data);
}


int main(int argc, char *argv[]) {
    clock_t start_time = clock();

    // --- Hardcoded Inputs for Testing ---
    const char* initial_known_words[NUM_KNOWN_WORDS] = {
        "logic", "puzzle", "pave", "glimpse", "off",
        "onion", "hollow", "symptom", "undo", "crucial"
        // Missing: "ugly", "tube"
    };
    for (int i = 0; i < NUM_KNOWN_WORDS; ++i) {
        strncpy(known_words[i], initial_known_words[i], MAX_WORD_LENGTH -1);
        known_words[i][MAX_WORD_LENGTH-1] = '\0';
    }

    // Target address for the test case (compressed P2PKH)
    // Mnemonic: logic puzzle pave glimpse off onion hollow symptom undo crucial ugly tube
    // Path: m/44'/0'/0'/0/0
    char default_target_address[] = "1M9XALBSj6YJ3K3kYNDL2vTfHSy5m7d58v";

    if (argc > 1) {
        strncpy(target_address, argv[1], TARGET_ADDRESS_MAX_LEN -1);
        target_address[TARGET_ADDRESS_MAX_LEN-1] = '\0';
        printf("Using target address from command line: %s\n", target_address);
    } else {
        strncpy(target_address, default_target_address, TARGET_ADDRESS_MAX_LEN -1);
        target_address[TARGET_ADDRESS_MAX_LEN-1] = '\0';
        printf("Using hardcoded test target address: %s\n", target_address);
    }

    printf("Using hardcoded known words for testing: \n");
    for(int i=0; i < NUM_KNOWN_WORDS; ++i) printf("  %s\n", known_words[i]);


    // --- Initialization ---
    if (pthread_mutex_init(&found_mutex, NULL) != 0) {
        perror("Mutex init failed");
        return FAILURE;
    }

    if (load_bip39_word_list("data/english.txt") != SUCCESS) {
        fprintf(stderr, "Failed to load BIP39 word list. Ensure 'data/english.txt' exists and is valid.\n");
        pthread_mutex_destroy(&found_mutex);
        return FAILURE;
    }

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    int num_cores = (nproc > 0) ? (int)nproc : 4;
    printf("Using %d CPU cores for parallel processing.\n", num_cores);


    // --- Main Logic ---
    printf("Starting search for target address: %s\n", target_address);
    printf("Generating combinations for %d missing word positions out of %d total mnemonic words...\n",
           NUM_MISSING_WORDS, NUM_WORDS_MNEMONIC);

    generate_combinations(NUM_WORDS_MNEMONIC, NUM_MISSING_WORDS, process_combination_callback, &num_cores);

    // --- Results & Cleanup ---
    clock_t end_time = clock();
    double time_spent = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    if (found_flag) {
        printf("\n--- MNEMONIC FOUND! ---\n");
        printf("Mnemonic: %s\n", found_mnemonic_buffer);
        printf("Target Address: %s\n", target_address);
    } else {
        printf("\n--- MNEMONIC NOT FOUND ---\n");
        printf("Target Address: %s was not found with the given known words.\n", target_address);
    }
    printf("Total search time: %.2f seconds\n", time_spent);

    pthread_mutex_destroy(&found_mutex);

    return found_flag ? SUCCESS : FAILURE;
}
