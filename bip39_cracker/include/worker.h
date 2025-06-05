#ifndef WORKER_H
#define WORKER_H

#include "config.h" // For NUM_KNOWN_WORDS, MAX_WORD_LENGTH, etc.

// Arguments for the worker thread function
typedef struct {
    int pos1;                                       // Index of the first missing word
    int pos2;                                       // Index of the second missing word
    char known_words_perm[NUM_KNOWN_WORDS][MAX_WORD_LENGTH]; // Permutation of known words
    int word1_start_idx;                            // Start index in BIP39 word list for the first missing word (for this thread)
    int word1_end_idx;                              // End index in BIP39 word list for the first missing word (for this thread)
    // target_address is global
    // bip39_word_list is global
} worker_args_t;

/**
 * @brief Worker function to check mnemonic candidates.
 *        This function is executed by each thread.
 *
 * @param args A pointer to worker_args_t containing the parameters for this thread.
 * @return void* Always returns NULL. Thread exits early if solution is found or found_flag is set.
 */
void* check_mnemonic_candidate_worker(void* args);

#endif // WORKER_H
