#include "combinatorics.h"
#include <stdio.h>
#include <string.h> // For memcpy, strcpy in permutation swap
#include <stdlib.h> // For malloc, free in generate_combinations_recursive

// --- Combinations ---

// Helper recursive function for generate_combinations
static void generate_combinations_recursive(
    int offset,
    int k_recursive, // This is the "countdown" k
    int n,
    int original_k, // The k value generate_combinations was called with
    int* current_combination,
    combination_callback_t callback,
    void* user_data) {

    if (k_recursive == 0) {
        callback(current_combination, original_k, user_data);
        return;
    }
    for (int i = offset; i <= n - k_recursive; ++i) {
        current_combination[original_k - k_recursive] = i;
        generate_combinations_recursive(i + 1, k_recursive - 1, n, original_k, current_combination, callback, user_data);
    }
}

void generate_combinations(int n, int k, combination_callback_t callback, void* user_data) {
    if (k < 0 || k > n) {
        fprintf(stderr, "Invalid k value for combinations\n");
        return;
    }
    if (callback == NULL) {
        fprintf(stderr, "Combination callback cannot be null\n");
        return;
    }
    int* current_combination = (int*)malloc(k * sizeof(int));
    if (!current_combination) {
        fprintf(stderr, "Failed to allocate memory for combination array\n");
        return;
    }
    generate_combinations_recursive(0, k, n, k, current_combination, callback, user_data);
    free(current_combination);
}


// --- Permutations (Heap's Algorithm) ---

// Helper function to swap two strings (words)
static void swap_strings(char str1[MAX_WORD_LENGTH], char str2[MAX_WORD_LENGTH]) {
    char temp[MAX_WORD_LENGTH];
    strncpy(temp, str1, MAX_WORD_LENGTH -1);
    temp[MAX_WORD_LENGTH-1] = '\0';

    strncpy(str1, str2, MAX_WORD_LENGTH -1);
    str1[MAX_WORD_LENGTH-1] = '\0';

    strncpy(str2, temp, MAX_WORD_LENGTH -1);
    str2[MAX_WORD_LENGTH-1] = '\0';
}

// Recursive helper for Heap's algorithm
static void generate_permutations_recursive(
    char items[][MAX_WORD_LENGTH],
    int size, // current size of the array slice being permuted
    int n,    // original number of items
    permutation_callback_t callback,
    void* user_data) {

    if (size == 1) {
        callback(items, n, user_data);
        return;
    }

    for (int i = 0; i < size; i++) {
        generate_permutations_recursive(items, size - 1, n, callback, user_data);

        // If size is odd, swap first and last element
        if (size % 2 == 1) {
            swap_strings(items[0], items[size - 1]);
        }
        // If size is even, swap ith and last element
        else {
            swap_strings(items[i], items[size - 1]);
        }
    }
}

void generate_permutations(char items[][MAX_WORD_LENGTH], int n, permutation_callback_t callback, void* user_data) {
    if (n <= 0 ) {
        // Removed n > NUM_KNOWN_WORDS condition as NUM_KNOWN_WORDS may not be the correct upper bound here.
        // The function should be generic for any 'n' up to a reasonable limit based on MAX_WORD_LENGTH and memory.
        // A practical limit might be related to NUM_WORDS_MNEMONIC.
        fprintf(stderr, "Invalid n value for permutations\n");
        return;
    }
    if (callback == NULL) {
        fprintf(stderr, "Permutation callback cannot be null\n");
        return;
    }
    generate_permutations_recursive(items, n, n, callback, user_data);
}
