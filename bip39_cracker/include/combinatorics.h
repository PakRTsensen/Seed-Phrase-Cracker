#ifndef COMBINATORICS_H
#define COMBINATORICS_H

#include "config.h" // For MAX_WORD_LENGTH, NUM_KNOWN_WORDS etc.

/**
 * @brief Callback function type for generate_combinations.
 *
 * @param combination An array of k integers representing the current combination (e.g., indices).
 * @param k_val The number of elements in the combination (same as k in generate_combinations).
 * @param user_data A pointer to user-defined data passed to generate_combinations.
 */
typedef void (*combination_callback_t)(int* combination, int k_val, void* user_data);

/**
 * @brief Generates all combinations of k elements from a set of n elements (represented by indices 0 to n-1).
 *
 * @param n Total number of elements to choose from.
 * @param k Number of elements to choose in each combination.
 * @param callback The function to call for each generated combination.
 * @param user_data User-specific data to pass to the callback.
 */
void generate_combinations(int n, int k, combination_callback_t callback, void* user_data);


/**
 * @brief Callback function type for generate_permutations.
 *
 * @param perm_items An array of strings representing the current permutation.
 * @param n_val The number of items in the permutation.
 * @param user_data A pointer to user-defined data passed to generate_permutations.
 */
typedef void (*permutation_callback_t)(char items[][MAX_WORD_LENGTH], int n_val, void* user_data);

/**
 * @brief Generates all permutations of an array of n strings (words).
 *        Uses Heap's algorithm.
 *
 * @param items An array of strings (words) to permute. This array will be modified during permutation.
 *              The callback receives a pointer to this array in its current permuted state.
 * @param n The number of items in the array.
 * @param callback The function to call for each generated permutation.
 * @param user_data User-specific data to pass to the callback.
 */
void generate_permutations(char items[][MAX_WORD_LENGTH], int n, permutation_callback_t callback, void* user_data);

#endif // COMBINATORICS_H
