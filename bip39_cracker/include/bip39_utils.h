#ifndef BIP39_UTILS_H
#define BIP39_UTILS_H

#include "config.h" // For constants like BIP39_WORD_LIST_SIZE, MAX_WORD_LENGTH

/**
 * @brief Loads the BIP39 word list from the specified file into the global
 *        bip39_word_list array.
 *
 * @param filename The path to the BIP39 word list file (e.g., "english.txt").
 * @return SUCCESS if loading is successful,
 *         FILE_NOT_FOUND_ERROR if the file cannot be opened,
 *         INVALID_FILE_FORMAT_ERROR if the file format is incorrect or word count is wrong.
 */
int load_bip39_word_list(const char* filename);

#endif // BIP39_UTILS_H
