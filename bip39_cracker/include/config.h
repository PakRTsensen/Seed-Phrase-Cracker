#ifndef CONFIG_H
#define CONFIG_H

#include <pthread.h> // For pthread_mutex_t
#include <stddef.h>  // For size_t

// --- Constants ---
#define NUM_WORDS_MNEMONIC 12
#define NUM_KNOWN_WORDS 10
#define NUM_MISSING_WORDS 2
#define BIP39_WORD_LIST_SIZE 2048
#define MAX_WORD_LENGTH 20 // Maximum characters per BIP39 word + null terminator
#define TARGET_ADDRESS_MAX_LEN 60 // Max length for a P2PKH address string
#define MAX_MNEMONIC_LENGTH (NUM_WORDS_MNEMONIC * (MAX_WORD_LENGTH + 1)) // Max length for a mnemonic phrase string

// --- Global Variables (declarations using extern) ---

// Array to store the BIP39 word list
extern char bip39_word_list[BIP39_WORD_LIST_SIZE][MAX_WORD_LENGTH];

// Array to store the 10 known words (input by user)
extern char known_words[NUM_KNOWN_WORDS][MAX_WORD_LENGTH];

// Target Bitcoin address (input by user)
extern char target_address[TARGET_ADDRESS_MAX_LEN];

// Passphrase for BIP39 (can be empty)
extern const char passphrase[]; // Defined as const "" in a .c file

// Flag to indicate if the mnemonic has been found (volatile for thread safety)
extern volatile int found_flag;

// Mutex to protect access to found_flag and the found mnemonic buffer
extern pthread_mutex_t found_mutex;

// Buffer to store the found mnemonic
extern char found_mnemonic_buffer[MAX_MNEMONIC_LENGTH];

// --- Function Return Codes (example) ---
#define SUCCESS 0
#define FAILURE -1
#define FILE_NOT_FOUND_ERROR -2
#define INVALID_FILE_FORMAT_ERROR -3

#endif // CONFIG_H
