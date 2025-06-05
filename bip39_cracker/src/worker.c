#include "worker.h"
#include "config.h"
#include "crypto_utils.h" // For all crypto operations
#include <stdio.h>
#include <string.h>
#include <pthread.h> // For pthread_exit, pthread_mutex_lock/unlock

// Access to global variables (declared extern in config.h)
// char bip39_word_list[BIP39_WORD_LIST_SIZE][MAX_WORD_LENGTH];
// char target_address[TARGET_ADDRESS_MAX_LEN];
// volatile int found_flag;
// pthread_mutex_t found_mutex;
// char found_mnemonic_buffer[MAX_MNEMONIC_LENGTH];
// const char passphrase[];


void* check_mnemonic_candidate_worker(void* arg) {
    worker_args_t* w_args = (worker_args_t*)arg;

    char candidate_mnemonic_words[NUM_WORDS_MNEMONIC][MAX_WORD_LENGTH];
    char mnemonic_str[MAX_MNEMONIC_LENGTH];
    unsigned char seed[64];
    unsigned char private_key_bytes[32];
    unsigned char public_key_compressed[33];
    unsigned char public_key_uncompressed[65];
    unsigned char ripemd160_c[20], ripemd160_unc[20];
    char address_c[TARGET_ADDRESS_MAX_LEN], address_unc[TARGET_ADDRESS_MAX_LEN];

    // Loop for the first missing word (assigned chunk to this thread)
    for (int w1_idx = w_args->word1_start_idx; w1_idx < w_args->word1_end_idx; ++w1_idx) {
        if (found_flag) pthread_exit(NULL); // Check global flag periodically

        // Progress reporting: Report every, say, 64th iteration of the outer loop for this thread
        // The value 64 is arbitrary; adjust for desired frequency.
        if ((w1_idx - w_args->word1_start_idx) % 64 == 0 && (w1_idx != w_args->word1_start_idx)) {
            // Get thread ID for more specific logging, though it can be verbose
            // pthread_t self_id = pthread_self();
            // unsigned long thread_id_num = (unsigned long)self_id; //Platform dependent cast

            // Simplified progress message:
            printf("Thread (pos1=%d, pos2=%d): Processing candidate word1 index %d (%.1f%% of its chunk)\n",
                   w_args->pos1, w_args->pos2, w1_idx,
                   (double)(w1_idx - w_args->word1_start_idx + 1) * 100.0 / (w_args->word1_end_idx - w_args->word1_start_idx));
        }

        // Loop for the second missing word (full BIP39 list)
        for (int w2_idx = 0; w2_idx < BIP39_WORD_LIST_SIZE; ++w2_idx) {
            if (found_flag) pthread_exit(NULL);

            // 1. Build Mnemonic Candidate
            int known_word_idx = 0;
            for (int i = 0; i < NUM_WORDS_MNEMONIC; ++i) {
                if (i == w_args->pos1) {
                    strncpy(candidate_mnemonic_words[i], bip39_word_list[w1_idx], MAX_WORD_LENGTH -1);
                    candidate_mnemonic_words[i][MAX_WORD_LENGTH-1] = '\0';
                } else if (i == w_args->pos2) {
                    strncpy(candidate_mnemonic_words[i], bip39_word_list[w2_idx], MAX_WORD_LENGTH -1);
                    candidate_mnemonic_words[i][MAX_WORD_LENGTH-1] = '\0';
                } else {
                    strncpy(candidate_mnemonic_words[i], w_args->known_words_perm[known_word_idx++], MAX_WORD_LENGTH -1);
                    candidate_mnemonic_words[i][MAX_WORD_LENGTH-1] = '\0';
                }
            }

            // Concatenate words into a single mnemonic string
            mnemonic_str[0] = '\0';
            for (int i = 0; i < NUM_WORDS_MNEMONIC; ++i) {
                strncat(mnemonic_str, candidate_mnemonic_words[i], MAX_WORD_LENGTH -1);
                if (i < NUM_WORDS_MNEMONIC - 1) {
                    strcat(mnemonic_str, " ");
                }
            }
            // Optimization: check if mnemonic is valid before deriving.
            // The current mnemonic_to_seed placeholder returns SUCCESS.
            // A real one would validate checksum.
            // if (!mnemonic_is_valid(mnemonic_str)) continue; // Requires a BIP39 checksum validation function

            // 2. Validate and Derive Seed
            if (mnemonic_to_seed(mnemonic_str, passphrase, seed) != SUCCESS) {
                // This also implicitly validates checksum with a real BIP39 library.
                // If it fails, this mnemonic is invalid.
                continue;
            }

            // Loop Derivation Paths (e.g., m/44'/0'/account'/0/index)
            // Standard P2PKH path: m/44'/0'/account'/0/address_index
            uint32_t purpose = 44;
            uint32_t coin_type = 0; // Bitcoin
            uint32_t change = 0;    // External chain

            for (uint32_t account = 0; account < 2; ++account) { // Check first 2 accounts
                if (found_flag) pthread_exit(NULL);
                for (uint32_t index = 0; index < 10; ++index) { // Check first 10 addresses per account
                    if (found_flag) pthread_exit(NULL);

                    if (bip32_derive_private_key(seed,
                                               0x80000000 | purpose,
                                               0x80000000 | coin_type,
                                               0x80000000 | account,
                                               change,
                                               index,
                                               private_key_bytes) != SUCCESS) {
                        continue; // Derivation failed for this path
                    }

                    // 3. Generate and Check Addresses (Compressed & Uncompressed)

                    // Compressed Address
                    if (private_key_to_public_key_compressed(private_key_bytes, public_key_compressed) == SUCCESS) {
                        hash_public_key_to_ripemd160(public_key_compressed, sizeof(public_key_compressed), ripemd160_c);
                        ripemd160_to_p2pkh_address(ripemd160_c, 0x00, address_c); // 0x00 for Bitcoin mainnet

                        if (strcmp(address_c, target_address) == 0) {
                            pthread_mutex_lock(&found_mutex);
                            if (found_flag == 0) { // Check again inside lock
                                found_flag = 1;
                                strncpy(found_mnemonic_buffer, mnemonic_str, MAX_MNEMONIC_LENGTH -1);
                                found_mnemonic_buffer[MAX_MNEMONIC_LENGTH-1] = '\0';
                                printf("FOUND (Compressed)! Mnemonic: %s -> Address: %s\n", mnemonic_str, address_c);
                            }
                            pthread_mutex_unlock(&found_mutex);
                            pthread_exit(NULL);
                        }
                    }

                    // Uncompressed Address
                    if (private_key_to_public_key_uncompressed(private_key_bytes, public_key_uncompressed) == SUCCESS) {
                        hash_public_key_to_ripemd160(public_key_uncompressed, sizeof(public_key_uncompressed), ripemd160_unc);
                        ripemd160_to_p2pkh_address(ripemd160_unc, 0x00, address_unc); // 0x00 for Bitcoin mainnet

                        if (strcmp(address_unc, target_address) == 0) {
                            pthread_mutex_lock(&found_mutex);
                            if (found_flag == 0) { // Check again inside lock
                                found_flag = 1;
                                strncpy(found_mnemonic_buffer, mnemonic_str, MAX_MNEMONIC_LENGTH -1);
                                found_mnemonic_buffer[MAX_MNEMONIC_LENGTH-1] = '\0';
                                printf("FOUND (Uncompressed)! Mnemonic: %s -> Address: %s\n", mnemonic_str, address_unc);
                            }
                            pthread_mutex_unlock(&found_mutex);
                            pthread_exit(NULL);
                        }
                    }
                } // end index loop
            } // end account loop
        } // end w2_idx loop (second missing word)
         // Optional: Add a small sleep here if workers are too CPU intensive without finding,
         // or a counter to print progress for this thread.
         // if (w1_idx % 10 == 0) { // crude progress for this thread
         //   printf("Thread working on w1_idx = %d for pos1=%d, pos2=%d\n", w1_idx, w_args->pos1, w_args->pos2);
         // }
    } // end w1_idx loop (first missing word)

    pthread_exit(NULL);
    return NULL; // Should be unreachable due to pthread_exit
}
