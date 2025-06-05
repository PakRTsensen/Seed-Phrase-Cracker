#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h> // For sysconf

// Placeholder paths for library headers
#include "../lib/crypto/bip39.h"
#include "../lib/crypto/bip32.h"
#include "../lib/crypto/curves.h"
#include "../lib/crypto/sha2.h"
#include "../lib/crypto/ripemd160.h"
#include "../lib/libbase58/libbase58.h"
#include "../lib/secp256k1/include/secp256k1.h"

// Constants
#define NUM_KNOWN_WORDS 10
#define TOTAL_WORDS 12
#define BIP39_WORD_LIST_SIZE 2048
#define MAX_WORD_LENGTH 20
#define TARGET_ADDRESS_MAX_LEN 64
#define PASSPHRASE_MAX_LEN 128
#define MAX_MNEMONIC_LENGTH (TOTAL_WORDS * MAX_WORD_LENGTH + TOTAL_WORDS)
#define MAX_POSSIBLE_THREADS 128 // Max threads for process_permutation_callback

// Global BIP39 word list
char bip39_word_list[BIP39_WORD_LIST_SIZE][MAX_WORD_LENGTH];

// Global secp256k1 context
secp256k1_context* global_secp256k1_ctx = NULL;

// --- Main Orchestration Globals & Structs ---
pthread_mutex_t found_flag_mutex;
volatile int found_flag = 0;
char found_mnemonic_buffer[MAX_MNEMONIC_LENGTH];
char known_words[NUM_KNOWN_WORDS][MAX_WORD_LENGTH];
char target_address[TARGET_ADDRESS_MAX_LEN];
char passphrase[PASSPHRASE_MAX_LEN];
int num_cores = 1;

typedef struct {
    int num_cores;
    char (*known_words_array_ptr)[NUM_KNOWN_WORDS][MAX_WORD_LENGTH];
    const char (*bip39_word_list_ptr)[MAX_WORD_LENGTH];
    const char* passphrase_ptr;
    const char* target_address_ptr;
    pthread_mutex_t* found_flag_mutex_ptr;
    volatile int* found_flag_ptr;
    char* found_mnemonic_buffer_ptr;
    long* total_permutations_processed_ptr;
} main_orchestrator_data_t;

typedef struct {
    main_orchestrator_data_t* orchestrator_data_ptr;
    const int* current_positions_ptr;
} permutation_callback_args_t;

// Forward declaration for callbacks used in orchestration
void process_combination_callback(const int* current_combination_indices, int k_selected_count, void* user_data_orchestrator);
void process_permutation_callback(char current_permuted_words[][MAX_WORD_LENGTH], int num_words_in_perm, void* user_data_perm_args);
void* check_mnemonic_worker(void* args); // Forward declaration for worker

// Structure for arguments passed to each worker thread
typedef struct {
    int pos1;
    int pos2;
    char known_words_perm[NUM_KNOWN_WORDS][MAX_WORD_LENGTH];
    int word1_start_idx;
    int word1_end_idx;

    const char (*bip39_word_list_ptr)[MAX_WORD_LENGTH];
    const char* passphrase_ptr;
    const char* target_address_ptr;

    pthread_mutex_t* found_flag_mutex_ptr;
    volatile int* found_flag_ptr;
    char* found_mnemonic_buffer_ptr;
} worker_args_t;


int load_bip39_word_list(const char* filename, char word_list_out[][MAX_WORD_LENGTH], int list_size) {
    if (found_flag) return 0; // Optimization: if found elsewhere, no need to load.
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening word list file");
        fprintf(stderr, "Attempted to open: %s\n", filename);
        return -1;
    }
    char line[MAX_WORD_LENGTH + 2];
    int count = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        if (count >= list_size) {
            fprintf(stderr, "Error: Too many words in the word list file. Expected %d. Loaded %d.\n", list_size, count);
            break;
        }
        line[strcspn(line, "\n")] = 0;
        line[strcspn(line, "\r")] = 0;
        if (strlen(line) == 0 && feof(file)) break;
        if (strlen(line) >= MAX_WORD_LENGTH) {
            fprintf(stderr, "Error: Word '%s' (line %d) is too long (max %d chars).\n", line, count + 1, MAX_WORD_LENGTH -1);
            continue;
        }
        strncpy(word_list_out[count], line, MAX_WORD_LENGTH -1);
        word_list_out[count][MAX_WORD_LENGTH - 1] = '\0';
        count++;
    }
    fclose(file);
    return count;
}

int c_mnemonic_check(const char* mnemonic) { return mnemonic_check(mnemonic); }
int c_mnemonic_to_seed(const char* mnemonic, const char* passphrase, unsigned char* seed_out_64bytes) {
    mnemonic_to_seed(mnemonic, passphrase, seed_out_64bytes, 0); return 1;
}
int c_derive_hdnode_from_seed(const unsigned char* seed_64bytes, HDNode* out_node) {
    HDNode* result_node = hdnode_from_seed(seed_64bytes, 64, SECP256K1_NAME, out_node);
    return (result_node != NULL) ? 1 : 0;
}
int c_derive_bip32_child_key(const HDNode* parent_node, const uint32_t* path_elements, int path_len, HDNode* child_node_out, unsigned char* private_key_out_32bytes) {
    if (!parent_node || !path_elements || path_len <= 0 || !child_node_out || !private_key_out_32bytes) return 0;
    HDNode current_node; memcpy(&current_node, parent_node, sizeof(HDNode));
    for (int i = 0; i < path_len; ++i) {
        if (path_elements[i] >= BIP32_HARDEN) hdnode_private_ckd_prime(&current_node, path_elements[i]);
        else hdnode_private_ckd(&current_node, path_elements[i]);
    }
    memcpy(child_node_out, &current_node, sizeof(HDNode));
    hdnode_get_private_key(child_node_out, private_key_out_32bytes); return 1;
}
int c_private_to_public_compressed(const unsigned char* priv_key_32bytes, unsigned char* pub_key_out_33bytes) {
    if (!global_secp256k1_ctx || !priv_key_32bytes || !pub_key_out_33bytes) return 0;
    secp256k1_pubkey pubkey_struct;
    if (secp256k1_ec_pubkey_create(global_secp256k1_ctx, &pubkey_struct, priv_key_32bytes) != 1) return 0;
    size_t output_len = 33; int ret = secp256k1_ec_pubkey_serialize(global_secp256k1_ctx, pub_key_out_33bytes, &output_len, &pubkey_struct, SECP256K1_EC_COMPRESSED);
    return (ret == 1 && output_len == 33);
}
int c_private_to_public_uncompressed(const unsigned char* priv_key_32bytes, unsigned char* pub_key_out_65bytes) {
    if (!global_secp256k1_ctx || !priv_key_32bytes || !pub_key_out_65bytes) return 0;
    secp256k1_pubkey pubkey_struct;
    if (secp256k1_ec_pubkey_create(global_secp256k1_ctx, &pubkey_struct, priv_key_32bytes) != 1) return 0;
    size_t output_len = 65; int ret = secp256k1_ec_pubkey_serialize(global_secp256k1_ctx, pub_key_out_65bytes, &output_len, &pubkey_struct, SECP256K1_EC_UNCOMPRESSED);
    return (ret == 1 && output_len == 65);
}
void c_hash_public_key_to_ripemd160(const unsigned char* pub_key_bytes, size_t pub_key_len, unsigned char* ripemd160_hash_out_20bytes) {
    if (!pub_key_bytes || !ripemd160_hash_out_20bytes) return;
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    sha256_Raw(pub_key_bytes, pub_key_len, sha256_digest);
    ripemd160_Raw(sha256_digest, SHA256_DIGEST_LENGTH, ripemd160_hash_out_20bytes);
}
int c_ripemd160_to_p2pkh_address(const unsigned char* ripemd160_hash_20bytes, unsigned char network_byte, char* address_out, size_t address_out_max_len) {
    if (!ripemd160_hash_20bytes || !address_out || address_out_max_len < 36) return 0;
    size_t encoded_len = address_out_max_len;
    bool success = b58check_enc(address_out, &encoded_len, network_byte, ripemd160_hash_20bytes, 20);
    if (!success && address_out_max_len > 0) address_out[0] = '\0';
    return success ? 1 : 0;
}

// --- Combinations Logic (with early exit) ---
static void combinations_recursive_impl(int offset, int k_remaining, int n_total, int k_select, int* current_selection, void (*callback)(const int*, int, void*), void* user_data_orchestrator) {
    main_orchestrator_data_t* orch_data = (main_orchestrator_data_t*)user_data_orchestrator;
    pthread_mutex_lock(orch_data->found_flag_mutex_ptr); int is_found = *(orch_data->found_flag_ptr); pthread_mutex_unlock(orch_data->found_flag_mutex_ptr);
    if (is_found) return;
    if (k_remaining == 0) { callback(current_selection, k_select, user_data_orchestrator); return; }
    int current_selection_idx = k_select - k_remaining;
    for (int i = offset; i <= n_total - k_remaining; ++i) {
        current_selection[current_selection_idx] = i;
        combinations_recursive_impl(i + 1, k_remaining - 1, n_total, k_select, current_selection, callback, user_data_orchestrator);
        pthread_mutex_lock(orch_data->found_flag_mutex_ptr); is_found = *(orch_data->found_flag_ptr); pthread_mutex_unlock(orch_data->found_flag_mutex_ptr);
        if (is_found) return;
    }
}
void generate_combinations(int n_total_elements, int k_select_elements, void (*callback)(const int* combination, int k, void* user_data), void* user_data) {
    if (k_select_elements < 0 || k_select_elements > n_total_elements) return;
    if (k_select_elements == 0) { /* callback(NULL, 0, user_data); */ return; } // Decide if k=0 callback is needed
    int* current_selection_array = (int*)malloc(k_select_elements * sizeof(int));
    if (!current_selection_array) { perror("malloc combinations"); return; }
    combinations_recursive_impl(0, k_select_elements, n_total_elements, k_select_elements, current_selection_array, callback, user_data);
    free(current_selection_array);
}

// --- Permutations Logic (with early exit) ---
static void swap_strings_impl(char str1[MAX_WORD_LENGTH], char str2[MAX_WORD_LENGTH]) {
    char temp[MAX_WORD_LENGTH];
    strncpy(temp, str1, MAX_WORD_LENGTH); if (MAX_WORD_LENGTH > 0 && temp[MAX_WORD_LENGTH-1]!='\0') temp[MAX_WORD_LENGTH-1]='\0';
    strncpy(str1, str2, MAX_WORD_LENGTH); if (MAX_WORD_LENGTH > 0 && str1[MAX_WORD_LENGTH-1]!='\0') str1[MAX_WORD_LENGTH-1]='\0';
    strncpy(str2, temp, MAX_WORD_LENGTH); if (MAX_WORD_LENGTH > 0 && str2[MAX_WORD_LENGTH-1]!='\0') str2[MAX_WORD_LENGTH-1]='\0';
}
static void permutations_recursive_impl(char arr_items[][MAX_WORD_LENGTH], int current_perm_size, int total_num_items, void (*callback)(char perm_items[][MAX_WORD_LENGTH], int n, void* user_data), void* user_data_perm_args) {
    permutation_callback_args_t* perm_args = (permutation_callback_args_t*)user_data_perm_args;
    main_orchestrator_data_t* orch_data = perm_args->orchestrator_data_ptr;
    pthread_mutex_lock(orch_data->found_flag_mutex_ptr); int is_found = *(orch_data->found_flag_ptr); pthread_mutex_unlock(orch_data->found_flag_mutex_ptr);
    if (is_found) return;
    if (current_perm_size == 1) { callback(arr_items, total_num_items, user_data_perm_args); return; }
    for (int i = 0; i < current_perm_size; i++) {
        permutations_recursive_impl(arr_items, current_perm_size - 1, total_num_items, callback, user_data_perm_args);
        pthread_mutex_lock(orch_data->found_flag_mutex_ptr); is_found = *(orch_data->found_flag_ptr); pthread_mutex_unlock(orch_data->found_flag_mutex_ptr);
        if (is_found) return;
        if (current_perm_size % 2 == 1) swap_strings_impl(arr_items[0], arr_items[current_perm_size - 1]);
        else swap_strings_impl(arr_items[i], arr_items[current_perm_size - 1]);
    }
}
void generate_permutations(char items_to_permute[][MAX_WORD_LENGTH], int num_items_to_permute, void (*callback)(char perm_items[][MAX_WORD_LENGTH], int n, void* user_data), void* user_data) {
    if (num_items_to_permute <= 0) return;
    permutations_recursive_impl(items_to_permute, num_items_to_permute, num_items_to_permute, callback, user_data);
}

// --- Worker Thread Function ---
void* check_mnemonic_worker(void* args) {
    worker_args_t* data = (worker_args_t*)args;
    if (!data || !data->bip39_word_list_ptr || !data->known_words_perm || !data->passphrase_ptr || !data->target_address_ptr || !data->found_flag_mutex_ptr || !data->found_flag_ptr || !data->found_mnemonic_buffer_ptr) {
        fprintf(stderr, "Worker error: Essential data pointers in worker_args_t are NULL.\n"); pthread_exit((void*)-1);
    }
    if (data->pos1<0 || data->pos1>=TOTAL_WORDS || data->pos2<0 || data->pos2>=TOTAL_WORDS || data->pos1==data->pos2 || data->word1_start_idx<0 || data->word1_end_idx > BIP39_WORD_LIST_SIZE || data->word1_start_idx > data->word1_end_idx) {
        fprintf(stderr, "Worker error: Invalid params pos1=%d,pos2=%d,w1_start=%d,w1_end=%d\n",data->pos1,data->pos2,data->word1_start_idx,data->word1_end_idx); pthread_exit((void*)-1);
    }

    char candidate_list_temp[TOTAL_WORDS][MAX_WORD_LENGTH]; char mnemonic_str_temp[MAX_MNEMONIC_LENGTH];
    unsigned char seed[64]; HDNode root_node; uint32_t derivation_path[5]; HDNode child_node;
    unsigned char child_private_key[32]; unsigned char compressed_pubkey[33]; unsigned char uncompressed_pubkey[65];
    unsigned char ripemd160_hash_c[RIPEMD160_DIGEST_LENGTH]; unsigned char ripemd160_hash_unc[RIPEMD160_DIGEST_LENGTH];
    char p2pkh_address_c[TARGET_ADDRESS_MAX_LEN]; char p2pkh_address_unc[TARGET_ADDRESS_MAX_LEN];

    for (int word1_idx = data->word1_start_idx; word1_idx < data->word1_end_idx; ++word1_idx) {
        if (word1_idx % 16 == 0) { pthread_mutex_lock(data->found_flag_mutex_ptr); int f=*(data->found_flag_ptr); pthread_mutex_unlock(data->found_flag_mutex_ptr); if(f)pthread_exit(NULL); }
        for (int word2_idx = 0; word2_idx < BIP39_WORD_LIST_SIZE; ++word2_idx) {
            if (word2_idx % 128 == 0) { pthread_mutex_lock(data->found_flag_mutex_ptr); int f=*(data->found_flag_ptr); pthread_mutex_unlock(data->found_flag_mutex_ptr); if(f)pthread_exit(NULL); }
            int known_word_idx = 0; memset(mnemonic_str_temp, 0, MAX_MNEMONIC_LENGTH);
            strncpy(candidate_list_temp[data->pos1], data->bip39_word_list_ptr[word1_idx], MAX_WORD_LENGTH-1); candidate_list_temp[data->pos1][MAX_WORD_LENGTH-1]='\0';
            strncpy(candidate_list_temp[data->pos2], data->bip39_word_list_ptr[word2_idx], MAX_WORD_LENGTH-1); candidate_list_temp[data->pos2][MAX_WORD_LENGTH-1]='\0';
            for (int i=0; i<TOTAL_WORDS; ++i) {
                if (i==data->pos1 || i==data->pos2) continue;
                if (known_word_idx < NUM_KNOWN_WORDS) { strncpy(candidate_list_temp[i], data->known_words_perm[known_word_idx++], MAX_WORD_LENGTH-1); candidate_list_temp[i][MAX_WORD_LENGTH-1]='\0'; }
                else { pthread_exit((void*)-1); } // Should not happen
            }
            if (known_word_idx != NUM_KNOWN_WORDS) pthread_exit((void*)-1); // Should not happen
            for (int i=0; i<TOTAL_WORDS; ++i) {
                if(strlen(candidate_list_temp[i])==0) goto next_word2_iteration; // Should not happen
                strncat(mnemonic_str_temp, candidate_list_temp[i], strlen(candidate_list_temp[i]));
                if (i < TOTAL_WORDS - 1) strncat(mnemonic_str_temp, " ", 1);
            }
            if (c_mnemonic_check(mnemonic_str_temp)==0) continue;
            c_mnemonic_to_seed(mnemonic_str_temp, (data->passphrase_ptr ? data->passphrase_ptr : ""), seed);
            if (c_derive_hdnode_from_seed(seed, &root_node)==0) continue;
            for (int acc_num=0; acc_num<=1; ++acc_num) {
                for (int addr_idx=0; addr_idx<=9; ++addr_idx) {
                    derivation_path[0]=44|BIP32_HARDEN; derivation_path[1]=0|BIP32_HARDEN; derivation_path[2]=acc_num|BIP32_HARDEN; derivation_path[3]=0; derivation_path[4]=addr_idx;
                    if (c_derive_bip32_child_key(&root_node, derivation_path, 5, &child_node, child_private_key)==0) continue;
                    if (c_private_to_public_compressed(child_private_key, compressed_pubkey)) {
                        c_hash_public_key_to_ripemd160(compressed_pubkey, sizeof(compressed_pubkey), ripemd160_hash_c);
                        if (c_ripemd160_to_p2pkh_address(ripemd160_hash_c, 0x00, p2pkh_address_c, sizeof(p2pkh_address_c))) {
                            if (strncmp(p2pkh_address_c, data->target_address_ptr, TARGET_ADDRESS_MAX_LEN)==0) {
                                pthread_mutex_lock(data->found_flag_mutex_ptr); if(*(data->found_flag_ptr)==0){ *(data->found_flag_ptr)=1; strncpy(data->found_mnemonic_buffer_ptr, mnemonic_str_temp, MAX_MNEMONIC_LENGTH-1); data->found_mnemonic_buffer_ptr[MAX_MNEMONIC_LENGTH-1]='\0'; printf("!!! MNEMONIC FOUND (C): %s -> %s !!!\n", mnemonic_str_temp, p2pkh_address_c); } pthread_mutex_unlock(data->found_flag_mutex_ptr); pthread_exit(NULL);
                            }
                        }
                    }
                    if (c_private_to_public_uncompressed(child_private_key, uncompressed_pubkey)) {
                        c_hash_public_key_to_ripemd160(uncompressed_pubkey, sizeof(uncompressed_pubkey), ripemd160_hash_unc);
                        if (c_ripemd160_to_p2pkh_address(ripemd160_hash_unc, 0x00, p2pkh_address_unc, sizeof(p2pkh_address_unc))) {
                            if (strncmp(p2pkh_address_unc, data->target_address_ptr, TARGET_ADDRESS_MAX_LEN)==0) {
                                pthread_mutex_lock(data->found_flag_mutex_ptr); if(*(data->found_flag_ptr)==0){ *(data->found_flag_ptr)=1; strncpy(data->found_mnemonic_buffer_ptr, mnemonic_str_temp, MAX_MNEMONIC_LENGTH-1); data->found_mnemonic_buffer_ptr[MAX_MNEMONIC_LENGTH-1]='\0'; printf("!!! MNEMONIC FOUND (U): %s -> %s !!!\n", mnemonic_str_temp, p2pkh_address_unc); } pthread_mutex_unlock(data->found_flag_mutex_ptr); pthread_exit(NULL);
                            }
                        }
                    }
                    pthread_mutex_lock(data->found_flag_mutex_ptr); int f_in=*(data->found_flag_ptr); pthread_mutex_unlock(data->found_flag_mutex_ptr); if(f_in) pthread_exit(NULL);
                }
            }
            next_word2_iteration:;
        }
    }
    return NULL;
}

// --- Orchestration Callbacks & Main ---
void process_permutation_callback(char current_permuted_words[][MAX_WORD_LENGTH], int num_words_in_perm, void* user_data_perm_args) {
    permutation_callback_args_t* perm_args = (permutation_callback_args_t*)user_data_perm_args;
    main_orchestrator_data_t* orch_data = perm_args->orchestrator_data_ptr;
    pthread_mutex_lock(orch_data->found_flag_mutex_ptr); int is_already_found = *(orch_data->found_flag_ptr); pthread_mutex_unlock(orch_data->found_flag_mutex_ptr);
    if (is_already_found) return;

    int pos1 = perm_args->current_positions_ptr[0]; int pos2 = perm_args->current_positions_ptr[1];
    pthread_t threads[MAX_POSSIBLE_THREADS]; worker_args_t thread_args[MAX_POSSIBLE_THREADS];
    int current_num_cores = orch_data->num_cores;
    if (current_num_cores > MAX_POSSIBLE_THREADS) current_num_cores = MAX_POSSIBLE_THREADS;
    if (current_num_cores <= 0) current_num_cores = 1;

    int words_per_thread_for_w1 = (BIP39_WORD_LIST_SIZE > 0) ? (BIP39_WORD_LIST_SIZE / current_num_cores) : 0;
    if (words_per_thread_for_w1 == 0 && BIP39_WORD_LIST_SIZE > 0) words_per_thread_for_w1 = 1;

    for (int i = 0; i < current_num_cores; ++i) {
        thread_args[i].pos1 = pos1; thread_args[i].pos2 = pos2;
        memcpy(thread_args[i].known_words_perm, current_permuted_words, sizeof(char) * NUM_KNOWN_WORDS * MAX_WORD_LENGTH);
        if (BIP39_WORD_LIST_SIZE == 0) { thread_args[i].word1_start_idx = 0; thread_args[i].word1_end_idx = 0; }
        else {
            thread_args[i].word1_start_idx = i * words_per_thread_for_w1;
            thread_args[i].word1_end_idx = (i == current_num_cores - 1) ? BIP39_WORD_LIST_SIZE : (i + 1) * words_per_thread_for_w1;
            if (thread_args[i].word1_start_idx >= BIP39_WORD_LIST_SIZE) { thread_args[i].word1_start_idx = BIP39_WORD_LIST_SIZE; thread_args[i].word1_end_idx = BIP39_WORD_LIST_SIZE; }
        }
        thread_args[i].bip39_word_list_ptr = orch_data->bip39_word_list_ptr;
        thread_args[i].passphrase_ptr = orch_data->passphrase_ptr;
        thread_args[i].target_address_ptr = orch_data->target_address_ptr;
        thread_args[i].found_flag_mutex_ptr = orch_data->found_flag_mutex_ptr;
        thread_args[i].found_flag_ptr = orch_data->found_flag_ptr;
        thread_args[i].found_mnemonic_buffer_ptr = orch_data->found_mnemonic_buffer_ptr;
        threads[i] = 0;
        int rc = pthread_create(&threads[i], NULL, check_mnemonic_worker, &thread_args[i]);
        if (rc) { threads[i] = 0; } // Mark as not joinable
    }
    for (int i = 0; i < current_num_cores; ++i) { if (threads[i] != 0) pthread_join(threads[i], NULL); }

    (*(orch_data->total_permutations_processed_ptr))++;
    if ((*(orch_data->total_permutations_processed_ptr) % 10000 == 0) || (*(orch_data->total_permutations_processed_ptr) == 1 && current_num_cores >0) ) {
        pthread_mutex_lock(orch_data->found_flag_mutex_ptr); int cs = *(orch_data->found_flag_ptr); pthread_mutex_unlock(orch_data->found_flag_mutex_ptr);
        if (!cs) printf("Progress: Permutation group %ld (pos %d,%d). Still searching...\n", *(orch_data->total_permutations_processed_ptr), pos1, pos2);
    }
}

void process_combination_callback(const int* current_combination_indices, int k_selected_count, void* user_data_orchestrator) {
    main_orchestrator_data_t* orch_data = (main_orchestrator_data_t*)user_data_orchestrator;
    pthread_mutex_lock(orch_data->found_flag_mutex_ptr); int is_already_found = *(orch_data->found_flag_ptr); pthread_mutex_unlock(orch_data->found_flag_mutex_ptr);
    if (is_already_found) return;
    permutation_callback_args_t perm_args;
    perm_args.orchestrator_data_ptr = orch_data;
    perm_args.current_positions_ptr = current_combination_indices;
    generate_permutations((*(orch_data->known_words_array_ptr)), NUM_KNOWN_WORDS, process_permutation_callback, &perm_args);
}

// Test callbacks for generate_combinations/permutations if run in isolation
void print_combination_callback(const int* c, int k, void* u){ printf("Combo: "); for(int i=0;i<k;++i)printf("%d ",c[i]); if(u)printf("(%s)",(char*)u); printf("\n");}
void print_permutation_callback(char p[][MAX_WORD_LENGTH], int n, void* u){ printf("Perm: "); for(int i=0;i<n;++i)printf("%s ",p[i]); if(u)printf("(%s)",(char*)u); printf("\n");}


int main() {
    global_secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!global_secp256k1_ctx) { fprintf(stderr, "Failed to create secp256k1 context.\n"); return 1; }

    if (load_bip39_word_list("../english.txt", bip39_word_list, BIP39_WORD_LIST_SIZE) != BIP39_WORD_LIST_SIZE) {
        fprintf(stderr, "Failed to load BIP39 word list completely. Ensure 'english.txt' is present and correct.\n");
        secp256k1_context_destroy(global_secp256k1_ctx); return 1;
    }
    printf("BIP39 word list loaded (%d words).\n", BIP39_WORD_LIST_SIZE);

    if (pthread_mutex_init(&found_flag_mutex, NULL) != 0) {
        perror("Mutex init failed"); secp256k1_context_destroy(global_secp256k1_ctx); return 1;
    }
    found_mnemonic_buffer[0] = '\0'; found_flag = 0;

    const char* const known_words_input_arr[] = {"moon", "tower", "food", "this", "real", "subject", "address", "total", "ten", "black"};
    if (sizeof(known_words_input_arr)/sizeof(known_words_input_arr[0]) != NUM_KNOWN_WORDS) {
        fprintf(stderr, "Error: Mismatch in number of initialized known words (%zu) and NUM_KNOWN_WORDS constant (%d).\n", sizeof(known_words_input_arr)/sizeof(known_words_input_arr[0]), NUM_KNOWN_WORDS);
        secp256k1_context_destroy(global_secp256k1_ctx); pthread_mutex_destroy(&found_flag_mutex); return 1;
    }
    for (int i = 0; i < NUM_KNOWN_WORDS; ++i) {
        strncpy(known_words[i], known_words_input_arr[i], MAX_WORD_LENGTH - 1); known_words[i][MAX_WORD_LENGTH - 1] = '\0';
    }
    printf("Known words populated (%d words).\n", NUM_KNOWN_WORDS);

    strncpy(target_address, "1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ", TARGET_ADDRESS_MAX_LEN - 1); target_address[TARGET_ADDRESS_MAX_LEN - 1] = '\0';
    printf("Target address set: %s\n", target_address);
    strncpy(passphrase, "", PASSPHRASE_MAX_LEN - 1); passphrase[PASSPHRASE_MAX_LEN - 1] = '\0';
    printf("Passphrase set (empty).\n");

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc > 0) num_cores = (int)nproc;
    else { perror("sysconf(_SC_NPROCESSORS_ONLN) failed"); num_cores = 1; fprintf(stderr, "Defaulting to %d core.\n", num_cores); }
    printf("Using %d CPU cores for worker threads.\n", num_cores);

    main_orchestrator_data_t orchestrator_data;
    orchestrator_data.num_cores = num_cores;
    orchestrator_data.known_words_array_ptr = &known_words;
    orchestrator_data.bip39_word_list_ptr = (const char (*)[MAX_WORD_LENGTH])bip39_word_list;
    orchestrator_data.passphrase_ptr = passphrase;
    orchestrator_data.target_address_ptr = target_address;
    orchestrator_data.found_flag_mutex_ptr = &found_flag_mutex;
    orchestrator_data.found_flag_ptr = &found_flag;
    orchestrator_data.found_mnemonic_buffer_ptr = found_mnemonic_buffer;
    long permutations_counter = 0;
    orchestrator_data.total_permutations_processed_ptr = &permutations_counter;

    int k_missing_words = TOTAL_WORDS - NUM_KNOWN_WORDS;
    if (k_missing_words <= 0 || k_missing_words > TOTAL_WORDS ) {
        fprintf(stderr, "Error: Invalid number of missing words calculated: %d. (TOTAL_WORDS=%d, NUM_KNOWN_WORDS=%d)\n", k_missing_words, TOTAL_WORDS, NUM_KNOWN_WORDS);
        secp256k1_context_destroy(global_secp256k1_ctx); pthread_mutex_destroy(&found_flag_mutex); return 1;
    }

    printf("Starting search for %d missing words (TOTAL_WORDS=%d, NUM_KNOWN_WORDS=%d)...\n", k_missing_words, TOTAL_WORDS, NUM_KNOWN_WORDS);
    printf("Targeting address: %s\n", target_address);
    printf("Number of known words: %d. First known word: '%s'\n", NUM_KNOWN_WORDS, known_words[0]);
    printf("BIP39 wordlist size: %d. First word: '%s'\n", BIP39_WORD_LIST_SIZE, bip39_word_list[0]);
    printf("------------------------------------------------------------------\n");

    generate_combinations(TOTAL_WORDS, k_missing_words, process_combination_callback, &orchestrator_data);

    printf("------------------------------------------------------------------\n");
    if (found_flag) {
        printf("\n>>> Search finished. MNEMONIC FOUND: %s\n", found_mnemonic_buffer);
    } else {
        printf("\n>>> Search finished. Mnemonic not found after checking %ld permutation groups.\n", permutations_counter);
    }

    pthread_mutex_destroy(&found_flag_mutex);
    secp256k1_context_destroy(global_secp256k1_ctx);
    printf("Cleanup complete. Exiting.\n");
    return 0;
}
