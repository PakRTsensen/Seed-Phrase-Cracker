#include "bip39_utils.h"
#include "config.h" // Ensures globals are known (though accessed via extern from config.h)
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // For exit() in case of critical error, though returning error codes is preferred

int load_bip39_word_list(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Could not open BIP39 word list file: %s\n", filename);
        return FILE_NOT_FOUND_ERROR;
    }

    int count = 0;
    char line_buffer[MAX_WORD_LENGTH + 2]; // Buffer for line including newline and null terminator

    while (fgets(line_buffer, sizeof(line_buffer), file) != NULL && count < BIP39_WORD_LIST_SIZE) {
        // Remove newline character if present
        line_buffer[strcspn(line_buffer, "\r\n")] = 0;

        if (strlen(line_buffer) == 0) {
            continue; // Skip empty lines, though wordlist shouldn't have them
        }

        if (strlen(line_buffer) >= MAX_WORD_LENGTH) {
            fprintf(stderr, "Error: Word '%s' at line %d in %s exceeds MAX_WORD_LENGTH of %d\n",
                    line_buffer, count + 1, filename, MAX_WORD_LENGTH -1);
            fclose(file);
            return INVALID_FILE_FORMAT_ERROR;
        }
        strncpy(bip39_word_list[count], line_buffer, MAX_WORD_LENGTH);
        bip39_word_list[count][MAX_WORD_LENGTH - 1] = '\0'; // Ensure null termination
        count++;
    }

    fclose(file);

    if (count != BIP39_WORD_LIST_SIZE) {
        fprintf(stderr, "Error: Expected %d words in %s, but found %d words.\n",
                BIP39_WORD_LIST_SIZE, filename, count);
        return INVALID_FILE_FORMAT_ERROR;
    }

    printf("Successfully loaded %d words from %s.\n", count, filename);
    return SUCCESS;
}
