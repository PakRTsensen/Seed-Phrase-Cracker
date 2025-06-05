# BIP39 Mnemonic Cracker

This program attempts to find a 12-word BIP39 mnemonic phrase given 10 known words (in any order) and 2 missing words. It searches for a mnemonic that derives a specific target Bitcoin P2PKH address (compressed or uncompressed).

The program is written in C and is designed for speed and parallelism.

## Features

*   Searches for 2 missing words in a 12-word BIP39 mnemonic.
*   Accounts for random order of 10 known words.
*   Utilizes multi-threading to parallelize the search across available CPU cores.
*   Checks derivation paths: `m/44'/0'/account'/0/index` (for accounts 0-1, indexes 0-9).
*   Checks both compressed and uncompressed P2PKH addresses.

## Project Structure

```
bip39_cracker/
├── data/
│   └── english.txt       # BIP39 English word list (must contain 2048 words)
├── obj/                  # Object files (created during compilation)
├── lib/                  # required libraries
│   └── libbase58/        # implementation of base58 libary
│   └── crypto/           # trezor-firmware crypto libary
│   └── libsecp256k1/     # implementation of secp256k1
├── Makefile              # Build script
└── README.md             # This file
```

## Prerequisites

1.  **C Compiler**: A C compiler that supports C11 and pthreads (e.g., GCC).
2.  **BIP39 Word List**: A file named `english.txt` containing the 2048 official BIP39 English words, one word per line, must be placed in the `data/` directory. A sample is provided, but ensure it's complete for actual use.
3.  **Cryptographic Libraries (for full functionality)**:
    *   **OpenSSL (libcrypto)**: For SHA256 and RIPEMD160.
    *   **libsecp256k1**: For ECDSA operations (private key to public key).
    *   **A BIP39/BIP32 implementation**: parts of `trezor-firmware`
    *   **A Base58Check implementation**: Parts of `libbase58` or `trezor-crypto`

    The `Makefile` includes linker flags (`-lcrypto -lsecp256k1`) for some of these. You may need to adjust include paths and linker flags based on how these libraries are installed on your system. The current build will link against them if present but will use the placeholder functions from `crypto_utils.c`.

## Compilation

To compile the program, navigate to the `bip39_cracker` directory and run:

```bash
make
```

This will create an executable named `bip39_cracker` in the project root.

To clean build files:
```bash
make clean
```

The `Makefile` compiles with `-O2` optimization and `-g` for debugging symbols.

## Usage

To run the program:

```bash
./bip39_cracker [TARGET_BITCOIN_ADDRESS]
```

*   `[TARGET_BITCOIN_ADDRESS]` (optional): The P2PKH Bitcoin address you are searching for.

If no target address is provided as a command-line argument, the program will use a hardcoded test target address and a set of 10 known words from `src/main.c`.

**Example:**
```bash
./bip39_cracker 1M9XALBSj6YJ3K3kYNDL2vTfHSy5m7d58v
```

The program will then start searching and print progress updates. If a mnemonic is found, it will be printed along with the target address. Otherwise, it will indicate that no mnemonic was found after completing the search.

## Known Words Configuration

The 10 known words are currently hardcoded in `src/main.c` in the `initial_known_words` array. For a different search, you will need to modify this array in the source code and recompile.

## Important Note on Cryptographic Placeholders

As mentioned, the cryptographic functions in `src/crypto_utils.c` are **placeholders**. They return dummy data and do not perform real cryptographic operations. For the program to actually find correct mnemonics based on cryptographic hashes and derivations, these functions **must be replaced** with implementations that use real cryptographic libraries. The current version with placeholders is useful for testing the overall structure, multi-threading, and combinatorial logic of the application.

```
