#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "config.h" // For SUCCESS, FAILURE, MAX_WORD_LENGTH etc.
#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// --- Hex Conversion ---
/**
 * @brief Converts a hexadecimal string to a byte array.
 * @param hex_str Input hexadecimal string.
 * @param byte_array Output byte array.
 * @param byte_array_len Maximum size of the output byte array.
 * @return The number of bytes written to byte_array, or -1 on error (e.g., invalid hex string).
 */
int hex_to_bytes(const char* hex_str, unsigned char* byte_array, size_t byte_array_len);

/**
 * @brief Converts a byte array to a hexadecimal string.
 * @param byte_array Input byte array.
 * @param byte_array_len Length of the input byte array.
 * @param hex_str Output hexadecimal string buffer.
 * @param hex_str_len Maximum size of the output hex string buffer (should be at least 2*byte_array_len + 1).
 */
void bytes_to_hex(const unsigned char* byte_array, size_t byte_array_len, char* hex_str, size_t hex_str_len);

// --- BIP39/BIP32 ---
/**
 * @brief Converts a mnemonic phrase to a seed using PBKDF2-HMAC-SHA512.
 *        This function should also implicitly validate the mnemonic's checksum.
 * @param mnemonic_phrase The BIP39 mnemonic phrase (space-separated words).
 * @param passphrase_str The optional passphrase.
 * @param seed_output_64_bytes Output buffer for the 64-byte seed.
 * @return SUCCESS or FAILURE.
 */
int mnemonic_to_seed(const char* mnemonic_phrase, const char* passphrase_str, unsigned char* seed_output_64_bytes);

/**
 * @brief Derives a private key using BIP32.
 *        Path: m / purpose' / coin_type' / account' / change / address_index
 * @param seed_64_bytes The 64-byte seed from mnemonic_to_seed.
 * @param purpose Purpose (e.g., 44 for BIP44).
 * @param coin_type Coin type (e.g., 0 for Bitcoin).
 * @param account Account number.
 * @param change 0 for external chain, 1 for internal (change).
 * @param address_index Address index.
 * @param out_priv_key_32_bytes Output buffer for the 32-byte derived private key.
 * @return SUCCESS or FAILURE.
 */
int bip32_derive_private_key(
    const unsigned char* seed_64_bytes,
    uint32_t purpose,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t address_index,
    unsigned char* out_priv_key_32_bytes
);

// --- ECDSA (secp256k1) ---
/**
 * @brief Converts a 32-byte private key to a 65-byte uncompressed public key.
 *        Format: 0x04 + X-coordinate (32 bytes) + Y-coordinate (32 bytes).
 * @param priv_key_bytes 32-byte private key.
 * @param pub_key_bytes_uncompressed Output buffer for the 65-byte uncompressed public key.
 * @return SUCCESS or FAILURE.
 */
int private_key_to_public_key_uncompressed(
    const unsigned char* priv_key_bytes,
    unsigned char* pub_key_bytes_uncompressed // Should be 65 bytes
);

/**
 * @brief Converts a 32-byte private key to a 33-byte compressed public key.
 *        Format: 0x02/0x03 + X-coordinate (32 bytes).
 * @param priv_key_bytes 32-byte private key.
 * @param pub_key_bytes_compressed Output buffer for the 33-byte compressed public key.
 * @return SUCCESS or FAILURE.
 */
int private_key_to_public_key_compressed(
    const unsigned char* priv_key_bytes,
    unsigned char* pub_key_bytes_compressed // Should be 33 bytes
);

// --- Hashing (OpenSSL) ---
/**
 * @brief Hashes a public key to a RIPEMD160 digest.
 *        Logic: RIPEMD160(SHA256(pub_key_bytes)).
 * @param pub_key_bytes Public key bytes (can be compressed or uncompressed).
 * @param pub_key_len Length of the public key.
 * @param ripemd160_hash_bytes Output buffer for the 20-byte RIPEMD160 hash.
 */
void hash_public_key_to_ripemd160(
    const unsigned char* pub_key_bytes,
    size_t pub_key_len,
    unsigned char* ripemd160_hash_bytes // Should be 20 bytes
);

// --- Address Encoding ---
/**
 * @brief Converts a 20-byte RIPEMD160 hash to a P2PKH Bitcoin address string.
 * @param ripemd160_hash_bytes 20-byte RIPEMD160 hash.
 * @param network_byte The network byte (e.g., 0x00 for Bitcoin mainnet).
 * @param out_address_str Output buffer for the P2PKH address string.
 *                        Ensure buffer is large enough (e.g., TARGET_ADDRESS_MAX_LEN).
 */
void ripemd160_to_p2pkh_address(
    const unsigned char* ripemd160_hash_bytes, // 20 bytes
    unsigned char network_byte,
    char* out_address_str
);

#endif // CRYPTO_UTILS_H
