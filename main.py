from bip32utils import BIP32Key
from bip32utils import BIP32_HARDEN
# from bip32utils import Base58 # Base58 is imported from base58 library later
import os, bip39
import multiprocessing
import itertools
import math
    
import codecs
import hashlib
import ecdsa
import base58

def pk_to_hash_unc_p2pkh(priv_key): 
    private_key_bytes = codecs.decode(priv_key, 'hex')
        # Get ECDSA public key (paired to given private key)
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
        # Add bitcoin byte '04' that denote UNCOMPRESSED public key
    bitcoin_byte = b'04'
    public_key = bitcoin_byte + key_hex
        # Compute the hash: public key bytes -> sha256 -> RIPEMD160
    public_key_bytes = codecs.decode(public_key, 'hex')
            # Run SHA256 for the public key
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
            # Run ripemd160 for the SHA256
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        # Return RIPEMD160 hash
    return ripemd160_bpk_hex

    # Logic is same, but the public key is COMPRESSED: 
    # used only 32 bytes of the public key with "bitcoin code" set to
    # '03' or '02' based on the sign of the other unused 32 bytes
def pk_to_hash_c_p2pkh(priv_key):
    private_key_bytes = codecs.decode(priv_key, 'hex')

    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    
    if key_bytes[-1] & 1:
        bitcoin_byte = b'03'
    else:
        bitcoin_byte = b'02'
            
    key_bytes =  key_bytes[0:32]    
    key_hex = codecs.encode(key_bytes, 'hex')

    public_key = bitcoin_byte + key_hex

    public_key_bytes = codecs.decode(public_key, 'hex')
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')  
      
    return ripemd160_bpk_hex

def rp160hash_to_p2pkhAddress(rp160hash):
            # Add network byte
    network_byte = b'00'
    network_bitcoin_public_key = network_byte + rp160hash
    network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
            # Double SHA256 to get checksum
    sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = sha256_2_hex[:8]
            # Concatenate public key and checksum to get the address
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    #address = BTC_operations.base58(address_hex)
    address = base58.b58encode(bytes(bytearray.fromhex(address_hex))).decode('utf-8')
    return address

# Worker function to check a mnemonic candidate constructed from known words permutation and two trial words at specific positions
def check_mnemonic_candidate(args):
    pos1, pos2, known_words_perm, word1_idx, word2_idx, bip39_list, passphrase, target_address = args

    word1 = bip39_list[word1_idx]
    word2 = bip39_list[word2_idx]

    # Build the 12-word candidate list
    candidate_list = [None] * 12
    candidate_list[pos1] = word1
    candidate_list[pos2] = word2

    # Fill the remaining slots with the known words permutation
    perm_iter = iter(known_words_perm)
    for i in range(12):
        if candidate_list[i] is None:
            try:
                candidate_list[i] = next(perm_iter)
            except StopIteration:
                # Should not happen if logic is correct (10 known words, 10 slots)
                print(f"Error: StopIteration while filling mnemonic slots. Pos: {pos1},{pos2}. Perm: {known_words_perm}")
                return None # Error case

    mnemonic_candidate = " ".join(candidate_list)

    try:
        # Validate checksum first (optional but can save computation)
        # bip39.phrase_to_seed will raise ValueError if checksum is bad
        seed = bip39.phrase_to_seed(mnemonic_candidate, passphrase=passphrase)
        key = BIP32Key.fromEntropy(seed)
        # Check first two accounts (standard practice)
        for account_number in range(0, 2):
            # Check first 10 addresses per account (common range)
            for i in range(0, 10):
                pk = key.ChildKey(44 + BIP32_HARDEN).ChildKey(0 + BIP32_HARDEN).ChildKey(account_number + BIP32_HARDEN).ChildKey(0).ChildKey(i).PrivateKey().hex()
                # Check both compressed and uncompressed P2PKH addresses
                if rp160hash_to_p2pkhAddress(pk_to_hash_c_p2pkh(pk)) == target_address or \
                   rp160hash_to_p2pkhAddress(pk_to_hash_unc_p2pkh(pk)) == target_address:
                    return mnemonic_candidate # Found!
    except ValueError:
        # Ignore invalid checksum errors from bip39.phrase_to_seed
        pass
    except Exception as ex:
        # Optionally log other unexpected errors
        # print(f"Error checking {mnemonic_candidate}: {ex}")
        pass
    return None # Not found for this combination

# Main execution block
if __name__ == "__main__":
    # Read the BIP39 seed word list
    try:
        with open('english.txt') as f:
            bip39_list = f.readlines()
        bip39_list = [w.strip('\n') for w in bip39_list]
        if len(bip39_list) != 2048:
             print(f"Warning: Expected 2048 words in english.txt, but found {len(bip39_list)}.")
    except FileNotFoundError:
        print("Error: english.txt not found. Please ensure the BIP39 word list is in the same directory.")
        exit(1)
    
    passphrase = '' # BIP39 passphrase (optional, default is empty)
    # The 10 known words (order doesn't matter here, will be permuted)
    known_words_input = 'moon tower food this real subject address total ten black'
    target_address = '1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ' # The target Bitcoin address
    
    known_words = known_words_input.split()
    num_known_words = len(known_words)
    if num_known_words != 10:
        print(f"Error: Expected 10 known words, but got {num_known_words}.")
        exit(1)
    
    num_bip39_words = len(bip39_list)
    total_word_pair_combinations = num_bip39_words * num_bip39_words
    num_known_word_permutations = math.factorial(num_known_words)
    num_missing_word_positions = math.comb(12, 2) # 12 choose 2 = 66
    
    total_combinations_overall = num_missing_word_positions * num_known_word_permutations * total_word_pair_combinations
    
    num_cores = multiprocessing.cpu_count()
    print(f"Starting search for target address: {target_address}")
    print(f"Known words: {' '.join(known_words)}")
    print(f"Number of possible position pairs for missing words: {num_missing_word_positions:,}")
    print(f"Number of permutations for the {num_known_words} known words: {num_known_word_permutations:,}")
    print(f"Number of combinations for the 2 missing words: {total_word_pair_combinations:,}")
    print(f"Total combinations to check overall: {total_combinations_overall:,} (approx {total_combinations_overall:.2e})")
    print(f"Using {num_cores} CPU cores...")
    
    found_mnemonic = None
    position_pair_count = 0
    overall_checked_count = 0 # For potentially very long runs, track overall progress
    
    # Outermost loop: Iterate through all possible pairs of positions for the missing words
    for positions in itertools.combinations(range(12), 2):
        pos1, pos2 = positions
        position_pair_count += 1
        print(f"\n=== Testing Position Pair {position_pair_count} / {num_missing_word_positions}: Missing words at index {pos1} and {pos2} ===")
    
        permutation_count = 0
        # Middle loop: Iterate through all permutations of the known words
        for perm_tuple in itertools.permutations(known_words):
            permutation_count += 1
            # Optional: Print permutation being tested if needed for detailed debugging, but can be very verbose
            # print(f"  --- Testing Permutation {permutation_count} / {num_known_word_permutations} ---")
    
            # Prepare arguments for the worker function for the current position pair and permutation
            args_list = [(pos1, pos2, perm_tuple, j, k, bip39_list, passphrase, target_address)
                         for j in range(num_bip39_words) for k in range(num_bip39_words)]
    
            completed_tasks_this_perm = 0
            # Use a multiprocessing Pool for the innermost loop (checking word pairs)
            # Adjust chunksize based on performance testing
            chunk_size = max(1, min(1000, total_word_pair_combinations // (num_cores * 10)))
    
            try:
                with multiprocessing.Pool(processes=num_cores) as pool:
                    # Use imap_unordered for responsiveness
                    results = pool.imap_unordered(check_mnemonic_candidate, args_list, chunksize=chunk_size)
    
                    # Initial progress print for this permutation
                    print(f"\rPos {position_pair_count}/{num_missing_word_positions} | Perm {permutation_count}/{num_known_word_permutations} | Progress: 0.00%", end="")
    
                    for result in results:
                        completed_tasks_this_perm += 1
                        overall_checked_count += 1
                        if result:
                            found_mnemonic = result
                            # Clear line and print FOUND message
                            print(f"\r{' ' * 100}\rFOUND: {found_mnemonic}")
                            pool.terminate()
                            pool.join()
                            break # Exit inner results loop
    
                        # Update progress periodically
                        if completed_tasks_this_perm % (chunk_size * num_cores // 4) == 0 or completed_tasks_this_perm == total_word_pair_combinations:
                            progress_perm = (completed_tasks_this_perm / total_word_pair_combinations) * 100
                            # Use \r to overwrite progress line
                            print(f"\rPos {position_pair_count}/{num_missing_word_positions} | Perm {permutation_count}/{num_known_word_permutations} | Progress: {progress_perm:.2f}% ({completed_tasks_this_perm:,}/{total_word_pair_combinations:,})", end="")
    
                # If found in the inner loop, break the middle permutation loop
                if found_mnemonic:
                    break
    
            except KeyboardInterrupt:
                print("\nSearch interrupted by user.")
                found_mnemonic = "INTERRUPTED"
                break # Exit middle loop
            except Exception as e:
                print(f"\nAn unexpected error occurred during Pos {position_pair_count}, Perm {permutation_count}: {e}")
                found_mnemonic = "ERROR"
                break # Exit middle loop
    
            # Clear the progress line for the completed permutation if nothing was found yet
            print(f"\r{' ' * 100}\r", end="")
    
        # If found or interrupted/error in the middle loop, break the outer position loop as well
        if found_mnemonic:
            break
    
    # Final status message
    print(f"\n{'='*20} Search Finished {'='*20}")
    if found_mnemonic and found_mnemonic not in ["INTERRUPTED", "ERROR"]:
        print(f"Mnemonic found after checking approx {overall_checked_count:,} combinations:")
        print(f"-> {found_mnemonic}")
    elif found_mnemonic == "INTERRUPTED":
         print(f"Search was interrupted by user after checking approx {overall_checked_count:,} combinations.")
    elif found_mnemonic == "ERROR":
         print(f"Search stopped due to an error after checking approx {overall_checked_count:,} combinations.")
    else:
        print(f"Mnemonic not found after checking all {total_combinations_overall:,} combinations.")
        print(f"(Checked across {num_missing_word_positions} position pairs and {num_known_word_permutations} permutations per pair).")


