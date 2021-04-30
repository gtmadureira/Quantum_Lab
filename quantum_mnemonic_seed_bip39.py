import os
import sys
import hmac
import qrng # Install this module so that IBM Quantum Computers can be accessed '$ pip install qrng'.
import argon2 # Need to install the Argon2 package '$ pip install argon2-cffi'.
import base64
import base58
import hashlib
import unicodedata

# Checking the type of operating system to determine the clear function.
if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear') # On Linux/OS X system.
elif sys.platform == "win32":
    def clear(): os.system('cls') # On Windows system.

# Clean the terminal.
clear()

def main():

    # Configuration of the Argon2 hash function.
    timeCost = 4 # 2 is the default value.
    memoryCost = 1048576 # 102400 is the default value.
    paraLLelism = 20 # 8 is the default value.

    # Hashing function using Argon2(*id* version) algorithm.
    def argon2id_hasher(password, salt, hashlen, suffix) -> str:
        encoded_hash = argon2.low_level.hash_secret(password, salt.encode('utf-8'),
                                            time_cost = timeCost, memory_cost = memoryCost, parallelism = paraLLelism,
                                            hash_len = hashlen, type = argon2.low_level.Type.ID)
        encoded_hash = encoded_hash.decode("utf-8")
        hexhash = base64.b64decode(encoded_hash[-suffix:] + '===').hex()
        return (encoded_hash, hexhash)

    # Your API Token from 'https://quantum-computing.ibm.com/'.
    qrng.set_provider_as_IBMQ(open('ibmq_api_token').read())

    # Clean the terminal.
    clear()

    # Use this code below to overwrite any API Token.
    # qrng.IBMQ.ibmq.save_account(open('ibmq_api_token').read(), overwrite = True)

    # Use 'simulator_statevector' for Quantum Simulator System. Faster!
    # Use 'ibmq_16_melbourne' for real Quantum Computer System. Slower!
    qrng.set_backend('simulator_statevector')

    # Get 64000 random bits for the initial entropy, through the IBM Quantum Computer System. 
    QBits = qrng.get_bit_string(64000)

    # Convert the bit string to integer.
    QBits_to_int = int("0b" + QBits, 2)

    # Convert the integer to hex string.
    int_to_hex = hex(QBits_to_int)[2:].zfill(16000)

    # Convert the hex string to bytes.
    hex_to_bytes = bytes.fromhex(int_to_hex)

    # Get binary entropy with checksum.
    entropy = argon2id_hasher(hex_to_bytes, "Hattori Hanzō", 32, 43)
    entropyHashBytes = hashlib.sha256(bytes.fromhex(entropy[1])).hexdigest()
    checksum = '{:08b}'.format(int("0x" + entropyHashBytes[0:2], 16))
    binary_seed = ""

    for b in bytearray.fromhex(entropy[1]):
        binary_seed = binary_seed + "{:08b}".format(b)

    binary_seed = binary_seed + checksum

    # English Word List.
    wordList = open('wordlist').read().splitlines()

    # Split up seed into 11 bit chunks.
    index = 0
    chunks = [""]

    for bit in range(0, len(binary_seed)):
        if bit % 11 == 0 and bit != 0:
            index += 1
            chunks.append("")
        chunks[index] += binary_seed[bit]

    # Print words.
    word_index = 0

    for value in chunks:
        word_index += 1
        a_print = print("Word " + '{: >2d}'.format(word_index) + ": " + value + " " + '{: >6d}'.format(int(value, 2)) + "  " + wordList[int(value, 2)])

    # Print as space delimited.
    mnemonic = []

    for value in chunks:
        mnemonic.append(wordList[int(value, 2)])

    b_print = print("\nBIP39 Seed Phrase:\n\n" + " ".join(mnemonic))

    # To SEED.
    mnemonic_phrase = " ".join(mnemonic)
    seed_extension_passphrase = ""
    normalized_mnemonic_phrase = unicodedata.normalize("NFKD", mnemonic_phrase)
    normalized_seed_extension_passphrase = unicodedata.normalize("NFKD", seed_extension_passphrase)
    prefixed_passphrase = "mnemonic" + normalized_seed_extension_passphrase
    encoded_mnemonic_phrase = normalized_mnemonic_phrase.encode("utf-8")
    encoded_passphrase = prefixed_passphrase.encode("utf-8")
    hex_seed = hashlib.pbkdf2_hmac("sha512", encoded_mnemonic_phrase, encoded_passphrase, 2048, 64).hex().zfill(64).upper()
    c_print = print("\n\nSEED:\n\n" + hex_seed)

    # To serialized key (master node).
    m_ext_key = hmac.new(b'Bitcoin seed', bytes.fromhex(hex_seed), hashlib.sha512).hexdigest().zfill(128).upper()
    version = "0488ADE4"
    depth = "00"
    fingerprint = "00000000"
    index = "00000000"
    chain_code = m_ext_key[64:]
    private_key = "00" + m_ext_key[0:64]
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(version + depth + fingerprint + index + chain_code + private_key)).digest()).hexdigest().zfill(64).upper()[0:8]
    serialized = base58.b58encode(bytes.fromhex(version + depth + fingerprint + index + chain_code + private_key + checksum))
    d_print = print("\n\nMaster Node (root key):\n\n" + serialized.decode("utf-8"))

    return a_print, b_print, c_print, d_print

main()
