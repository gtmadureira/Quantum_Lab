# Example of how to generate Custom Mnemonic Phrase with Quantum Computing.
# For educational purposes only.
# Works on Python 3.6.13 or higher.
# Source: 'https://github.com/gtmadureira/Quantum_Lab/blob/main/quantum_mnemonic_seed_argon2.py'.
# What is Quantum Computing: 'https://gtmadureira.github.io/Quantum_Lab/index.html'.

import os
import sys
import qrng # Install this module so that IBM Quantum Computers can be accessed '$ pip install qrng'.
import argon2 # Need to install the Argon2 package '$ pip install argon2-cffi'.
import base64
import animation # Loading animation module '$ pip install animation'.
import unicodedata

# Checking the type of operating system to determine the clear function.
if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear') # On Linux/OS X system.
elif sys.platform == "win32":
    def clear(): os.system('cls') # On Windows system.

# Clean the terminal.
clear()

# Sets the loading animation.
wait = animation.Wait(animation = 'dots',
                      text = '[ Custom Mnemonic Phrase - Wait for the IBM Quantum Computing System to generate entropy ]',
                      color = 'cyan')

# Starts the loading animation.
wait.start()

def main():

    # Configuration of the Argon2 hash function.
    timeCost = 4 # 2 is the default value.
    memoryCost = 1048576 # 102400 is the default value.
    paraLLelism = 20 # 8 is the default value.

    # Hashing function using Argon2(*id* version) algorithm.
    def argon2id_hasher(password: bytes, salt: bytes, hashlen: int, suffix: int) -> str:
        encoded_hash = argon2.low_level.hash_secret(password, salt,
        time_cost = timeCost, memory_cost = memoryCost, parallelism = paraLLelism,
        hash_len = hashlen, type = argon2.low_level.Type.ID)
        encoded_hash = encoded_hash.decode("utf-8")
        hexhash = base64.b64decode(encoded_hash[-suffix:] + '===').hex()
        return (encoded_hash, hexhash)

    # Use this code below to save (or overwrite) the credential API Token.
    # Your API Token from 'https://quantum-computing.ibm.com/'.
    # Use 'YOUR_API_TOKEN_HERE' instead of "open('ibmq_api_token').read()" if you don't have it on file.
    qrng.IBMQ.save_account(open('ibmq_api_token').read(), overwrite = True)
    
    # ▲▲▲ or ▼▼▼

    # Your API Token from 'https://quantum-computing.ibm.com/'.
    # Use 'YOUR_API_TOKEN_HERE' instead of "open('ibmq_api_token').read()" if you don't have it on file.
    # qrng.set_provider_as_IBMQ(open('ibmq_api_token').read())

    # Load saved credential to access IBM Quantum Computing.
    qrng.IBMQ.load_account()
    
    # Use this code below to overwrite any API Token.
    # qrng.IBMQ.ibmq.save_account(open('ibmq_api_token').read(), overwrite = True)

    # Use 'simulator_statevector' for Quantum Simulator System. Faster!
    # Use 'ibmq_16_melbourne' for real Quantum Computer System. Slower!
    qrng.set_backend('simulator_statevector')

    # Get 64000 random bits for the data entropy;
    # Get 512 random bits for the hash salt;
    # through the IBM Quantum Computer System. 
    qbits_data = qrng.get_bit_string(64000)
    qbits_salt = qrng.get_bit_string(512)

    # Convert the bit string to integer.
    qbits_data_to_int = int("0b" + qbits_data, 2)
    qbits_salt_to_int = int("0b" + qbits_salt, 2)

    # Convert the integer to hex string.
    data_int_to_hex = hex(qbits_data_to_int)[2:].zfill(16000)
    salt_int_to_hex = hex(qbits_salt_to_int)[2:].zfill(128)

    # Convert the hex string to bytes.
    data_hex_to_bytes = bytes.fromhex(data_int_to_hex)
    salt_hex_to_bytes = bytes.fromhex(salt_int_to_hex)

    # Get binary entropy with checksum.
    entropy = argon2id_hasher(data_hex_to_bytes, salt_hex_to_bytes, 64, 86)
    entropyHashBytes = argon2id_hasher(bytes.fromhex(entropy[1]), salt_hex_to_bytes, 64, 86)
    checksum = '{:016b}'.format(int("0x" + entropyHashBytes[1][0:2], 16))
    binary_seed = ""

    for b in bytes.fromhex(entropy[1]):
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

    # Finishes the loading animation.
    wait.stop()

    # Clean the terminal.
    clear()

    # Print words.
    word_index = 0

    for value in chunks:
        word_index += 1
        a_print = print("Word " + '{: >2d}'.format(word_index) + ": " + value + " " + '{: >6d}'.format(int(value, 2)) + "  " + wordList[int(value, 2)])

    # Print as space delimited.
    mnemonic = []

    for value in chunks:
        mnemonic.append(wordList[int(value, 2)])

    b_print = print("\nCustom Seed Phrase:\n\n" + " ".join(mnemonic))

    # To Seed.
    mnemonic_phrase = " ".join(mnemonic)
    seed_extension_passphrase = ""
    normalized_mnemonic_phrase = unicodedata.normalize("NFKD", mnemonic_phrase)
    normalized_seed_extension_passphrase = unicodedata.normalize("NFKD", seed_extension_passphrase)
    prefixed_passphrase = "Hattori Hanzō" + normalized_seed_extension_passphrase
    encoded_mnemonic_phrase = normalized_mnemonic_phrase.encode("utf-8")
    encoded_passphrase = prefixed_passphrase.encode("utf-8")
    privkey = argon2id_hasher(encoded_mnemonic_phrase, encoded_passphrase, 64, 86)

    c_print = print("\n\nHash in encoded format (hashed by Argon2*id* version):\n\n" + privkey[0])
    d_print = print("\n\nPrivate Key:\n\n" + privkey[1].zfill(128).upper())

    return a_print, b_print, c_print, d_print

main()
