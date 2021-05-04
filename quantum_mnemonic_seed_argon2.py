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
    def argon2id_hasher(password, salt, hashlen, suffix) -> str:
        encoded_hash = argon2.low_level.hash_secret(password, salt.encode('utf-8'),
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
    entropyHashBytes = argon2id_hasher(bytes.fromhex(entropy[1]), "Hattori Hanzō", 32, 43)
    checksum = '{:08b}'.format(int("0x" + entropyHashBytes[1][0:2], 16))
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

    # To SEED.
    mnemonic_phrase = " ".join(mnemonic)
    seed_extension_passphrase = ""
    normalized_mnemonic_phrase = unicodedata.normalize("NFKD", mnemonic_phrase)
    normalized_seed_extension_passphrase = unicodedata.normalize("NFKD", seed_extension_passphrase)
    prefixed_passphrase = "Hattori Hanzō" + normalized_seed_extension_passphrase
    encoded_mnemonic_phrase = normalized_mnemonic_phrase.encode("utf-8")
    privkey = argon2id_hasher(encoded_mnemonic_phrase, prefixed_passphrase, 32, 43)

    c_print = print("\n\nHash in encoded format (hashed by Argon2*id* version):\n\n" + privkey[0])
    d_print = print("\n\nPrivate Key:\n\n" + privkey[1].zfill(64).upper())

    return a_print, b_print, c_print, d_print

main()
