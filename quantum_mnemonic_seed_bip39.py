import os
import sys
import hmac
import qrng # Install this module so that IBM Quantum Computers can be accessed '$ pip install qrng'.
import argon2 # Need to install the Argon2 package '$ pip install argon2-cffi'.
import base64
import base58
import hashlib
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
                      text = '[ BIP39 Mnemonic Phrase - Wait for the IBM Quantum Computing System to generate entropy ]',
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
    entropy = argon2id_hasher(data_hex_to_bytes, salt_hex_to_bytes, 32, 43)
    entropyHashBytes = hashlib.sha256(bytes.fromhex(entropy[1])).hexdigest()
    checksum = '{:08b}'.format(int("0x" + entropyHashBytes[0:2], 16))
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

    b_print = print("\n\nBIP39 - Mnemonic Phrase:\n\n" + " ".join(mnemonic))

    # To SEED.
    mnemonic_phrase = " ".join(mnemonic)
    seed_extension_passphrase = ""
    normalized_mnemonic_phrase = unicodedata.normalize("NFKD", mnemonic_phrase)
    normalized_seed_extension_passphrase = unicodedata.normalize("NFKD", seed_extension_passphrase)
    prefixed_passphrase = "mnemonic" + normalized_seed_extension_passphrase
    encoded_mnemonic_phrase = normalized_mnemonic_phrase.encode("utf-8")
    encoded_passphrase = prefixed_passphrase.encode("utf-8")
    hex_seed = hashlib.pbkdf2_hmac("sha512", encoded_mnemonic_phrase, encoded_passphrase, 2048, 64).hex().zfill(64).upper()
    c_print = print("\n\nBIP39 - Master Seed:\n\n" + hex_seed)

    # Preparing serialized key (master node).
    m_ext_key = hmac.new(b'Bitcoin seed', bytes.fromhex(hex_seed), hashlib.sha512).hexdigest().zfill(128).upper()
    m_print = print("\n\nNon-Serialized Master Node (Root Extended Private Key):\n\n" + m_ext_key)
    version_bip44 = "0488ADE4"
    version_bip49 = "049D7878"
    version_bip84 = "04B2430C"
    depth = "00"
    fingerprint = "00000000"
    index = "00000000"
    chain_code = m_ext_key[64:]
    private_key = "00" + m_ext_key[0:64]

    # Serialized BIP32-BIP44
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(version_bip44 + depth + fingerprint + index + chain_code + private_key)).digest()).hexdigest().zfill(64).upper()[0:8]
    serialized = base58.b58encode(bytes.fromhex(version_bip44 + depth + fingerprint + index + chain_code + private_key + checksum))
    d_print = print("\n\nSerialized Master Node (Root Extended Private Key on BIP32-BIP44):\n\n" + serialized.decode("utf-8"))

    # Serialized BIP49-BIP141
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(version_bip49 + depth + fingerprint + index + chain_code + private_key)).digest()).hexdigest().zfill(64).upper()[0:8]
    serialized = base58.b58encode(bytes.fromhex(version_bip49 + depth + fingerprint + index + chain_code + private_key + checksum))
    e_print = print("\n\nSerialized Master Node (Root Extended Private Key on BIP49-BIP141):\n\n" + serialized.decode("utf-8"))

    # Serialized BIP84
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(version_bip84 + depth + fingerprint + index + chain_code + private_key)).digest()).hexdigest().zfill(64).upper()[0:8]
    serialized = base58.b58encode(bytes.fromhex(version_bip84 + depth + fingerprint + index + chain_code + private_key + checksum))
    f_print = print("\n\nSerialized Master Node (Root Extended Private Key on BIP84):\n\n" + serialized.decode("utf-8"))

    return a_print, b_print, c_print, m_print, d_print, e_print, f_print

main()
