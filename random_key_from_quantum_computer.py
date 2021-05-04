import os
import sys
import qrng # Install this module so that IBM Quantum Computers can be accessed '$ pip install qrng'.
from hashlib import sha3_256, sha3_512
import animation # Loading animation module '$ pip install animation'.

# Checking the type of operating system to determine the clear function.
if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear') # On Linux/OS X system.
elif sys.platform == "win32":
    def clear(): os.system('cls') # On Windows system.

# Clean the terminal.
clear()

# Sets the loading animation.
wait = animation.Wait(animation = 'dots',
                      text = '[ Random Private Key - Wait for the IBM Quantum Computing System to generate entropy ]',
                      color = 'cyan')

# Starts the loading animation.
wait.start()

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

# Randomly generates a 256 bits private key, through a quantum process.
def key_256bits():
    
    bits = qrng.get_bit_string(15360)
    bits_to_int = int("0b" + bits, 2)
    int_to_hex = hex(bits_to_int)[2:].zfill(3840)
    hex_to_bytes = bytes.fromhex(int_to_hex)
    hash = sha3_256(hex_to_bytes).digest()
    key = hash.hex().zfill(64).upper()
    
    return key


# Randomly generates a 512 bits private key, through a quantum process.
def key_512bits():
    
    bits = qrng.get_bit_string(15360)
    bits_to_int = int("0b" + bits, 2)
    int_to_hex = hex(bits_to_int)[2:].zfill(3840)
    hex_to_bytes = bytes.fromhex(int_to_hex)
    hash = sha3_512(hex_to_bytes).digest()
    key = hash.hex().zfill(128).upper()
    
    return key


key256 = key_256bits()
key512 = key_512bits()

# Finishes the loading animation.
wait.stop()

# Clean the terminal.
clear()

print("This is a Random 256 bits Key from Quantum Computer:")
print()
print(key256)
print()
print()
print("This is a Random 512 bits Key from Quantum Computer:")
print()
print(key512)
