import os
import sys
import qrng # Install this module so that IBM Quantum Computers can be accessed '$ pip install qrng'.
from hashlib import sha3_256, sha3_512

# Checking the type of operating system.
if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear') # On Linux/OS X system.
elif sys.platform == "win32":
    def clear(): os.system('cls') # On Windows system.

clear() # Clean the terminal.

qrng.set_provider_as_IBMQ('YOUR_IBMQ_TOKEN_HERE') # Your API Token from 'https://quantum-computing.ibm.com/'.

# qrng.IBMQ.ibmq.save_account('YOUR_IBMQ_TOKEN_HERE', overwrite = True) <- Use this to overwrite any API Token.

qrng.set_backend('simulator_statevector')   # Use 'simulator_statevector' for Quantum Simulator System. Faster!
                                            # Use 'ibmq_16_melbourne' for real Quantum Computer System. Slower!
clear()


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

print("This is a Random 256 bits Key from Quantum Computer:")
print()
print(key256)
print()
print()
print()
print("This is a Random 512 bits Key from Quantum Computer:")
print()
print(key512)
