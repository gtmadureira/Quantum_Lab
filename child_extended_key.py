import hashlib
import hmac

# Prefixed Private Key(first 32 bytes from Master Extended Private Key).
privkey = "00" + "47434D55FC2B0CA25923F677E5F44C7C48613F84E7798CFA75F257BE0FA96571"

# Index of purpose in derivation path.
index = 2**31 + 84

# The last 32 bytes from Master Extended Private Key.
chaincode = "5AFC13DF6A535008E6050AEDAB400D0A3FA53508B372F4054DFC1106E55186D0"

# Order of the curve(secp256k1).
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

hmachash = hmac.new(bytes.fromhex(chaincode), bytes.fromhex(privkey) + int_to_bytes(index), hashlib.sha512).hexdigest().zfill(128).upper()

scalar_add_mod = (int("0x" + privkey, 16) + int("0x" + hmachash[0:64], 16)) % N

newkey = hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]

print(newkey)
print(newkey[0:64])
