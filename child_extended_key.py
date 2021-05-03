import hashlib
import hmac

# secp256k1 domain parameters.
Pcurve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F # The proven prime.
Acurve = 0x0000000000000000000000000000000000000000000000000000000000000000 # These two values defines the elliptic curve.
Bcurve = 0x0000000000000000000000000000000000000000000000000000000000000007 # y^2 = x^3 + Acurve * x + Bcurve.
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 # This is the x coordinate of the generating point.
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 # This is the y coordinate of the generating point.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field.

def ModInv(a, n = Pcurve): # Extended euclidean algorithm/'division' in elliptic curves.
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECAdd(xp, yp, xq, yq): # Not true addition, invented for EC. It adds Point-P with Point-Q.
    m = ((yq - yp) * ModInv(xq - xp, Pcurve) % Pcurve)
    xr = (m * m - xp - xq) % Pcurve
    yr = (m * (xp - xr) - yp) % Pcurve
    return (xr, yr)

def ECDouble(xp, yp): # EC point doubling, invented for EC. It doubles Point-P.
    LamNumer = 3 * xp * xp + Acurve
    LamDenom = 2 * yp
    Lam = (LamNumer * ModInv(LamDenom, Pcurve)) % Pcurve
    xr = (Lam * Lam - 2 * xp) % Pcurve
    yr = (Lam * (xp - xr) - yp) % Pcurve
    return (xr, yr)

def ECMultiply(xs, ys, Scalar): # Double & Add. EC multiplication, not true multiplication.
    ScalarBin = str(bin(Scalar))[2:]
    Qx, Qy = xs, ys
    for i in range (1, len(ScalarBin)): # This is invented EC multiplication.
        Qx, Qy = ECDouble(Qx, Qy) # print "DUB", Qx; print.
        if ScalarBin[i] == "1":
            Qx, Qy = ECAdd(Qx, Qy, xs, ys) # print "ADD", Qx; print.
    return (Qx, Qy)

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')    

def extended_key_tree_bip44(private_key: str, chain_code: str) -> str:
        
    # Purpose    
    index = 2**31 + 44
    hmachash = hmac.new(bytes.fromhex(chain_code), bytes.fromhex(private_key) + int_to_bytes(index), hashlib.sha512).hexdigest().zfill(128).upper()
    scalar_add_mod = (int("0x" + private_key, 16) + int("0x" + hmachash[0:64], 16)) % N
    newkey_a = hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]

    # Coin Type
    index = 2**31 + 0
    hmachash = hmac.new(bytes.fromhex(newkey_a[64:]), bytes.fromhex("00" + newkey_a[0:64]) + int_to_bytes(index), hashlib.sha512).hexdigest().zfill(128).upper()
    scalar_add_mod = (int("0x00" + newkey_a[0:64], 16) + int("0x" + hmachash[0:64], 16)) % N
    newkey_b = hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]

    # Account
    index = 2**31 + 0
    hmachash = hmac.new(bytes.fromhex(newkey_b[64:]), bytes.fromhex("00" + newkey_b[0:64]) + int_to_bytes(index), hashlib.sha512).hexdigest().zfill(128).upper()
    scalar_add_mod = (int("0x00" + newkey_b[0:64], 16) + int("0x" + hmachash[0:64], 16)) % N
    newkey_c = hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]
    
    # Receiving or Change
    index = 0
    publicKey = ECMultiply(Gx, Gy, int("0x" + newkey_c[0:64], 16))

    if publicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
        pk = "03" + hex(publicKey[0])[2:].zfill(64).upper()
    else: # If the Y coordinate of the Public Key is even.
        pk = "02" + hex(publicKey[0])[2:].zfill(64).upper()
    
    hmachash = hmac.new(bytes.fromhex(newkey_c[64:]), bytes.fromhex(pk) + int_to_bytes(index), hashlib.sha512).hexdigest().zfill(128).upper()
    scalar_add_mod = (int("0x00" + newkey_c[0:64], 16) + int("0x" + hmachash[0:64], 16)) % N
    newkey_d = hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]

    # Address
    index = 0
    hmachash = hmac.new(bytes.fromhex(newkey_d[64:]), bytes.fromhex("00" + newkey_d[0:64]) + int_to_bytes(index), hashlib.sha512).hexdigest().zfill(128).upper()
    scalar_add_mod = (int("0x00" + newkey_d[0:64], 16) + int("0x" + hmachash[0:64], 16)) % N
    newkey_e = hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]
    
    return newkey_d[0:64]

       
p = "00C9F2850037E2793FA0B4B9F2A7271536C21B548482214725CEBCD64BAB544F1E"
c = "6285DB691D919D00B275061272C0B06DE75B5B6639FB8DE4D7E535CE9BFB0447"

print(extended_key_tree_bip44(p, c))
