import hashlib
import hmac
from Elliptic_Arithmetic import Point


# ECVRF Core Functions

def prove(secKey, alpha):
    # 1. Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
    (x, pubKey) = get_pubKey(secKey)

    # 2. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
    B = Point()
    H = hash_to_curve_try_and_increment(pubKey, alpha)

    # 3. h_string = point_to_string(H)
    h = point_to_string(H)

    # 4. Gamma = x*H
    G = H.mul(x)

    # 5. k = ECVRF_nonce_generation(SK, h_string)
    k = nonce_generartion(secKey, h)

    # 6. c = ECVRF_hash_points(H, Gamma, k*B, k*H)
    c = hash_point(H, G, B.mul(k), H.mul(k))

    # 7. s = (k + c*x) mod q
    s = (k + c * x) % ORDER

    # 8. pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
    pi = point_to_string(G) + int_to_string(c, 16) + int_to_string(s, 32)

    # 9. Output pi_string
    return pi


def proof_to_hash(pi):
    # 1. D = ECVRF_decode_proof(pi_string)AA
    D = decode_proof(pi)
    # 2. If D is "INVALID", output "INVALID" and stop
    if D == "INVALID":
        return "INVALID"
    # 3. (Gamma, c, s) = D
    (G, c, s) = D
    # 4. three_string = 0x03 = int_to_string(3, 1), a single octet with value 3
    t_string = bytes([0x03])
    # 5. beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
    beta_string = Hash(SUITE_STRING + t_string + point_to_string(G.mul(8)))
    # 6. Output beta_string
    return beta_string


def verify(pubKey, alpha, pi):
    D = decode_proof(pi)
    if D == "INVALID":
        return D
    (G, c, s) = D
    H = hash_to_curve_try_and_increment(pubKey, alpha)
    U = s * B - c * pubKey
    V = s * H - c * G
    hashed = hash_point(H, G, U, V)
    if c == hashed:
        return "VALID", proof_to_hash(pi)
    else:
        return "INVALID"


# ECVRF Auxiliary Functions
def decode_proof(pi):
    gamma = pi[0:32]
    c_string = pi[32:48]
    s_string = pi[48:]
    G = string_to_point(gamma)
    if G == "INVALID":
        return G
    c = int.from_bytes(c_string, 'little')
    s = int.from_bytes(s_string, 'little')
    return G, c, s


def get_pubKey(secKey):
    x = int.from_bytes(secKey, 'little')  # secret scalar
    point = Point()
    pubKey = point.mul(x)
    return x, pubKey


def hash_to_curve_try_and_increment(pubKey, alpha):
    # 1.ctr = 0
    ctr = 0
    # 2.PK_string = point_to_string(Y)
    PK_string = point_to_string(pubKey)
    # 3.one_string = 0x01 = int_to_string(1, 1), a single octet with value 1
    one_string = bytes([0x01])
    # 4.H = "INVALID"
    H = "INVALID"
    # 5.While H is "INVALID" or H is EC point at infinity:
    while H == "INVALID" or H.y == float('inf'):
        # A.ctr_string = int_to_string(ctr, 1)
        c_str = int_to_string(ctr, 1)
        # B.hash_string = Hash(suite_string | | one_string | | PK_string | | alpha_string | | ctr_string)
        h_string = Hash(SUITE_STRING + one_string + PK_string + alpha + c_str)  # concatenate
        # C.H = arbitrary_string_to_point(hash_string)
        H = arbitrary_string_to_point(h_string)
        # D.If H is not "INVALID" and cofactor > 1, set H = cofactor * H
        if H != "INVALID":
            H = H.mul(8)
        # E. ctr = ctr + 1
        ctr = ctr + 1
    return H


def hash_point(H, G, PB, PH):
    two_string = bytes([0x02])
    str = SUITE_STRING + two_string
    for p in [H, G, PB, PH]:
        str = str + point_to_string(p)
    c_string = Hash(str)
    truncated_string = c_string[0:16]
    c = int.from_bytes(truncated_string, 'little')
    return c


def nonce_generartion(SK, h_string):
    hash_data = Hash(h_string)
    V = 0x0101010101010101010101010101010101010101010101010101010101010101
    K = 0x0000000000000000000000000000000000000000000000000000000000000000
    K = hmac.HMAC(K, V + 0x00 + SK + hash_data).digest()
    V = hmac.HMAC(K, V).digest()
    K = hmac.HMAC(K, V + 0x01 + SK + hash_data).digest()
    V = hmac.HMAC(K, V).digest()
    T = 0x00
    while len(T) < 32:
        V = hmac.HMAC(K, V)
        T = T + V
        k = int(T, 2)
        if k < 32:
            return K
        else:
            K = hmac.HMAC(K, V + 0x00)
            V = hmac.HMAC(K, V)


def Hash(message):
    return hashlib.sha256(message).digest()


# TypeConversion Functions

def point_to_string(point):
    return encode_point(point)


def string_to_point(str):
    return decode_point(str)


def int_to_string(n, l):
    return int.to_bytes(n, l, 'little')


def hex_to_bytes(h):
    return bytes.fromhex(h)


def arbitrary_string_to_point(str):
    return string_to_point(bytes([0x02]) + str)



def encode_point(P):
    """Encode point to string containing LSB OF X followed by 254 bits of Y"""
    return ((P.y & ((1 << 255) - 1)) + ((P.x & 1) << 255)).to_bytes(32, 'little')


def decode_point(s):
    """Decode string containing LSB OF X followed by 254 bits of Y into point. Checks on-curve"""
    y = int.from_bytes(s, 'little') & ((1 << 255) - 1)
    x = inverse(y)  # case handling for modular
    # if x & 1 != int.from_bytes(s,'little')>>255): x = PRIME - x
    P = Point(x, y)  # check required for is_on_curve
    return P


def get_bit(s):
    b = int.from_bytes(s, 'little')
    return (b >> 255) & 0x01


def inverse(y):
    """y^2 mod PRIME  = x^3 + 7 mod PRIME"""
    n = y ** 2 - 7
    return n % PRIME


# Default Values
PRIME = 115792089237316195423570985008687907853269984665640564039457584007908834671663
ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337
SUITE_STRING = bytes([0xFE])
