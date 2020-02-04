# Copyright (C) 2020 Eric Schorn <eschorn@integritychain.com>
#
# This program is free software; you can redistribute it and/or modify it under the terms
# of the GNU General Public License version 3 as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.


#
# A self-contained Python 3 reference implementation of draft-irtf-cfrg-vrf-05
# corresponding to the ECVRF-EDWARDS25519-SHA512-Elligator2 cipher suite configuration.
# This code is suitable for demonstration, porting and the generation of test vectors.
# However, it is inefficient and not fully secure (e.g. not side-channel resistant, no
# memory scrubbing etc), so should not be used in production. This file retains a
# significant amount of documentation extracted from the specification as comments.
# Section 5.6.1 ECVRF_validate_key is not yet implemented.
# See https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05.pdf
#
# Significant portions of the lower-level ed25519-related code was adapted from that
# provided in Appendix A of RFC 8032 at https://tools.ietf.org/pdf/rfc8032.pdf. The
# optional test_dict dictionary has no functional impact (strictly for test). Variable
# naming is largely kept consistent with the documentation source despite PEP 8.
#


import hashlib  # Python 3 standard library

# Public API

# Section 5.1. ECVRF Proving
def ecvrf_prove(SK, alpha_string, test_dict=None):
    """
    Input:
        SK - VRF private key
        alpha_string - input alpha, an octet string
        test_dict - optional dict of samples to assert and/or record
    Output:
        pi_string - VRF proof, octet string of length ptLen+n+qLen
        If a test_dict is supplied, one will be returned
    """
    # 1. Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
    #    (this derivation depends on the ciphersuite, as per Section 5.5; these values can
    #    be cached, for example, after key generation, and need not be rederived each time)
    secret_scalar, public_key = _get_secret_scalar_and_public_key(SK)  # ANOMALY: need key API?
    test_dict = _assert_and_sample(test_dict, 'secret_scalar', secret_scalar)
    test_dict = _assert_and_sample(test_dict, 'public_key', public_key)

    # 2. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
    H, test_dict = _ecvrf_hash_to_curve_elligator2_25519(SUITE_STRING, public_key, alpha_string, test_dict)
    test_dict = _assert_and_sample(test_dict, 'H', H)

    # 3. h_string = point_to_string(H)
    h_string = _decode_point(H)  # ANOMALY: H-point vs H_string?

    # 4. Gamma = x*H
    Gamma = _scalar_multiply(P=h_string, e=secret_scalar)

    # 5. k = ECVRF_nonce_generation(SK, h_string)
    k, test_dict = _ecvrf_nonce_generation_rfc8032(SK, H, test_dict)

    # 6. c = ECVRF_hash_points(H, Gamma, k*B, k*H)
    kB = _scalar_multiply(P=BASE, e=k)
    kH = _scalar_multiply(P=h_string, e=k)
    c, test_dict = _ecvrf_hash_points(h_string, Gamma, kB, kH, test_dict)
    test_dict = _assert_and_sample(test_dict, 'kB', _encode_point(kB))
    test_dict = _assert_and_sample(test_dict, 'kH', _encode_point(kH))

    # 7. s = (k + c*x) mod q
    s = (k + c * secret_scalar) % ORDER

    # 8. pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
    pi_string = _encode_point(Gamma) + int.to_bytes(c, 16, 'little') + int.to_bytes(s, 32, 'little')
    test_dict = _assert_and_sample(test_dict, 'pi_string', pi_string)

    # 9. Output pi_string
    if test_dict: return pi_string, test_dict
    else: return pi_string


# Section 5.2. ECVRF Proof To Hash
def ecvrf_proof_to_hash(pi_string, test_dict=None):
    """
    Input:
        pi_string - VRF proof, octet string of length ptLen+n+qLen
        test_dict - optional dict of samples to assert and/or record
    Output:
        "INVALID", or beta_string - VRF hash output, octet string of length hLen
        If a test_dict is supplied, one will be returned
    Important note:
        ECVRF_proof_to_hash should be run only on pi_string that is known to have been
        produced by ECVRF_prove, or from within ECVRF_verify as specified in Section 5.3.
    """
    # 1. D = ECVRF_decode_proof(pi_string)
    D, test_dict = _ecvrf_decode_proof(pi_string, test_dict)

    # 2. If D is "INVALID", output "INVALID" and stop
    if D == "INVALID": return "INVALID"

    # 3. (Gamma, c, s) = D
    Gamma, c, s = D

    # 4. three_string = 0x03 = int_to_string(3, 1), a single octet with value 3
    three_string = bytes([0x03])

    # 5. beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
    cofactor_gamma = _scalar_multiply(P=Gamma, e=8)
    beta_string = _hash(SUITE_STRING + three_string + _encode_point(cofactor_gamma))
    test_dict = _assert_and_sample(test_dict, 'beta_string', beta_string)

    # 6. Output beta_string
    if test_dict: return beta_string, test_dict
    else: return beta_string


# Section 5.3. ECVRF Verifying
def ecvrf_verify(Y, pi_string, alpha_string, test_dict=None):
    """
    Input:
        Y - public key, an EC point
        pi_string - VRF proof, octet string of length ptLen+n+qLen
        alpha_string - VRF input, octet string
        test_dict - optional dict of samples to assert and/or record
    Output:
        ("VALID", beta_string), where beta_string is the VRF hash output, octet string
        of length hLen; or "INVALID"
        If a test_dict is supplied, one will be returned
    """
    # 1. D = ECVRF_decode_proof(pi_string)
    D, test_dict = _ecvrf_decode_proof(pi_string, test_dict)

    # 2. If D is "INVALID", output "INVALID" and stop
    if D == "INVALID": return "INVALID"

    # 3. (Gamma, c, s) = D
    Gamma, c, s = D

    # 4. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
    H, test_dict = _ecvrf_hash_to_curve_elligator2_25519(SUITE_STRING, Y, alpha_string, test_dict)
    test_dict = _assert_and_sample(test_dict, 'H', H)

    # 5. U = s*B - c*Y
    sB = _scalar_multiply(P=BASE, e=s)
    Y_point = _decode_point(Y)
    cY = _scalar_multiply(P=Y_point, e=c)
    ncY = [cY[0], PRIME - cY[1]]
    U = _edwards_add(sB, ncY)
    nU = [PRIME - U[0], PRIME - U[1]]  # ANOMALY: Extraneous negation (nV too)
    test_dict = _assert_and_sample(test_dict, 'U', _encode_point(nU))

    # 6. V = s*H - c*Gamma
    sH = _scalar_multiply(P=_decode_point(H), e=s)
    cG = _scalar_multiply(P=Gamma, e=c)
    ncG = [cG[0], PRIME - cG[1]]
    V = _edwards_add(ncG, sH)
    nV = [PRIME - V[0], PRIME - V[1]]
    test_dict = _assert_and_sample(test_dict, 'V', _encode_point(nV))

    # 7. c’ = ECVRF_hash_points(H, Gamma, U, V)
    cp, test_dict = _ecvrf_hash_points(_decode_point(H), Gamma, nU, nV, test_dict)

    # 8. If c and c’ are equal, output ("VALID", ECVRF_proof_to_hash(pi_string)); else output "INVALID"
    result = "VALID" if c == cp else "INVALID"
    if test_dict: return result, test_dict
    else: return result


# Internal functions

# Section 5.4.1.2. ECVRF_hash_to_curve_elligator2_25519
def _ecvrf_hash_to_curve_elligator2_25519(suite_string, Y, alpha_string, test_dict=None):
    """
    Input:
        suite_string - a single octet specifying ECVRF ciphersuite.
        alpha_string - value to be hashed, an octet string
        Y - public key, an EC point
        test_dict - optional dict of samples to assert and/or record
    Output:
        H - hashed value, a finite EC point in G
        Test_dict passes from input to output with optional assert/record
    Fixed options:
        p = 2^255-19, the size of the finite field F, a prime, for edwards25519 and curve25519 curves
        A = 486662, Montgomery curve constant for curve25519
        cofactor = 8, the cofactor for edwards25519 and curve25519 curves
    """
    assert suite_string == SUITE_STRING
    # 1. PK_string = point_to_string(Y)
    # 2. one_string = 0x01 = int_to_string(1, 1) (a single octet with value 1)
    one_string = bytes([0x01])

    # 3. hash_string = Hash(suite_string || one_string || PK_string || alpha_string )
    hash_string = _hash(suite_string + one_string + Y + alpha_string)

    # 4. truncated_h_string = hash_string[0]...hash_string[31]
    truncated_h_string = bytearray(hash_string[0:32])

    # 5. oneTwentySeven_string = 0x7F = int_to_string(127, 1) (a single octet with value 127)
    oneTwentySeven_string = 0x7f

    # 6. truncated_h_string[31] = truncated_h_string[31] & oneTwentySeven_string (this step clears the high-order bit of octet 31)
    truncated_h_string[31] = int(truncated_h_string[31] & oneTwentySeven_string)

    # 7. r = string_to_int(truncated_h_string)
    r = int.from_bytes(truncated_h_string, 'little')
    test_dict = _assert_and_sample(test_dict, 'r', truncated_h_string)

    # 8. u = - A / (1 + 2*(r^2) ) mod p (note: the inverse of (1+2*(r^2)) modulo p is guaranteed to exist)
    u = (PRIME - A) * _inverse(1 + 2 * (r ** 2)) % PRIME

    # 9. w = u * (u^2 + A*u + 1) mod p (this step evaluates the Montgomery equation for Curve25519)
    w = u * (u**2 + A * u + 1) % PRIME
    test_dict = _assert_and_sample(test_dict, 'w', int.to_bytes(w, 32, 'little'))

    # 10. Let e equal the Legendre symbol of w and p (see note below on how to compute e)
    e = pow(w, (PRIME - 1) // 2, PRIME)
    test_dict = _assert_and_sample(test_dict, 'e', int.to_bytes(e, 32, 'little'))

    # 11. If e is equal to 1 then final_u = u; else final_u = (-A - u) mod p
    #     (note: final_u is the Montgomery u-coordinate of the output; see  note below on how to compute it)
    final_u = (e * u + (e - 1) * A * TWO_INV) % PRIME

    # 12. y_coordinate = (final_u - 1) / (final_u + 1) mod p
    #     (note 1: y_coordinate is the Edwards coordinate corresponding to final_u)
    #     (note 2: the inverse of (final_u + 1) modulo p is guaranteed to exist)
    y_coordinate = (final_u - 1) * _inverse(final_u + 1) % PRIME

    # 13. h_string = int_to_string (y_coordinate, 32)
    h_string = int.to_bytes(y_coordinate, 32, 'little')

    # 14. H_prelim = string_to_point(h_string) (note: string_to_point will not return INVALID by correctness of Elligator2)
    H_prelim = _decode_point(h_string)

    # 15. Set H = cofactor * H_prelim
    H = _scalar_multiply(P=H_prelim, e=8)

    # 16. Output H
    H_point = _encode_point(H)
    return H_point, test_dict


# 5.4.2.2. ECVRF Nonce Generation From RFC 8032
def _ecvrf_nonce_generation_rfc8032(SK, h_string, test_dict=None):
    """
    Input:
        SK - an ECVRF secret key
        h_string - an octet string
        test_dict - optional dict of samples to assert and/or record
    Output:
        k - an integer between 0 and q-1
        Test_dict passes from input to output with optional assert/record
    """
    # 1. hashed_sk_string = Hash (SK)
    hashed_sk_string = _hash(SK)

    # 2. truncated_hashed_sk_string = hashed_sk_string[32]...hashed_sk_string[63]
    truncated_hashed_sk_string = hashed_sk_string[32:]

    # 3. k_string = Hash(truncated_hashed_sk_string || h_string)
    k_string = _hash(truncated_hashed_sk_string + h_string)
    test_dict = _assert_and_sample(test_dict, 'k', k_string)  # ANOMALY: k_hash vs k_int

    # 4. k = string_to_int(k_string) mod q
    k = int.from_bytes(k_string, 'little') % ORDER

    return k, test_dict


# Section 5.4.3. ECVRF Hash Points
def _ecvrf_hash_points(P1, P2, P3, P4, test_dict=None):
    """
    Input:
        P1...PM - EC points in G
        test_dict - optional dict of samples to assert and/or record
    Output:
        c - hash value, integer between 0 and 2^(8n)-1
        Test_dict passes from input to output with optional assert/record
    """
    # 1. two_string = 0x02 = int_to_string(2, 1), a single octet with value 2
    two_string = bytes([0x02])

    # 2. Initialize str = suite_string || two_string
    string = SUITE_STRING + two_string

    # 3. for PJ in [P1, P2, ... PM]:
    #        str = str || point_to_string(PJ)
    string = string + _encode_point(P1) + _encode_point(P2) + _encode_point(P3) + _encode_point(P4)

    # 4. c_string = Hash(str)
    c_string = _hash(string)

    # 5. truncated_c_string = c_string[0]...c_string[n-1]
    truncated_c_string = c_string[0:16]

    # 6. c = string_to_int(truncated_c_string)
    c = int.from_bytes(truncated_c_string, 'little')

    # 7. Output c
    return c, test_dict


# Section 5.4.4. ECVRF Decode Proof
def _ecvrf_decode_proof(pi_string, test_dict=None):
    """
    Input:
        pi_string - VRF proof, octet string (ptLen+n+qLen octets)
        test_dict - optional dict of samples to assert and/or record
    Output:
        "INVALID", or Gamma - EC point
        c - integer between 0 and 2^(8n)-1
        s - integer between 0 and 2^(8qLen)-1
        Test_dict passes from input to output with optional assert/record
    """
    # 1. let gamma_string = pi_string[0]...p_string[ptLen-1]
    gamma_string = pi_string[0:32]

    # 2. let c_string = pi_string[ptLen]...pi_string[ptLen+n-1]
    c_string = pi_string[32:48]

    # 3. let s_string =pi_string[ptLen+n]...pi_string[ptLen+n+qLen-1]
    s_string = pi_string[48:]

    # 4. Gamma = string_to_point(gamma_string)
    Gamma = _decode_point(gamma_string)

    # 5. if Gamma = "INVALID" output "INVALID" and stop.
    if Gamma == "INVALID": return "INVALID"

    # 6. c = string_to_int(c_string)
    c = int.from_bytes(c_string, 'little')

    # 7. s = string_to_int(s_string)
    s = int.from_bytes(s_string, 'little')

    # 8. Output Gamma, c, and s
    return (Gamma, c, s), test_dict


def _assert_and_sample(test_dict, key, actual):
    """
    Input:
        test_dict - holds values to assert and records values to sample
        key - key for assert values, basename (+ '_sample') for sampled values.
    Output:
        Return the potentially updated test_dict
    If key exists, assert dict expected value against provided actual value.
    Sample actual value and store into test_dict under key + '_sample'.
    """
    if test_dict and key in test_dict and actual:
        assert actual == test_dict[key]
    if test_dict: test_dict[key + '_sample'] = actual
    return test_dict


# Much of the following code has been adapted from ed25519 at https://ed25519.cr.yp.to/software.html retrieved 27 Dec 2019

def _edwards_add(P, Q):
    """Edwards curve point addition"""
    x1 = P[0]; y1 = P[1]
    x2 = Q[0]; y2 = Q[1]
    x3 = (x1 * y2 + x2 * y1) * _inverse(1 + D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inverse(1 - D * x1 * x2 * y1 * y2)
    return [x3 % PRIME, y3 % PRIME]


def _encode_point(P):
    """Encode point to string containing LSB OF X followed by 254 bits of Y"""
    return ((P[1] & ((1 << 255) - 1)) + ((P[0] & 1) << 255)).to_bytes(32, 'little')


def _decode_point(s):
    """Decode string containing LSB OF X followed by 254 bits of Y into point. Checks on-curve"""
    y = int.from_bytes(s, 'little') & ((1 << 255) - 1)
    x = _x_recover(y)
    if x & 1 != _get_bit(s, BITS - 1): x = PRIME - x
    P = [x, y]
    if not _is_on_curve(P): raise Exception("decoding point that is not on curve")
    return P


def _get_bit(h, i):
    """Return specified bit from integer for subsequent testing"""
    h1 = int.from_bytes(h, 'little')
    return (h1 >> i) & 0x01


def _get_secret_scalar_and_public_key(SK):
    """Calculate and return the secret_scalar and the corresponding public_key
       secret_scalar is an integer; public_key is an encoded point string
    """
    h = bytearray(_hash(SK)[0:32])
    -
    secret_int = int.from_bytes(h, 'little')
    public_point = _scalar_multiply(P=BASE, e=secret_int)
    public_string = _encode_point(public_point)
    return secret_int, public_string


def _hash(message):
    """Return 64-byte SHA512 hash of arbitrary-length byte message"""
    return hashlib.sha512(message).digest()


def _inverse(x):
    """Calculate inverse via Fermat's little theorem"""
    return pow(x, PRIME - 2, PRIME)


def _is_on_curve(P):
    """Check to confirm point is on curve; return boolean"""
    x = P[0]; y = P[1]
    result = (-x * x + y * y - 1 - D * x * x * y * y) % PRIME
    return result == 0


def _scalar_multiply(P, e):
    """Scalar multiplied by curve point"""
    if e == 0: return [0, 1]
    Q = _scalar_multiply(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1: Q = _edwards_add(Q, P)
    return Q


def _x_recover(y):
    """Recover x coordinate from y coordinate"""
    xx = (y * y - 1) * _inverse(D * y * y + 1)
    x = pow(xx, (PRIME + 3) // 8, PRIME)
    if (x * x - xx) % PRIME != 0: x = (x * I) % PRIME
    if x % 2 != 0: x = PRIME - x
    return x


# Checked constants, some of which are calculated at runtime
SUITE_STRING = bytes([0x04])
BITS = 256
PRIME = 2 ** 255 - 19
ORDER = 2 ** 252 + 27742317777372353535851937790883648493
TWO_INV = _inverse(2)
I = pow(2, (PRIME - 1) // 4, PRIME)
A = 486662
D = -121665 * _inverse(121666)
BASEy = 4 * _inverse(5)
BASEx = _x_recover(BASEy)
BASE = [BASEx % PRIME, BASEy % PRIME]
assert BITS >= 10
assert 8 * len(_hash("hash input".encode("UTF-8"))) == 2 * BITS
assert pow(2, PRIME - 1, PRIME) == 1
assert PRIME % 4 == 1
assert pow(2, ORDER - 1, ORDER) == 1
assert ORDER >= 2 ** (BITS - 4)
assert ORDER <= 2 ** (BITS - 3)
assert pow(D, (PRIME - 1) // 2, PRIME) == PRIME - 1
assert pow(I, 2, PRIME) == PRIME - 1
assert _is_on_curve(BASE)
assert _scalar_multiply(BASE, ORDER) == [0, 1]
