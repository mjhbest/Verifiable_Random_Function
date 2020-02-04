import pynacl
import Elliptic_Arithmetic

def prove(self, secKey, alpha):
    #1. Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
    (x, pubKey) = get_pubKey(secKey)
    #2. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
    H = hash_to_curve(SUITE_STRING,pubKey,)
    #3. h_string = point_to_string(H)
    h =
    #4. Gamma = x*H
    G = multi(sScala,H)
    #5. k = ECVRF_nonce_generation(SK, h_string)
    #6. c = ECVRF_hash_points(H, Gamma, k*B, k*H)
    #7. s = (k + c*x) mod q
    #8. pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
    #9. Output pi_string
    pi =

def proof_to_hash(self,pi):
    #1. D = ECVRF_decode_proof(pi_string)
    #2. If D is "INVALID", output "INVALID" and stop
    #3. (Gamma, c, s) = D
    #4. three_string = 0x03 = int_to_string(3, 1), a single octet with value 3
    #5. beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
    #6. Output beta_string

def verify(self, pubKey, alpha, pi):
    pass

def get_pubKey(self,secKey):
    x = int.from_bytes(secKey[0:32],'little') #secret scalar
    point = Elliptic_Arithmetic.Point
    pubKey = point.mul(x)
    return (x,pubKey)

def hash_point():
    pass

def nonce_generartion():
    pass

def hash_to_curve_try_and_increment(pubKey,alpha):
    #1.ctr = 0
    ctr - 0
    #2.PK_string = point_to_string(Y)

    #3.one_string = 0x01 = int_to_string(1, 1), a single octet with value 1

    #4.H = "INVALID"

    #5.While H is "INVALID" or H is EC point at infinity:
        #A.ctr_string = int_to_string(ctr, 1)
        #B.hash_string = Hash(suite_string | | one_string | | PK_string | | alpha_string | | ctr_string)
        #C.H = arbitrary_string_to_point(hash_string)
        #D.If H is not "INVALID" and cofactor > 1, set H = cofactor * H
        #E.ctr = ctr + 1


