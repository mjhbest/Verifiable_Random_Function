
class VRF:

    def __init__(self):
        pass

    def prove(self, secKey, alpha):
        #1. Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
        (sScala, pubKey) = self.get_secret_scalar_and_public_key(secKey)

        #2. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
        #3. h_string = point_to_string(H)
        #4. Gamma = x*H
        #5. k = ECVRF_nonce_generation(SK, h_string)
        #6. c = ECVRF_hash_points(H, Gamma, k*B, k*H)
        #7. s = (k + c*x) mod q
        #8. pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
        #9. Output pi_string

    def proof2hash(self,pi):
        #1. D = ECVRF_decode_proof(pi_string)
        #2. If D is "INVALID", output "INVALID" and stop
        #3. (Gamma, c, s) = D
        #4. three_string = 0x03 = int_to_string(3, 1), a single octet with value 3
        #5. beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
        #6. Output beta_string

    def verify(self, pubKey, alpha, pi):
        pass

    def get_secret_scalar_and_public_key(self,secKey):
        h = bytearray(secKey.hash)

        return (sScala,pubKey)




