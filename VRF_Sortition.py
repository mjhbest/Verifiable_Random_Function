import rECVRF
import pynacl
from rECVRF import *
from Keys import Key
import random

class Sortition:

    currentKey = None
    def __init__(self,participent, number=1): #일단은 Num 제외
        self.participant = participent.split()
        self.serial_data = participent.encode('ascii')
        self.N = number
        self.Key = None
        self.Proof = None

    def createKey(self): #Key generation with elliptic curve(ECVRF 25519)
        keySet = Key()
        keySet.create_secretKey(self.serial_data)
        self.Key = keySet
        return keySet

    def pick_winner(self):  ##return (winner_lst, proof_of_winner,key)
        keys = self.createKey()
        randseed = self.make_random_seed(keys.SecretKey)
        return self.RandomlyPick(randseed,self.participant)

    def make_random_seed(self, SK):
        hashed = ECVRF_hash(SK)
        secretInt = int(hashed[0:32])
        return secretInt

    def RandomlyPick(self, seed, domain): #domain 스트링에서 seed 받아서 랜덤 function
        suffled = random.Random(seed).suffle(domain)
        return suffled[0:self.N]

    def ECVRF_hash(self,SK):
        self.Proof = ecvrf_prove(SK, self.serial_data)
        hashedList = rECVRF.ecvrf_proof_to_hash(self.VRF["pi"])
        self.Key.PublicKey = rECVRF._get_secret_scalar_and_public_key(SK)[1]
        return hashedList

    def verify_sortition(self):  ##return boolean of verifying

        vrf_val = False
        if rECVRF.ecvrf_verify(self.Key.PublicKey, self.Proof,self.serial_data) == "VALID":
            vrf_val = True

        key_val = self.Key.verify_secretKey()

        return vrf_val & key_val




