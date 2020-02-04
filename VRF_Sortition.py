import rECVRF
import pynacl
from ECVRF import *
from
from Keys import Key
import random

class Sortition:

    currentKey = None
    def __init__(self): #일단은 Num 제외
        self.participant = None
        self.data = None
        self.N = 1
        self.Key = None
        self.Proof = None

    def pick_winner(self,participant,n):  ##return (winner_lst, proof_of_winner,key)
        keys = self.createKey(self.data)
        self.update_sortition(participant,n)
        randseed = self.make_random_seed(keys.SecretKey)
        return self.RandomlyPick(randseed,participant)

    def update_sortition(self,participant,num):
        self.participant = participant
        self.data = self.serialize(participent)
        self.N = num

    def createKey(self,data): #Key generation with elliptic curve(ECVRF 25519)
        keySet = Key()
        keySet.create_secretKey(data)
        self.Key = keySet
        return keySet

    def serialize(self,participent_list):
        return participent_list.split().encode('ascii') #example이 string을 받아오니까 우선 split으로 행렬

    def make_random_seed(self, SK):
        hashed = self.ECVRF_hash(SK)
        hashseed = int.from_bytes(hashed[0:32],'little')
        return hashseed

    def ECVRF_hash(self,SK):
        self.Proof = ECVRF.prove(SK, self.data)
        hashedList = ECVRF.ecvrf_proof_to_hash(self.Proof)
        self.Key.PublicKey = ECVRF._get_secret_scalar_and_public_key(SK)[1]
        return hashedList

    def RandomlyPick(self, seed, domain):  # domain 스트링에서 seed 받아서 랜덤 function
        suffled = random.Random(seed).suffle(domain)
        return suffled[0:self.N]

    def verify_sortition(self):  ##return boolean of verifying
        vrf_val = False
        if ECVRF.ecvrf_verify(self.Key.PublicKey, self.Proof,self.serial_data) == "VALID":
            vrf_val = True
        key_val = self.Key.verify_secretKey()

        return vrf_val & key_val




