import ECVRF
import nacl.utils

from nacl.public import PrivateKey, SealedBox
from Keys import Key

class Sortition:

    currentKey = None

    def createKey(self): #Key generation with elliptic curve(ECVRF 25519)
        keypair = Key
        keypair.SecreatKey = PrivateKey()
        keypair.PublicKey = keypair.PublicKey
        return keypair

    def pick(self,lst):  ##return (winner_lst, proof_of_winner,key)
        self.createKey()



    def verify_sortition(self, proof, publicKey):  ##return boolean of verifying
        pass


    def RandomlyPick(self, seed, domain): #domain 스트링에서 seed 받아서 랜덤 function
