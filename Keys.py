import
import nacl.signing

class Key:
    def __init__(self):
        self.SecretKey =None
        self.PublicKey =None
        self.VerifyKey = None
        self.PublicKey4sign = None
        self.Signature = None

    def create_secretKey(self,data):
        self.SecretKey = Signer(data)
        self.Signature = self.SecretKey.signature
        self.PublicKey4sign = self.SecretKey.verify_key_hex  # signing public key

    def verify_secretKey(self):
        self.Verifykey = nacl.VerifyKey(self.PublicKey4sign, encoder = nacl.encoding.HexEncoder)
        return self.VerifyKey.verify(self.Signature)

class Signer:
    def __init__(self, data):
        self.key = nacl.signing.SigningKey.generate()
        self.signature = self.key.sign(bytes(data))
        self.verify_key_hex = self.key.verify_key.encode(encoder=nacl.encoding.HexEncoder)







