import hashlib
import secrets


class Lamport:

    def key_gen(self):
        binary_choices = ['0', '1']
        sk = [[0]*256, [0]*256]  # secret key
        pk = [[0]*256, [0]*256] # public key

        # create the secret key; 2x256 pairs of random numbers, each which is 256 bits long
        for j in range(256):

            sk[0][j] = secrets.token_hex(32)

        for i in range(256):
            sk[1][i] = secrets.token_hex(32)

        # public key
        for i in range(2):
            for j in range(256):
                # the public key is generated by hashing the 2x256 numbers in the secret key
                pk[i][j] = hashlib.sha256(sk[i][j].encode()).hexdigest()

        return pk, sk

    def sign(self, message, sk):
        signature = [0]*256

        # hash the message to get a unique hash sum
        message_hash = bin(int(hashlib.sha256(message.encode()).hexdigest(), 16))[2:].zfill(256)

        # sign the message by choosing one of the 256 pairs in the secret key
        for i in range(256):
            if message_hash[i] == '0':
                signature[i] = sk[0][i]
            elif message_hash[i] == '1':
                signature[i] = sk[1][i]

        return signature

    def verify(self, message, pk, signature):

        # hash the message to get a unique hash sum
        message_hash = bin(int(hashlib.sha256(message.encode()).hexdigest(), 16))[2:].zfill(256)
        verification_hashes = [0]*256
        signature_hashes = [0]*256
        for i in range(256):

            # hash the 256 numbers in the signature
            signature_hashes[i] = hashlib.sha256(signature[i].encode()).hexdigest()

            # choose numbers from the public key based on the message hash (same way as key_gen)
            if message_hash[i] == '0':
                verification_hashes[i] = pk[0][i]
            elif message_hash[i] == '1':
                verification_hashes[i] = pk[1][i]

        if verification_hashes == signature_hashes:
            verified = True
        else:
            verified = False

        return verified
