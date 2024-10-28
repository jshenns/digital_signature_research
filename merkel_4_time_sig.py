from lamport import Lamport
import hashlib


# N = 4, 2^2 , n = 2


class Merkel4:

    # generating public and secret keys
    def key_gen(self):
        ls = Lamport()
        pk = [0]*4
        sk = [0]*4
        h = [0]*4
        a = [[0]*4, [0]*2, [0]*1]
        Y = ""

        # first make 4 lamport key pairs
        for i in range(4):
            pk[i], sk[i] = ls.key_gen()

            # hash each public key, these are the leaves of the merkel tree
            for j in range(256):
                Y += pk[i][0][j] + pk[i][1][j]

            h[i] = hashlib.sha256(Y.encode()).hexdigest()

            Y = ""

        # compute the nodes of the merkel tree
        for i in range(3):
            if i == 0:
                a[0][0] = h[0]
                a[0][1] = h[1]
                a[0][2] = h[2]
                a[0][3] = h[3]
            elif i == 1:
                a[1][0] = hashlib.sha256((a[0][0] + a[0][1]).encode()).hexdigest()
                a[1][1] = hashlib.sha256((a[0][2] + a[0][3]).encode()).hexdigest()
            elif i==2:
                a[2][0] = hashlib.sha256((a[1][0] + a[1][1]).encode()).hexdigest()

        # the secret key is all pairs
        secret_key = [sk, pk]

        # the public key is the root node of the tree
        public_key = a[2][0]

        return public_key, secret_key, a

    # sign the message (m), index i(0:3) for different signatures,a is tree, pk public key, sk secret key
    def sign(self, m, i, a, sk):

        ls = Lamport()

        secret_key = sk[0][i]

        # first one-time sign the message with the secret key corresponding to the index
        sig_prime = ls.sign(m, secret_key)

        # choose auth nodes which will allow reconstruction of the path, these are sent as part of signature
        if i == 0:
            auth_0 = a[0][1]
            auth_1 = a[1][1]
        elif i == 1:
            auth_0 = a[0][0]
            auth_1 = a[1][1]
        elif i == 2:
            auth_0 = a[0][3]
            auth_1 = a[1][0]
        else:
            auth_0 = a[0][2]
            auth_1 = a[1][0]

        # final signature consists of the OTS, secret key at index i, auth nodes
        sig = [sig_prime, sk[1][i], auth_0, auth_1]

        return sig

    # verify the signature m = message, s= signature, pub=root node, i= index(0:3)
    def verify(self, m, s, pub, i):
        ls = Lamport()

        # decode the different parts of the signature
        sig_prime = s[0]
        pub_i = s[1]
        auth_0 = s[2]
        auth_1 = s[3]

        Y = ""

        # first verify the OTS
        verify_one_time = ls.verify(m, pub_i, sig_prime)

        # if OTS, true, reconstruct the path on the merkel tree
        if verify_one_time:
            for j in range(256):
                Y += pub_i[0][j] + pub_i[1][j]

            # concatenate the auths and the public key; concatenation order matters, tree traversal step
            if i == 0:
                a_0 = hashlib.sha256(Y.encode()).hexdigest()
                a_1 = hashlib.sha256((a_0 + auth_0).encode()).hexdigest()
                a_2 = hashlib.sha256((a_1 + auth_1).encode()).hexdigest()
            elif i == 1:
                a_0 = hashlib.sha256(Y.encode()).hexdigest()
                a_1 = hashlib.sha256((auth_0 + a_0).encode()).hexdigest()
                a_2 = hashlib.sha256((a_1 + auth_1).encode()).hexdigest()
            elif i == 2:
                a_0 = hashlib.sha256(Y.encode()).hexdigest()
                a_1 = hashlib.sha256((a_0 + auth_0).encode()).hexdigest()
                a_2 = hashlib.sha256((auth_1 + a_1).encode()).hexdigest()
            elif i == 3:
                a_0 = hashlib.sha256(Y.encode()).hexdigest()
                a_1 = hashlib.sha256((auth_0 + a_0).encode()).hexdigest()
                a_2 = hashlib.sha256((auth_1 + a_1).encode()).hexdigest()

            # if the root node (pub) equals the reconstructed root node a_2, then we have a winner
            if a_2 == pub:
                return True
            else:
                return False
        else:
            return False
