from lamport import Lamport
import hashlib
import math

def reverse(lst):
    new_lst = lst[::-1]
    return new_lst

class MerkelN:



    def __init__(self, num_sigs):
        self.n = num_sigs

    def key_gen(self):
        ls = Lamport()
        number_of_signatures = self.n

        pk = [0]*number_of_signatures
        sk = [0]*number_of_signatures
        leaves = [0]*number_of_signatures
        Y=""

        tree_height = int(math.log2(number_of_signatures))

        x = int(number_of_signatures)

        list_tree = [0]*(tree_height + 1)

        for i in range(tree_height + 1):
            if i == 0:
                list_tree[0] = [0]*number_of_signatures
            else:
                x = int(x/2)
                list_tree[i] = [0]*x





        for i in range(number_of_signatures):
            pk[i], sk[i] = ls.key_gen()

            for j in range(256):
                Y += pk[i][0][j] + pk[i][1][j]

            leaves[i] = hashlib.sha256(Y.encode()).hexdigest()

            Y=""

        for h in range(tree_height + 1):

            if h == 0:
                list_tree[h] = leaves
            else:

                for i in range(len(list_tree[h])):
                    if i == 0:
                        list_tree[h][i] = hashlib.sha256((list_tree[h-1][0] + list_tree[h-1][1]).encode()).hexdigest()

                    else:
                        list_tree[h][i] = hashlib.sha256((list_tree[h-1][i*2] + list_tree[h-1][i*2 + 1]).encode()).hexdigest()

        secret_key = [sk, pk]
        public_key = list_tree[tree_height][0]

        return public_key, secret_key, list_tree

    def sign(self, m, leaf_index, list_tree, sk):
        ls = Lamport()

        secret_key = sk[0][leaf_index]
        auths = [0]*(len(list_tree)-1)
        sig_prime = ls.sign(m, secret_key)

        p_i = 0  # parent index
        c_i = 0  # child index

        # start

        c_i = leaf_index
        # left child = p_i*2
        # right child = p_i*2+1

        for h in range(len(list_tree)-1):

            if c_i % 2 == 0:  # left child
                p_i = int(c_i / 2)
            else:  # right child
                p_i = int((c_i - 1) / 2)

            if c_i % 2 == 0:
                auths[h] = list_tree[h][c_i + 1]
            else:
                auths[h] = list_tree[h][c_i - 1]

            c_i = p_i

        sig = [sig_prime, sk[1][leaf_index], auths]

        return sig

    def verify(self, m, s, pub, leaf_index):

        ls = Lamport()

        sig_prime = s[0]
        pub_i = s[1]
        auths = s[2]

        Y = ""

        verify_one_time = ls.verify(m, pub_i, sig_prime)

        a = [0]*(len(auths)+1)

        c_i = leaf_index
        p_i = 0

        if verify_one_time:
            for j in range(256):
                Y += pub_i[0][j] + pub_i[1][j]


            a_0 = hashlib.sha256(Y.encode()).hexdigest()

            print("yes " + a_0)
            print("yes " + pub)
            for k in range(len(auths)+1):
                if k == 0:
                    a_0 = hashlib.sha256(Y.encode()).hexdigest()
                    a[k] = a_0

                elif k == 1:
                    if c_i % 2 == 0:  # left child
                        p_i = int(c_i / 2)
                    else:  # right child
                        p_i = int((c_i - 1) / 2)

                    if c_i % 2 == 0:
                        a[1] = hashlib.sha256((a_0 + auths[0]).encode()).hexdigest()
                    else:
                        a[1] = hashlib.sha256((auths[0] + a_0).encode()).hexdigest()

                    c_i = p_i

                else:
                    if c_i % 2 == 0:  # left child
                        p_i = int(c_i / 2)
                    else:  # right child
                        p_i = int((c_i - 1) / 2)

                    if c_i % 2 == 0:
                        a[k] = hashlib.sha256((a[k-1]+ auths[k-1]).encode()).hexdigest()
                    else:
                        a[k] = hashlib.sha256((auths[k-1] + a[k-1]).encode()).hexdigest()

                    c_i = p_i

            print(a)
            if a[len(auths)] == pub:
                return True
            else:
                return False

        else:

            return False

