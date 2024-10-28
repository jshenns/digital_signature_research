from lamport import Lamport
from merkel_4_time_sig import Merkel4
from merkel_n_time_sig import MerkelN

def main():
    ls = Lamport()
    message = "hello everyone"
    bad_message = "hello nobody afdsf dsafdsa"

    public_key, secret_key = ls.key_gen()
    signature = ls.sign(message, secret_key)
    verified = ls.verify(message, public_key, signature)
    not_verified = ls.verify(bad_message, public_key, signature)

    #print(verified)
    #print(not_verified)

    mrk = Merkel4()
    pk, sk, a = mrk.key_gen()
    signature = mrk.sign(message, 3, a, sk)

    verified_merkel = mrk.verify(message, signature, a[2][0],3)
    not_verified_merkel = mrk.verify(bad_message, signature, a[2][0], 3)

    #print(verified_merkel)
    #print(not_verified_merkel)


    mrkn = MerkelN(256)
    pk, sk, a = mrkn.key_gen()
    n_sig = mrkn.sign(message, 232, a, sk)

    verified_merkel_n = mrkn.verify(message, n_sig,pk, 232)
    not_verified_merkel_n = mrkn.verify(bad_message, n_sig, pk, 232)


    print(pk)
    print(a)
    print(a[0][7])
    print(n_sig[2])
    print(verified_merkel_n)
    print(not_verified_merkel_n)

if __name__ == '__main__':
    main()
