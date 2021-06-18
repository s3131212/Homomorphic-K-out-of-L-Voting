from Crypto.Util.number import inverse as multiplicative_inverse
from Crypto.Math.Primality import generate_probable_safe_prime
from Crypto.Math.Numbers import Integer
from Crypto.Random.random import randrange


class ElGamal:
    class PrivateKey:
        def __init__(self, p=None, g=None, x=None):
            self.p = p
            self.g = g
            self.x = x

        def __repr__(self):
            return f'ElGamal.PrivateKey(p={self.p}, g={self.g}, x={self.x})'

        def __eq__(self, pk):
            return self.p == pk.p and self.g == pk.g and self.x == pk.x

    class PublicKey:
        def __init__(self, p=None, g=None, h=None):
            self.p = p
            self.g = g
            self.h = h

        def __repr__(self):
            return f'ElGamal.PublicKey(p={self.p}, g={self.g}, h={self.h})'

        def __eq__(self, pk):
            return self.p == pk.p and self.g == pk.g and self.h == pk.h

    class Ciphertext:
        def __init__(self, cm, cr, pk):
            self.cm = cm # ciphertext with message
            self.cr = cr # ciphertext with random number
            self.pk = pk # the public key

        def __neg__(self):
            new_cm = multiplicative_inverse(self.cm, self.pk.p)
            new_cr = multiplicative_inverse(self.cr, self.pk.p)
            return ElGamal.Ciphertext(new_cm, new_cr, self.pk)

        def __add__(self, e):
            # homomorphic operation
            assert self.pk == e.pk, 'The public keys should be the same!'
            new_cm = self.cm * e.cm % self.pk.p
            new_cr = self.cr * e.cr % self.pk.p
            return ElGamal.Ciphertext(new_cm, new_cr, self.pk)

        def __sub__(self, e):
            return self + (-e)

        def __mul__(self, scalar):
            if not isinstance(scalar, int):
                ValueError('only scalar multiplication is allowed')
            ret = ElGamal.Encrypt(self.pk, 0, 0)
            # fast multiplication
            for b in bin(scalar)[2:]:
                ret = ret + ret
                if b == '1':
                    ret += self
            return ret

        def __eq__(self, e):
            return self.cm == e.cm and self.cr == e.cr and self.pk == e.pk

        def __repr__(self):
            return f'ElGamal.Ciphertext(cm={self.cm}, cr={self.cr}, pk={self.pk})'


    @classmethod
    def KeyGen(cls, nbits=512):
        # generate prime
        p = generate_probable_safe_prime(exact_bits=nbits)

        # generate group generator
        # reference: https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/PublicKey/ElGamal.py#L62
        while 1:
            g = pow(Integer.random_range(min_inclusive=2, max_exclusive=p), 2, p)
            if g in (1, 2):
                continue
            if (p - 1) % g == 0:
                continue
            ginv = g.inverse(p)
            if (p - 1) % ginv == 0:
                continue
            break

        p, g = int(p), int(g)

        x = randrange(nbits+1, p)
        h = pow(g, x, p)

        return (ElGamal.PublicKey(p, g, h), ElGamal.PrivateKey(p, g, x))

    @classmethod
    def Encrypt(cls, pk, m, alpha=None):
        if alpha is None:
            alpha = cls.genAlpha(pk.p)
        cm = pow(pk.g, m, pk.p) * pow(pk.h, alpha, pk.p) % pk.p
        cr = pow(pk.g, alpha, pk.p)
        return ElGamal.Ciphertext(cm, cr, pk)

    @classmethod
    def Decrypt(cls, sk, c, message_space):
        gm = c.cm * multiplicative_inverse(pow(c.cr, sk.x, sk.p), sk.p) % sk.p
        for m in message_space:
            if pow(sk.g, m, sk.p) == gm:
                return m
        raise ValueError('decryption failed')

    @classmethod
    def genAlpha(cls, p):
        return randrange(p - 1)


def __test():
    max_voter = 100
    message_space = list(range(max_voter+1))
    from random import choice

    for round_ in range(10):
        print(f'test round {round_} ... ', end='', flush=True)
        nbits = 512
        pk, sk = ElGamal.KeyGen(nbits)

        # test decrypt
        m = choice(message_space)
        assert ElGamal.Decrypt(sk, ElGamal.Encrypt(pk, m), message_space) == m, f'test decryption failed\n{pk}\n{sk}\n{m=}'

        # test homomorphic sub
        while True:
            m1 = choice(message_space)
            m2 = choice(message_space)
            if m1 - m2 in message_space:
                break
        alpha1 = randrange(pk.p - 1)
        alpha2 = randrange(pk.p - 1)
        c1 = ElGamal.Encrypt(pk, m1, alpha1)
        c2 = ElGamal.Encrypt(pk, m2, alpha2)
        assert ElGamal.Decrypt(sk, c1 - c2, message_space) == m1 - m2, f'test homomorphic add failed\n{sk}\n{m1=}\n{m2=}\n{alpha1=}\n{alpha2}'

        print('ok.')


if __name__ == '__main__':
    __test()
