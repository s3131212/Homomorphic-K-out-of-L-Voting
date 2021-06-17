class ElGamal:
    class PrivateKey(object):
        def __init__(self, p=None, g=None, x=None):
            self.p = p
            self.g = g
            self.x = x
        def __repr__(self):
            return f"{self.p=} {self.g=} {self.x=}"

    class PublicKey(object):
        def __init__(self, p=None, g=None, h=None):
            self.p = p
            self.g = g
            self.h = h
        def __repr__(self):
            return f"{self.p=} {self.g=} {self.h=}"

    class Ciphertext:
        def __init__(self, cm, cr, pk):
            self.cm = cm # ciphertext with message
            self.cr = cr # ciphertext with random number
            self.pk = pk # the public key

        def __neg__(self):
            # multiplicative inverse
            return ElGamal.Ciphertext(pow(self.cm, -1, self.pk.p) % self.p, pow(self.cr, -1, self.pk.p) % self.p)

        def __add__(self, e):
            # homomorphic operation
            assert self.pk == e.pk
            return ElGamal.Ciphertext(self.cm * e.cm % self.pk.p, self.cr * e.cr % self.pk.p)
            
        def __sub__(self, e):
            return self + (-e)
        
    @classmethod
    def KeyGen(n):
        # Public Key
        p = 1019
        g = 494

        # Private Key
        x = 413
        h = (g ** x) % p

        return (ElGamal.PublicKey(p, g, h), ElGamal.PrivateKey(p, g, x))
        
    @classmethod
    def Encrypt(pk, m, alpha):
        return ElGamal.Ciphertext(pow(pk.g, m, pk.p) * pow(pk.h, alpha, pk.p) % pk.p, pow(pk.g, alpha, pk.p), pk)
    
    @classmethod
    def Decrypt(sk, c, PS):
        dp = (c.cm * pow(pow(c.cr, sk.x, sk.p), -1, sk.p)) % sk.p
        for m in PS:
            if sk.g ** m % sk.p == dp:
                return m
        return -1
