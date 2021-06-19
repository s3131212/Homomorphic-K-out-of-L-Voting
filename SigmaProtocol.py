from hashlib import sha3_512
from ElGamal import ElGamal
from Crypto.Random.random import randrange
from Crypto.Hash import SHA3_512


def genChallenge(p):
    return randrange(p - 1)


class SigmaProtocol_0:

    class Prover:
        def __init__(self):
            pass

        def P1(self, e, alpha):
            self.pk = e.pk
            self.alpha = alpha
            self.alpha_ = ElGamal.genAlpha(e.pk.p)
            e_ = ElGamal.Encrypt(e.pk, 0, self.alpha_)
            return e_

        def P2(self, c):
            beta = (c * self.alpha + self.alpha_) % (self.pk.p - 1) # IMPORTANT !!! mod (p-1) instead of mod p
            return beta

    class Verifier:
        def __init__(self):
            pass

        def V1(self, e, e_):
            self.e = e
            self.e_ = e_

            self.c = genChallenge(e.pk.p)
            return self.c

        def V2(self, beta):
            return (self.e, self.e_, self.c, beta)

        @classmethod
        def verify(cls, conversation):
            e, e_, c, beta = conversation
            return ElGamal.Encrypt(e.pk, 0, beta) == (c * e + e_)

    # the simulator guaranteed by sigma protocol
    @classmethod
    def Simulator(cls, e):
        c = randrange(e.pk.p - 1)
        beta = randrange(e.pk.p - 1)
        e_ = ElGamal.Encrypt(e.pk, 0, beta) - c * e
        return (e, e_, c, beta)


class SigmaProtocol_K:

    class Prover:
        def __init__(self):
            pass

        def P1(self, e, K, alpha):
            # note that the alpha here is the product of every alpha_k
            assert e == ElGamal.Encrypt(e.pk, K, alpha), f'{(e, K, alpha)=}'

            e_minus_K = ElGamal.Encrypt(e.pk, -K, 0)

            self.underlying_protocol = SigmaProtocol_0.Prover()
            return self.underlying_protocol.P1(e + e_minus_K, alpha)

        def P2(self, c):
            return self.underlying_protocol.P2(c)

    class Verifier:
        def __init__(self):
            pass

        def V1(self, e, e_, K):
            self.e = e
            self.K = K
            e_minus_K = ElGamal.Encrypt(e.pk, -K, 0)

            self.underlying_protocol = SigmaProtocol_0.Verifier()
            return self.underlying_protocol.V1(e + e_minus_K, e_)

        def V2(self, beta):
            _, e_, c, beta = self.underlying_protocol.V2(beta)
            return (self.e, self.K, e_, c, beta)

        @classmethod
        def verify(cls, conversation):
            e, K, e_, c, beta = conversation
            e0 = e + ElGamal.Encrypt(e.pk, -K, 0)
            return SigmaProtocol_0.Verifier.verify((e0, e_, c, beta))

    @classmethod
    def Simulator(cls, e, K):
        e0 = e + ElGamal.Encrypt(e.pk, -K, 0)
        _, e_, c, beta = SigmaProtocol_0.Simulator(e0)
        return (e, K, e_, c, beta)

    # class FiatShamirSignature:
    #     class PublicKey:
    #         def __init__(self, e, K):
    #             self.e = e
    #             self.K = K

    #     class PrivateKey:
    #         def __init__(self, e, K, alpha):
    #             assert e == ElGamal.Encrypt(e.pk, K, alpha)
    #             self.e = e
    #             self.K = K
    #             self.alpha = alpha

    #     @classmethod
    #     def RandomOracle(cls, message, com):
    #         assert isinstance(message, int)
    #         assert isinstance(com, ElGamal.Ciphertext)

    #         RO = SHA3_512.new()
    #         RO.update(str(message).encode())
    #         RO.update(repr(com).encode())
    #         return int.from_bytes(RO.digest(), 'big') % (com.pk.p - 1)

    #     @classmethod
    #     def sign(cls, sk, message):
    #         assert isinstance(sk, cls.PrivateKey)
    #         assert isinstance(message, int)

    #         prover = SigmaProtocol_K.Prover()
    #         com = prover.P1(sk.e, sk.K, sk.alpha)
    #         ch = cls.RandomOracle(message, com)
    #         resp = prover.P2(ch)
    #         return (com, resp)

    #     @classmethod
    #     def verify(cls, pk, message, signature):
    #         assert isinstance(pk, cls.PublicKey)

    #         com, resp = signature
    #         ch = cls.RandomOracle(message, com)
    #         return cls.Verifier.verify((pk.e, pk.K, com, ch, resp))


class SigmaProtocol_01:

    class Prover:
        def __init__(self):
            pass

        def P1(self, e, m, alpha):
            assert e == ElGamal.Encrypt(e.pk, m, alpha)

            # prepare
            self.b = b = m # stands for bit
            self.bb = bb = 1 - m # stands for b bar
            self.e_ = [0, 0]
            self.c = [0, 0]
            self.beta = [0, 0]
            _, _, self.e_[bb], self.c[bb], self.beta[bb] = SigmaProtocol_K.Simulator(e, bb)

            self.underlying_protocol = SigmaProtocol_K.Prover()
            self.e_[b] = self.underlying_protocol.P1(e, m, alpha)
            return self.e_.copy()

        def P2(self, c_tmp):
            b = self.b
            bb = self.bb

            self.c[b] = c_tmp ^ self.c[bb]
            self.beta[b] = self.underlying_protocol.P2(self.c[b])
            return self.c, self.beta

    class Verifier:
        def __init__(self):
            pass

        def V1(self, e, e_):
            assert len(e_) == 2

            self.e = e
            self.e_ = e_

            self.c_tmp = genChallenge(e.pk.p)
            return self.c_tmp

        def V2(self, c, beta):
            return (self.e, self.e_, self.c_tmp, c, beta)

        @classmethod
        def verify(cls, conversation):
            e, e_, c_tmp, c, beta = conversation
            return (c_tmp == c[0] ^ c[1]) and \
                   (SigmaProtocol_K.Verifier.verify((e, 0, e_[0], c[0], beta[0]))) and \
                   (SigmaProtocol_K.Verifier.verify((e, 1, e_[1], c[1], beta[1])))


def __test():
    M = 100
    message_space = list(range(M+1))
    from random import choice

    for round_ in range(20):
        print(f'test round {round_} ... ', end='', flush=True)
        nbits = 512
        pk, sk = ElGamal.KeyGen(nbits)

        # test Simulator
        K = choice(message_space)
        e = ElGamal.Encrypt(pk, K)
        conversation = SigmaProtocol_K.Simulator(e, K)
        assert SigmaProtocol_K.Verifier.verify(conversation), f'test Simulator failed\n{pk}\n{sk}\n{conversation=}'

        # test SigmaProtocol_K
        K = choice(message_space)
        alpha = ElGamal.genAlpha(pk.p)
        e = ElGamal.Encrypt(pk, K, alpha)
        prover = SigmaProtocol_K.Prover()
        verifier = SigmaProtocol_K.Verifier()

        e_ = prover.P1(e, K, alpha)
        c = verifier.V1(e, e_, K)
        beta = prover.P2(c)
        conversation = verifier.V2(beta)

        assert verifier.verify(conversation), f'test SigmaProtocol_K failed\n{pk}\n{sk}\n{(K, alpha, conversation)=}'

        # test SigmaProtocol_01
        m = choice((0, 1))
        alpha = ElGamal.genAlpha(pk.p)
        e = ElGamal.Encrypt(pk, m, alpha)
        prover = SigmaProtocol_01.Prover()
        verifier = SigmaProtocol_01.Verifier()

        e_ = prover.P1(e, m, alpha)
        c_tmp = verifier.V1(e, e_)
        c, beta = prover.P2(c_tmp)
        conversation = verifier.V2(c, beta)

        assert verifier.verify(conversation), f'test SigmaProtocol_01 failed\n{pk}\n{sk}\n{(m, alpha, conversation)=}'

        print('ok.')


if __name__ == '__main__':
    __test()
