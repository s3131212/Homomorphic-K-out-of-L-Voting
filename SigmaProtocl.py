from .ElGamal import ElGamal
from .Network import *
import random

# Prove 0
def Prover_0(e, alpha):
    alpha_ = random.randint(1, e.pk.p - 1)
    e_ = ElGamal.Encrypt(e.pk, 0, alpha_)
    send(e_)

    c = recv()
    beta = c * alpha + alpha_
    send(beta)
    return

def Verifier_0_get_conversation(e):
    e_ = recv()

    c = random.randint(1, (e.pk.p - 1) // 2 - 1)
    send(c)

    beta = recv()
    return (e, e_, c, beta)

def Verifier_0_verify(conversation):
    e, e_, c, beta = conversation
    return ElGamal.Encrypt(e.pk, 0, beta) == c * e + e_

def Simulator_0(e):
    # the simulator guaranteed by sigma protocol
    c = random.randint(1, (e.pk.p - 1) // 2 - 1)
    beta = random.randint(1, e.pk.p - 1)
    e_ = ElGamal.Encrypt(e.pk, 0, beta) - c * e # if using ElGamal, the subtraction can be achieved by finding the multiplicative inverse
    return (e, e_, c, beta)

# Prove K
def Prover_K(e, K, alpha):
    # note that the alpha here is the product of every alpha_k
    e_minus_K = ElGamal.Encrypt(e.pk, -K, 0)

    Prover_0(e + e_minus_K, alpha)

def Verifier_K_get_conversation(e, K):
    e_minus_K = ElGamal.Encrypt(e.pk, -K, 0)

    return Verifier_0_get_conversation(e + e_minus_K)

def Verifier_K_verify(conversation):
    return Verifier_0_verify(conversation)

# Prove 01
def Prover_01(e, m, alpha):
    assert e == ElGamal.Encrypt(e.pk, m, alpha)

    # prepare
    b = m # stands for bit
    bb = 1 - m # stands for b bar
    e_ = [0, 0]
    c = [0, 0]
    beta = [0, 0]
    _, e_[bb], c[bb], beta[bb] = Simulator_0(e)

    # start the underlying protocol
    #async Prover_K(e, m, alpha) # WTF why????
    e_[b] = recv()
    send(e_)

    c_tmp = recv()
    c[b] = (c_tmp - c[bb]) % ((e.pk.p - 1) // 2)
    send(c[b])
    beta[b] = recv()
    send(c, beta)

def Verifier_01_get_conversation(e):
    e_ = recv() # list of len = 2

    c_tmp = random.randint(1, (e.pk.p - 1) // 2 - 1)
    send(c_tmp)

    c, beta = recv() # both c and beta are list of len = 2
    return (e, e_, c_tmp, c, beta)

def Verifier_01_verify(conversation):
    e, e_, c_tmp, c, beta = conversation
    return (c_tmp == c[0] ^ c[1]) and \
           (Verifier_K_verify((e, e_[0], c[0], beta[0]))) and \
           (Verifier_K_verify((e, e_[1], c[1], beta[1])))
