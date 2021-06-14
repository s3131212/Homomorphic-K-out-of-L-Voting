import random
import math
import sys
from functools import reduce

# Public Key
p = 1019
g = 494
q = (p - 1) // 2

# Private Key
x = 413
h = (g ** x) % p

G = list(range(g))
M = list(range(10))

u = min([q] + [i for i in range(1, q) if math.gcd(i, q) != 1 ])
print(u)

def Bigpow(a, b):
    ans = a
    for _ in range(b - 1):
        ans = (ans * a) % p
    return ans

def KeyGen():
    return 0

def Enc(m, r=None):
    r = random.randint(1, p - 1) if r is None else r
    return (pow(g, m, p) * pow(h, r, p) % p, pow(g, r, p))

def Dec(c):
    dp = (c[0] * pow(pow(c[1], x, p), -1, p)) % p
    for m in M:
        if g ** m % p == dp:
            return m
    return -1


## TEST
m1 = 1
m2 = 3
e1 = Enc(m1, 0)
e2 = Enc(m2, 0)
print("m1: ", m1, e1, Dec(e1))
print("m2: ", m2, e2, Dec(e2))


# ====== Voting Phase ======
# Suppose we have L=6 candidates, and a voter can at most vote for K=4 candidates.
L, K = 6, 4
ballot = [0, 1, 0, 1, 1, 1]

assert max(ballot) == 1 and min(ballot) == 0 and sum(ballot) == K and len(ballot) == L

# Ballot Encryption, E(ballot, alpha) is public, alpha and ballot are private 
alphas = [random.randint(1, p - 1) for _ in ballot]
ballot_encrypted = [Enc(v, r=a) for v, a in zip(ballot, alphas)]
print(ballot_encrypted)


# ====== Accumulation Phase ======
# Validate if the ballot's total is K
def check_ballot_sum_is_K(ballot_encrypted, alphas):
    
    ballot_sum_encrypted = reduce(lambda x,y: (x[0] * y[0] % p, x[1] * y[1] % p), ballot_encrypted)
    assert Dec(ballot_sum_encrypted) == K # check if the additive homomorphic encryption is correct

    encrypted_K = Enc(K, 0)
    encrypted_0 = (ballot_sum_encrypted[0] * pow(encrypted_K[0], -1, p) % p, ballot_sum_encrypted[1] * pow(encrypted_K[1], -1, p) % p)

    alphas_sum = sum(alphas)
    assert Enc(0, alphas_sum) == encrypted_0
    print(f"{ballot_sum_encrypted=} {encrypted_0=} {alphas_sum=}")

    ballot_sum_encrypted = Enc(0, alphas_sum)
    # Prover
    alpha_prime = random.randint(1, p - 1)
    e_prime = Enc(0, alpha_prime) # send to verifier
    print(f"Prover: {alpha_prime=} {e_prime=}")

    # Verifier
    c = random.randint(1, u - 1) # send to prover
    print(f"Verifer: {e_prime=} {c=}")

    # Prover
    beta = c * alphas_sum + alpha_prime # send to verifier
    print(f"Prover: {beta=}")

    # Verifier
    encrypted_beta = Enc(0, beta) 

    pf = (1, 1)
    for _ in range(c):
        pf = (pf[0] * ballot_sum_encrypted[0] % p, pf[1] * ballot_sum_encrypted[1] % p)
    pf = (pf[0] * e_prime[0] % p, pf[1] * e_prime[1] % p)
    print(f"Verifier: {encrypted_beta=} {pf=}")

    assert encrypted_beta == pf, "sigma protocol failed"

# Validate if the encryption is 0 or 1
all_possible_encryption = set([Enc(0, i + 1) for i in range(p - 1)] + [Enc(1, i + 1) for i in range(p - 1)])
def check_ballot_is_binary(ballot, ballot_encrypted, alphas):
    # Check 2
    encrypted_1 = Enc(1, 0)
    for v, e, alpha in list(zip(ballot, ballot_encrypted, alphas))[:1]:
        encrypted_ballot = [e, (e[0] * pow(encrypted_1[0], -1, p) % p, e[1] * pow(encrypted_1[1], -1, p) % p)]
        # Prover
        alpha_prime = random.randint(1, p - 1)

        c = [0, 0]
        c[1 - v] = random.randint(1, u - 1)

        beta = [0, 0]
        beta[1 - v] = random.randint(1, p - 1)

        e_prime = [None, None] # send to verifier
        e_prime[v] = Enc(0, alpha_prime)
        e_prime[1 - v] = Enc(0, beta[1 - v])

        for _ in range(c[1 - v]):
            e_prime[1 - v] = (e_prime[1 - v][0] * pow(encrypted_ballot[1 - v][0], -1, p) % p, e_prime[1 - v][1] * pow(encrypted_ballot[1 - v][1], -1, p) % p)
        print(f"{e_prime=}")

        # Verifier
        c_from_verifier = random.randint(1, u - 1) # send to prover
        print(f"{c_from_verifier=}")

        # Prover
        c[v] = (c_from_verifier - c[1 - v]) % u
        beta[v] = c[v] * alpha + alpha_prime
        # send c, beta to verifier
        print(f"{c=} {beta=} {e_prime=}")

        # Verifier
        assert c_from_verifier == (c[0] + c[1]) % u

        pf = (1, 1)
        for _ in range(c[0]):
            pf = (pf[0] * encrypted_ballot[0][0] % p, pf[1] * encrypted_ballot[0][1] % p)
        pf = (pf[0] * e_prime[0][0] % p, pf[1] * e_prime[0][1] % p)
        assert Enc(0, beta[0]) == pf

        pf = (1, 1)
        for _ in range(c[1]):
            pf = (pf[0] * encrypted_ballot[1][0] % p, pf[1] * encrypted_ballot[1][1] % p)
        pf = (pf[0] * e_prime[1][0] % p, pf[1] * e_prime[1][1] % p)
        assert Enc(0, beta[1]) == pf




    assert all([ b in all_possible_encryption for b in ballot_encrypted ])


check_ballot_sum_is_K(ballot_encrypted, alphas)
check_ballot_is_binary(ballot, ballot_encrypted, alphas)