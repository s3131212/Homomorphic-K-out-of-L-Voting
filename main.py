import sys
import threading
import time

from ElGamal import ElGamal
from SigmaProtocol import SigmaProtocol_K, SigmaProtocol_01
from Network import listen_on_port, connect_to, sendLine, recvLine

NBITS = 512
NUM_VOTER = 4
K = 2 # how many candidates you can vote
L = 5 # the number of candidates


PUBLIC_KEY_PORT = 10001
VOTE_PORT = 10002
DECRYPT_VOTE_PORT = 10003


def keygen_party():
    pk, sk = ElGamal.KeyGen(NBITS)

    def get_public_key_server(pk):
        def public_key_server(conn, addr):
            sendLine(conn, str(pk).encode())
            conn.close()
            return
        return public_key_server

    def get_decrypt_vote_server(sk):
        def decrypt_vote_server(conn, addr):
            candidate_sum = [ None for _ in range(L) ]
            for l in range(L):
                e = ElGamal.Ciphertext.from_str(recvLine(conn))
                m = ElGamal.Decrypt(sk, e, range(NUM_VOTER+1))
                candidate_sum[l] = m

            conn.close()
            print(f'decrypted ballot sum: {candidate_sum}')
            return
        return decrypt_vote_server

    t1 = threading.Thread(target=listen_on_port, args=(PUBLIC_KEY_PORT, get_public_key_server(pk)))
    t2 = threading.Thread(target=listen_on_port, args=(DECRYPT_VOTE_PORT, get_decrypt_vote_server(sk)))
    t1.start() ; print(f'listening public key server on {PUBLIC_KEY_PORT} ...', file=sys.stderr)
    t2.start() ; print(f'listening decryption server on {DECRYPT_VOTE_PORT} ...', file=sys.stderr)

    while True:
        time.sleep(1000000000)


def accumulate_ballot_party():
    pk = obtain_public_key()

    ballots = [ None for _ in range(NUM_VOTER) ]

    def ballot_server(conn, addr):
        line = recvLine(conn)
        voter_id = int(line)

        # cannot only vote once
        if not ballots[voter_id] is None:
            print(f'voter {voter_id} tries to vote more than once, reject', file=sys.stderr)
            conn.close()
            return

        print(f'voter {voter_id} tries to vote ...', file=sys.stderr)

        # receive ballot for every candidate
        tmp_ballots = []
        for _ in range(L):
            line = recvLine(conn)
            e = ElGamal.Ciphertext.from_str(line)
            if e.pk != pk:
                print(f'voter {voter_id} uses invalid public key', file=sys.stderr)
                conn.close()
                return
            tmp_ballots.append(e)

        # check the sum of every ballot is K
        e_sum = sum(tmp_ballots)
        verifier = SigmaProtocol_K.Verifier()
        e_ = ElGamal.Ciphertext.from_str(recvLine(conn))
        ch = verifier.V1(e_sum, e_, K)
        sendLine(conn, str(ch))
        beta = int(recvLine(conn))
        conversation = verifier.V2(beta)
        if not verifier.verify(conversation):
            print(f'voter {voter_id} SigmaProtocol_K failed', file=sys.stderr)
            conn.close()
            return

        # check every ballot is 0 or 1
        for l in range(L):
            verifier = SigmaProtocol_01.Verifier()
            e_ = [ None, None ]
            e_[0] = ElGamal.Ciphertext.from_str(recvLine(conn))
            e_[1] = ElGamal.Ciphertext.from_str(recvLine(conn))
            ch_tmp = verifier.V1(tmp_ballots[l], e_)
            sendLine(conn, str(ch_tmp))
            ch = [ None, None ]
            ch[0] = int(recvLine(conn))
            ch[1] = int(recvLine(conn))
            beta = [ None, None ]
            beta[0] = int(recvLine(conn))
            beta[1] = int(recvLine(conn))
            conversation = verifier.V2(ch, beta)
            if not verifier.verify(conversation):
                print(f'voter {voter_id} SigmaProtocol_01 of candidate {l} failed', file=sys.stderr)
                conn.close()
                return

        ballots[voter_id] = tmp_ballots
        print(f'voter {voter_id} successfully votes', file=sys.stderr)
        conn.close()

        # accumulate ballots and send to decryption
        if None not in ballots:
            print('every voter has voted, send accumulated ballot to decryption server', file=sys.stderr)
            candidate_sum = [ None for _ in range(L) ]
            for l in range(L):
                candidate_sum[l] = sum(ballots[v][l] for v in range(NUM_VOTER))

            def handler(conn):
                for l in range(L):
                    sendLine(conn, str(candidate_sum[l]))
                return

            connect_to(DECRYPT_VOTE_PORT, handler)

        return

    t1 = threading.Thread(target=listen_on_port, args=(VOTE_PORT, ballot_server))
    t1.start() ; print(f'listening ballot server server on {VOTE_PORT} ...', file=sys.stderr)

    while True:
        time.sleep(1000000000)


def voter():
    pk = obtain_public_key()

    voter_id = int(input('Enter your voter_id : '))
    if voter_id not in range(NUM_VOTER):
        print('invalid voter_id', file=sys.stderr)
        exit(-1)

    print(f'Available candidates : {list(range(L))} ')
    ballot_input = tuple(map(int, input(f'Select {K} candidates to vote (space-separated) : ').split()))

    alpha_list = [ ElGamal.genAlpha(pk.p) for _ in range(L) ]
    ballot_m = []
    ballot_e = []
    for l in range(L):
        m = 1 if l in ballot_input else 0
        ballot_m.append(m)
        ballot_e.append(ElGamal.Encrypt(pk, m, alpha_list[l]))

    if sum(ballot_m) != K:
        print(f'you should vote to {K} different candidates', file=sys.stderr)
        exit(-1)

    def send_ballot(conn):
        # send voter_id
        sendLine(conn, str(voter_id))

        # send ballot
        for l in range(L):
            sendLine(conn, str(ballot_e[l]))

        # prove sum of ballots is K
        e_sum = sum(ballot_e)
        alpha_sum = sum(alpha_list)
        prover = SigmaProtocol_K.Prover()
        e_ = prover.P1(e_sum, K, alpha_sum)
        sendLine(conn, str(e_))
        ch = int(recvLine(conn))
        beta = prover.P2(ch)
        sendLine(conn, str(beta))

        # prove every ballot is 0 or 1
        for l in range(L):
            prover = SigmaProtocol_01.Prover()
            e_ = prover.P1(ballot_e[l], ballot_m[l], alpha_list[l])
            sendLine(conn, str(e_[0]))
            sendLine(conn, str(e_[1]))
            ch_tmp = int(recvLine(conn))
            ch, beta = prover.P2(ch_tmp)
            sendLine(conn, str(ch[0]))
            sendLine(conn, str(ch[1]))
            sendLine(conn, str(beta[0]))
            sendLine(conn, str(beta[1]))

    connect_to(VOTE_PORT, send_ballot)


def obtain_public_key():
    def handler(conn):
        pk = ElGamal.PublicKey.from_str(recvLine(conn))
        return pk

    return connect_to(PUBLIC_KEY_PORT, handler)


def print_usage_and_exit():
    print(f'usage: python3 {__file__} --voter', file=sys.stderr)
    print(f'usage: python3 {__file__} --keygen', file=sys.stderr)
    print(f'usage: python3 {__file__} --accumulate', file=sys.stderr)
    exit(-1)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--voter':
        voter()

    elif len(sys.argv) == 2 and sys.argv[1] == '--keygen':
        keygen_party()

    elif len(sys.argv) == 2 and sys.argv[1] == '--accumulate':
        accumulate_ballot_party()

    else:
        print_usage_and_exit()



if __name__ == '__main__':
    main()
