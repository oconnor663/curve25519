import random
import sys

import nacl.c


def int_to_bytes(i):
    # I'm not sure relying on system byteorder is the right thing to do here.
    return i.to_bytes(32, sys.byteorder)


def bytes_to_int(b):
    return int.from_bytes(b, sys.byteorder)


def scalarmult_base(n):
    return bytes_to_int(nacl.c.crypto_scalarmult_base(int_to_bytes(n)))


def scalarmult(n, m):
    return bytes_to_int(nacl.c.crypto_scalarmult(
        int_to_bytes(n), int_to_bytes(m)))


def generate_key():
    # Note, this isn't a proper CSPRNG.
    client_prekey = random.randint(2**249, 2**250-1)
    client_key = 2**254 + 8*client_prekey
    server_prekey = random.randint(2**249, 2**250-1)
    server_key = 8 * server_prekey
    private_key = client_key + server_key
    public_key = scalarmult_base(private_key)
    return (client_key, server_key, public_key)
