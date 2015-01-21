import random
import sys

import nacl.c

from modular_inv import modular_inv
from modular_sqrt import modular_sqrt


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


def group_add(x1, x2):
    # Curve25519 constants
    p = 2*255 - 19
    a = 486662

    def compute_y(x):
        y = modular_sqrt(x**3 + a*x**2 + x, p)
        assert y != 0  # no quadratic residue
        return y

    y1 = compute_y(x1)
    y2 = compute_y(x2)

    if x1 == x2:
        lam = (3*x1**2 + a) * modular_inv(2*y1, p) % p
    else:
        lam = (y2 - y1) * modular_inv(x2 - x1, p) % p

    return (lam**2 - x1 - x2) % p
