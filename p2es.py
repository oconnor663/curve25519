#! /usr/bin/env python3

import random
import sys

import nacl.c

from modular_inv import modular_inv
from modular_sqrt import modular_sqrt


# curve25519 parameters
P = 2**255 - 19
A = 486662


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


def compute_y(x):
    y = modular_sqrt(x**3 + A*x**2 + x, P)
    assert y != 0  # no quadratic residue
    return y


def compute_l(x1, x2):
    y1 = compute_y(x1)
    y2 = compute_y(x2)
    if x1 == x2:
        # https://en.wikipedia.org/wiki/Montgomery_curve#Doubling
        return (3*x1**2 + 2*A*x1 + 1) * modular_inv(2 * y1, P) % P
    else:
        # https://en.wikipedia.org/wiki/Montgomery_curve#Addition
        return (y2 - y1) * modular_inv(x2 - x1, P) % P


def group_add(x1, x2):
    return (compute_l(x1, x2)**2 - A - x1 - x2) % P


def compute_shared_key(client_key, server_key, recipient_public):
    # This is the work the server does, using only what the server knows.
    Y = scalarmult(server_key, recipient_public)
    # This is the work the client does, using only what the client knows plus
    # Y from the server.
    X = scalarmult(client_key, recipient_public)
    return group_add(X, Y)


def update_key(client_key, server_key):
    # The client's work. Note again, not a CSPRNG.
    d = random.randint(-2**220, 2**220)
    new_client_key = client_key + 8*d
    # The server's work, after receiving d from the client.
    # NOTE: I think there is a typo in the spec here.
    new_server_key = server_key - 8*d
    return new_client_key, new_server_key


def main():
    c1, s1, p1 = generate_key()
    print("c1", c1)
    print("s1", s1)
    print("p1", p1)
    print()

    c2, s2, p2 = generate_key()
    print("c2", c2)
    print("s2", s2)
    print("p2", p2)
    print()

    # Print these out so that we can see they're equal. (They're not right now,
    # because something is broken.)
    print('shared key', compute_shared_key(c1, s1, p2))
    print('other way ', compute_shared_key(c2, s2, p1))


if __name__ == '__main__':
    main()
