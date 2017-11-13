from Crypto.PublicKey.RSA import importKey


def extended_euclid(a, b):
    r = a
    u = 1
    v = 0
    r2 = b
    u2 = 0
    v2 = 1

    while r2 != 0:
        q = r // r2
        (r, u, v, r2, u2, v2) = (r2, u2, v2, r - q * r2, u - q * u2, v - q * v2)
    return u


def byte_length(i):
    return (i.bit_length() + 7) // 8


def read_key(file):
    return importKey(open(file, "r").read()).key


def read_keys(pubf, prvf):
    pubk = read_key(pubf)
    prvk = read_key(prvf)
    return (pubk.e, pubk.n), (prvk.d, prvk.n)