#!/usr/bin/env python3
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes


def egcd(a, b):
    (x, x1), (y, y1) = (1, 0), (0, 1)
    while b != 0:
        q, a, b = a//b, b, a%b
        x, x1 = x1, x  - q * x1
        y, y1 = y1, y - q * y1
    # gcd, coefficient_a, coefficient_b
    return (a, x, y)


if __name__ == '__main__':
    with open('1.pub', 'r') as f:
        key1 = RSA.importKey(f.read())
    with open('2.pub', 'r') as f:
        key2 = RSA.importKey(f.read())

    with open('m1.enc', 'r') as f:
        c1 = bytes_to_long(b64decode(f.read()))
    with open('m2.enc', 'r') as f:
        c2 = bytes_to_long(b64decode(f.read()))

    if key1.n != key2.n:
        raise ValueError('Keys do not have a common modulus.')

    gcd, a, b  = egcd(key1.e, key2.e)
    if gcd != 1:
        raise ValueError('Public exponents must be coprime.')

    m = (pow(c1, a, key1.n) * pow(c2, b, key2.n)) % key1.n
    flag = long_to_bytes(m)
    print(flag.decode())
