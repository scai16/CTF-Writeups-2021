#!/usr/bin/env python3
from pwn import *


context.log_level = 'warn'
def egcd(a, b):
    x, x1 = 1, 0
    y, y1 = 0, 1
    while b != 0:
        q, a, b = a//b, b, a%b
        x, x1 = x1, x-q*x1
        y, y1 = y1, y-q*y1
    # gcd, coefficient_a, coefficient_b
    return (a, x, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist.')
    else:
        return x % m

def recover_primes(n, e, d):
    m = d*e-1
    k = m
    while k%2 == 0:
        k >>= 1
    g = 2
    while g <= 100:
        r = k
        while r < m:
            y = pow(g, r, n)
            if y != 1 and y != (n-1) and pow(y, 2, n) == 1:
                p, *_ = egcd(n, y-1)
                assert (n % p) == 0 and p != 1 and p != n
                q = n//p
                return p, q
            r *= 2
        g += 1
    raise ValueError("Unable to recover primes.")

def decrypt_msg(key1, key2, c):
    p, q = recover_primes(key1['n'], key1['e'], key1['d'])
    phin = (p-1) * (q-1)
    key2['d'] = modinv(key2['e'], phin)
    m = pow(c, key2['d'], key2['n'])
    return m
    
def connect():
    host = 'phicorps-26aed53a.challenges.bsidessf.net'
    port = 25519
    r = remote(host, port)
    return r

def get_values(conn):
    conn.recvuntil(b'public modulus: ')
    n = int(conn.recvuntil(b'\n'))
    conn.recvuntil(b'Your public encryption exponent: ')
    e1 = int(conn.recvuntil(b'\n'))
    conn.recvuntil(b'Your private decryption exponent: ')
    d1 = int(conn.recvuntil(b'\n'))

    conn.recvuntil(b'public encryption exponent is ')
    e2 = int(conn.recvuntil(b'\n'))
    conn.recvuntil(b'Agent 7 was ')
    c = int(conn.recvuntil(b'\n'))
    
    key1 = {'n': n,
            'e': e1,
            'd': d1
           }
    key2 = {'n': n,
            'e': e2
           }
    return key1, key2, c


if __name__ == '__main__':
    r = connect()
    key1, key2, c = get_values(r)
    m = decrypt_msg(key1, key2, c)
    r.recvuntil(b'What was the message sent to Agent 7? ')
    r.sendline(str(m))
    flag = r.recvall()
    print(flag.strip().decode())
