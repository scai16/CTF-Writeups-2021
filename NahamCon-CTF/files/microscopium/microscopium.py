#!/usr/bin/env python3
from base64 import b64decode
from hashlib import sha256
from itertools import product
from re import fullmatch
from string import digits


if __name__ == '__main__':
    cipher = b64decode('AA9VAhkGBwNWDQcCBwMJB1ZWVlZRVAENW1RSAwAEAVsDVlIAV00=')
    for c in product(digits, repeat=4):
        pin = ''.join(c).encode()
        key = sha256(b"pgJ2K9PMJFHqzMnqEgL" + pin)
        hash_str = key.hexdigest().encode()
        
        text = ''.join([chr(c ^ h) for c, h in zip(cipher, hash_str)])
        if fullmatch('^flag\{[0-9a-f]{32}\}$', text):
            print(f'Pin: {pin.decode()}')
            print(text)
            break
