#!/usr/bin/env python3
from pwn import *
from re import findall


context.log_level = 'warn'
def get_key():
    r.sendline(b'1')
    r.recvuntil(b'\n\n')
    key = r.recvuntil(b'\n\n', drop=True).decode()
    r.recvuntil(b'> ')

    key = re.findall('[^ ]+ -> \d+', key)
    key = dict(i.split(' -> ') for i in key)
    return key

def answer_question(key):
    r.recvuntil(b':\n\n')
    question = r.recvuntil(b'\n\n', drop=True).decode().split('=')[0].strip()
    for i in question:
        if i in key:
            question = question.replace(i, key[i])
    r.recvuntil(b'Answer: ')
    r.sendline(str(eval(question)).encode())


def take_test(key):
    r.sendline(b'2')
    for _ in range(500):
        answer_question(key)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3:
            raise ValueError
        host = sys.argv[1]
        port = int(sys.argv[2])
    except ValueError:
        raise ValueError(f'Usage: {sys.argv[0]} host port')
    r = remote(host, port)
    r.recvuntil(b'> ')
    key = get_key()
    take_test(key)
    response = r.recvuntil(b'\n\n')
    flag, = re.findall(b'CHTB{[^}]+}', response)
    print(flag.decode())
