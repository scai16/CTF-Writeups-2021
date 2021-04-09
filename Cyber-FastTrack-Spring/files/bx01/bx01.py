#!/usr/bin/env python3
from pwn import *


context.log_level = 'warning'
def connect(host, port):
    conn = remote(host, port)
    conn.recvuntil(b'angle brackets not terminated.\n')
    return conn

def terminatebrackets():
    i  = 1
    while True:
        r = connect(host, port)
        r.sendline(b'>' * i)
        if (data:=r.recvall()) and b"Error:" not in data:
            return data
        i += 1


if __name__ == '__main__':
    host = 'cfta-bx01.allyourbases.co'
    port = 8012
    response = terminatebrackets()
    print(response.decode())
