#!/usr/share/env python3
from pwn import *


context.log_level = 'warning'
if __name__ == '__main__':
    host = 'cfta-nm01.allyourbases.co'
    port = 8017
    r = connect(host, port)
    data = r.recvuntil(b'\n').decode()
    data = bytes.fromhex(data.replace('\\x',''))
    r.sendline(data)
    print(r.recvall().decode())
