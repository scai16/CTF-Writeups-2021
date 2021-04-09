#!/usr/bin/env python3


def substitute(msg, a, b):
    key = zip(a, b)
    for a, b in key:
        msg = msg.replace(a, b)
    return msg

if __name__ == '__main__':
    with open('cm02.txt', 'r') as f:
        data = f.read()

    emojis = filter(lambda c: ord(c) > 256, set(data))
    out = substitute(data, emojis, 'abcdefghijklmnopqrstuvwxyz')

    with open('cm02_alpha.txt', 'w') as f:
        f.write(out)
