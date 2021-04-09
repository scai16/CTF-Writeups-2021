#!/usr/bin/env python3
from itertools import product
from mnemonic import Mnemonic


def recover_phrase():
    m = Mnemonic('english')
    four = [w for w in m.wordlist if len(w) == 4]
    six = [w for w in m.wordlist if len(w) == 6]
    for i in product(four, six):
        mnemonic = phrase + ' '.join(i)
        if m.check(mnemonic) and m.to_seed(mnemonic).hex().startswith(seed):
            return mnemonic


if __name__ == '__main__':
    seed = '131c553f7fb4127e7b2b346991dd92'
    phrase = 'nature midnight buzz toe sleep fence kiwi ivory excuse system '
    passphrase = recover_phrase()
    print(passphrase)
