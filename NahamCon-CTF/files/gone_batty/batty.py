#!/usr/bin/env python3
import re


with open('gone_batty', 'r') as f:
    data = f.read().split('\n')


if __name__ == '__main__':
    set_num = re.compile('^set /a (?P<k>[a-z]+)=(?P<n1>[0-9]+) %% (?P<n2>[0-9]+)$')
    set_exitcode = re.compile('^set (?P<k>[a-z]+)=%=exitcodeAscii%$')
    set_value = re.compile('^set (?P<k>[a-z]+)=(?P<v>.+)$')
    
    sets = {}
    for i, n in enumerate(data):
        if m := set_num.match(n):
            k = m.groupdict()['k']
            v = int(m.groupdict()['n1']) % int(m.groupdict()['n2'])
            sets[k] = v
        elif m := set_exitcode.match(n):
            k = m.groupdict()['k']
            v = chr(v)
        elif m := set_value.match(n):
            k = m.groupdict()['k']
            v = m.groupdict()['v']
            sets[k] = v
        else:
            continue
        for j in range(i+1, len(data)):
            k_str = f'%{k}%'
            if k_str in data[j]:
                data[j] = data[j].replace(k_str, str(v))

    flag = [''] * 38
    flag_re = re.compile('^:: set flag_character(?P<i>[0-9]+)=(?P<v>.)$')
    for i in data:
        if m := flag_re.match(i):
            flag[int(m.groupdict()['i'])-1] = m.groupdict()['v']
    print(''.join(flag))
