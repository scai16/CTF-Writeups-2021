#!/usr/bin/env python3
import csv


def read_csv(filename):
    with open(filename, 'r') as f:
        data = csv.DictReader(f)
        return list(data)

def get_addr_data(data, addr):
    return bytes(int(x['Data'], 16) for x in data if x['Address'] == addr)


if __name__ == '__main__':
    csv_data = read_csv('compromised.csv')
    flag = get_addr_data(csv_data, '0x2C')
    print(flag.decode())
