#!/usr/bin/env python3
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import pyshark


def get_tx_data():
    pcap = pyshark.FileCapture('low_energy_crypto.pcapng',
                               use_json=True,
                               include_raw=True)
    packet = pcap[229]
    data, *_ = packet.btatt.uart_tx_raw
    return bytes.fromhex(data).rstrip(b'\x00')

def decrypt_flag(data, key_file):
    with open(key_file, 'r') as f:
        key = RSA.importKey(f.read())
    cipher = PKCS1_v1_5.new(key)
    return cipher.decrypt(data, None)


if __name__ == '__main__':
    enc = get_tx_data()

    flag = decrypt_flag(enc, 'low_energy_crypto.key')
    print(flag.decode())
