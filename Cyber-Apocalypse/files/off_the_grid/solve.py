#!/usr/bin/env python3
import csv
from PIL import Image


def split_screens(data):
    screens = []
    for i in range(0, len(data), 64//8*128):
        screens.append(data[i:i + 64//8*128])
    return screens

def render_txt(data, background='white'):
    if background == 'white':
        on, off = '⬛', '⬜'
    elif background == 'black':
        on, off = '⬜', '⬛'
    else:
        raise ValueError(f'Invalid background color: {background}')
    pages = []
    for page in range(8):
        columns = data[page*128:page*128+128]
        rows = []
        for row in range(8):
            pixels = [on if col>>row&1 else off for col in columns]
            rows.append(''.join(pixels))
        pages.append('\n'.join(rows))
    return '\n'.join(pages)

def render_img(data, background='black', magnify=4):
    if magnify <= 0:
        raise ValueError(f'Magnify must be a positive integer')
    if background not in ['black', 'white']:
        raise ValueError(f'Invalid background color: {background}')
    pixels = b''
    for page in range(8):
        columns = data[page*128:page*128+128]
        rows = []
        for row in range(8):
            row_data = 0
            for col in columns:
                row_data = (row_data<<1)|(col>>row&1)
                if background == 'white':
                    row_data ^= 1
            pixels += row_data.to_bytes(128//8, 'big')
    img = Image.frombytes('1', (128, 64), pixels)
    return img.resize((128*magnify, 64*magnify))

def vertical_merge(imgs):
    width = max(img.width for img in imgs)
    height = sum(img.height for img in imgs)
    merged = Image.new('1', (width, height))
    h = 0
    for img in imgs:
        merged.paste(img, (0, h))
        h += img.height
    return merged


if __name__ == '__main__':
    with open('off_the_grid.csv', 'r') as f:
        reader = csv.DictReader(f)
        data = b''
        for row in reader:
            data += bytes([int(row['MOSI'], 16)])

    screens = split_screens(data)
    with open('screens.txt', 'wb') as f:
        for screen in screens:
            f.write(f'{render_txt(screen)}\n'.encode())
    img = vertical_merge([render_img(screen) for screen in screens])
    img.save('screens.png')
