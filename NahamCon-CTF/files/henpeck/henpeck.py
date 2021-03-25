# Byte 0
MODIFIER_CODES = {
    0x01: '[LCTRL]', 0x02: '[LSHIFT]', 0x04: '[LALT]', 0x08: '[LMETA]',
    0x10: '[RCTRL]', 0x20: '[RSHIFT]', 0x40: '[RALT]', 0x80: '[RMETA]'
}

# Byte 2
KEY_CODES = {
    # Alphanumeric Keys
    0x04: ['a', 'A'], 0x05: ['b', 'B'], 0x06: ['c', 'C'], 0x07: ['d', 'D'],
    0x08: ['e', 'E'], 0x09: ['f', 'F'], 0x0A: ['g', 'G'], 0x0B: ['h', 'H'],
    0x0C: ['i', 'I'], 0x0D: ['j', 'J'], 0x0E: ['k', 'K'], 0x0F: ['l', 'L'],
    0x10: ['m', 'M'], 0x11: ['n', 'N'], 0x12: ['o', 'O'], 0x13: ['p', 'P'],
    0x14: ['q', 'Q'], 0x15: ['r', 'R'], 0x16: ['s', 'S'], 0x17: ['t', 'T'],
    0x18: ['u', 'U'], 0x19: ['v', 'V'], 0x1A: ['w', 'W'], 0x1B: ['x', 'X'],
    0x1C: ['y', 'Y'], 0x1D: ['z', 'Z'], 0x1E: ['1', '!'], 0x1F: ['2', '@'],
    0x20: ['3', '#'], 0x21: ['4', '$'], 0x22: ['5', '%'], 0x23: ['6', '^'],
    0x24: ['7', '&'], 0x25: ['8', '*'], 0x26: ['9', '('], 0x27: ['0', ')'],

    # Control Characters
    0x28: ['\n', '\n'], 0x29: ['[ESC]', '[ESC]'], 0x2b:['\t','\t'],
    0x2a: ['[BACKSPACE]', '[BACKSPACE]'],
    0x39: ['[CAPS LOCK]', '[CAPS LOCK]'],

    # Special Characters
    0x2C:[' ', ' '], 0x2D:['-', '_'], 0x2E:['=', '+'], 0x2F:['[', '{'],
    0x30:[']', '}'], 0x31:['\\', '|'],0x32:['`', '~'], 0x33:[';', ':'],
    0x34:["'", '"'], 0x36:[',', '<'], 0x37:['.', '>'], 0x38:['/', '?'],
    
    # Arrow Keys   
    0x4f: ['[RIGHT]', '[RIGHT]'], 0x50: ['[LEFT]', '[LEFT]'],
    0x51: ['[DOWN]', '[DOWN]'], 0x52: ['[UP]', '[UP]']
}


if __name__ == '__main__':
    with open('henpeck.txt', 'r') as f:
        data = f.read().strip().split('\n')

    text = ''
    for i in data:
        keypress = bytes.fromhex(i)
        if keypress[2] not in KEY_CODES:
            continue
        if keypress[0] == 0x02:
            text += KEY_CODES[keypress[2]][1]
        else:
            if keypress[0] != 0x00:
                text += MODIFIER_CODES[keypress[0]]
            text += KEY_CODES[keypress[2]][0]
    print(text)
