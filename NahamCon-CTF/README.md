# NahamCon CTF 2021

![CTFtime Weight: 24.98](https://img.shields.io/badge/CTFtime%20Weight-24.98-critical) ![Teams Participated: 3418](https://img.shields.io/badge/Teams%20Participated-3418-informational)

**Fri, 12 March 2021, 20:00 UTC — Sun, 14 March 2021, 20:00 UTC**

```
From the developers of VirSecCon, NahamCon 2020, H@cktivityCon, BsidesBOS and GRIMMCon 0x3 CTF, we bring you NahamCon CTF 2021!

For information on the NahamCon conference, check out https://nahamcon.com

Registration for the CTF will be accessible at https://ctf.nahamcon.com as the event comes closer.

Special thank you to all of the events sponsors!

```

[![https://ctftime.org/event/1281](https://img.shields.io/badge/CTFtime-white?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABYUlEQVR42pxTTUtCQRQ9973xSZbiTgghCNu0sidu2vcDWrjpJ7Zu3TqILAjaVeu2gYqWczvzhVZi6cCduY+Zc+6Z8+6IquJWDhVbDvNyIJW+qqAtClnacXmeTjGyFWieMRb4oAJ4Eik2VuK40d9/JVsh0BlJWiTRzQji4BVanN9IcqzbEHgOgrk8CfLev0gynXO2iFPESE8wvyMJv836MDvNGm0kaEIxtsqQIKVeArOhoHmyVolplx1gzOyIwBFjwvNjqhmhAkdd+8sDjaanG4So4vl+ik6pqMl3j9aamPnmKPBIcJcm7snvzknD2h8EvtOyKm6GU5yWESwrRFOF1bhHEz0wgAtcE3zGyvXYt9mK/vWVJaxs3qBAWPmKss8JbjighAIiizdg0ypBgf9b1ito4PLhHRddxS5PmywQ5MtEWBjtgM74ufhc3HPGgC8xXcXEV5giEdilcM33GfIvAQYAhHKA5j9Rx1UAAAAASUVORK5CYII=)](https://ctftime.org/event/1281)

## Challenges

- [Abyss](#abyss) ![Miscellaneous](https://img.shields.io/badge/Miscellaneous-purple)
- [Alphabet Soup](#alphabet-soup) ![Miscellaneous](https://img.shields.io/badge/Miscellaneous-purple)
- [Andra](#andra) ![Mobile](https://img.shields.io/badge/Mobile-green)
- [Car Keys](#car-keys) ![Warmups](https://img.shields.io/badge/Warmups-yellow)
- [Chicken Wings](#chicken-wings) ![Warmups](https://img.shields.io/badge/Warmups-yellow)
- [Dice Roll](#dice-roll) ![Cryptography](https://img.shields.io/badge/Cryptography-blue)
- [Eighth Circle](#eighth-circle) ![Warmups](https://img.shields.io/badge/Warmups-yellow)
- [esab64](#esab64) ![Warmups](https://img.shields.io/badge/Warmups-yellow)
- [Gone Batty](#gone-batty) ![Miscellaneous](https://img.shields.io/badge/Miscellaneous-purple)
- [Henpeck](#henpeck) ![Forensics](https://img.shields.io/badge/Forensics-darkorange)
- [Imposter](#imposter) ![Web](https://img.shields.io/badge/Web-brightgreen)
- [Microscopium](#microscopium) ![Mobile](https://img.shields.io/badge/Mobile-green)
- [Prison Break](#prison-break) ![Miscellaneous](https://img.shields.io/badge/Miscellaneous-purple)
- [Shoelaces](#shoelaces) ![Warmups](https://img.shields.io/badge/Warmups-yellow)

### Mission Challenges

- [**Introduction**](#the-mission--introduction)
  - [The Mission](#the-mission)
  - [Bionic](#bionic)
  - [Meet The Team](#meet-the-team)
- [**Path 1**](#the-mission--path-1)
  - [Leo](#leo)
- [**Path 2**](#the-mission--path-2)
  - [Hercules](#hercules)
- [**Path 3**](#the-mission--path-3)
  - [Orion](#orion)
- [**Path 4**](#the-mission--path-4)
  - [Gus](#gus)
- [**Path 5**](#the-mission--path-5)
  - [Lyra](#lyra)

## To Do

- [ ] $Echo ![Web](https://img.shields.io/badge/Web-brightgreen)
- [ ] Bad Blog ![Web](https://img.shields.io/badge/Web-brightgreen)
- [ ] Buzz ![Warmups](https://img.shields.io/badge/Warmups-yellow)
- [ ] Cereal and Milk ![Web](https://img.shields.io/badge/Web-brightgreen)
- [ ] Pollex ![Warmups](https://img.shields.io/badge/Warmups-yellow)
- [ ] Resourceful ![Mobile](https://img.shields.io/badge/Mobile-green)
- [ ] Zenith ![Miscellaneous](https://img.shields.io/badge/Miscellaneous-purple)

---

## Abyss

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Solves: 1017](https://img.shields.io/badge/Solves-1017-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Miscellaneous](https://img.shields.io/badge/Miscellaneous-purple)

**Challenge Description**

```
Author: @JohnHammond#6971

A Vortex? No... an Abyss.

Click the Start button on the top-right to start this challenge.
```

### Flag

```
flag{db758a0cc25523993416c305ef15f9ad}
```

### Solution

Whe we start the instance, we are given ssh credentials. The server keeps sending a lot of random characters, but the flag is hidden in the text. Send the output to a file, wait a little bit and exit, then search for the flag in the text.

```bash
$ ssh -p 30459 user@challenge.nahamcon.com > out.txt
$ egrep -o "flag\{[^\}]+\}" out.txt
flag{db758a0cc25523993416c305ef15f9ad}
```

[*Back to top*](#nahamcon-ctf-2021)

---

## Alphabet Soup

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 135](https://img.shields.io/badge/Solves-135-brightgreen) ![Points: 461](https://img.shields.io/badge/Points-461-blue)

**Challenge Category**

![Miscellaneous](https://img.shields.io/badge/Miscellaneous-purple)

**Challenge Description**

```
Author: @JohnHammond#6971

A, B, C, and V, G, L, Y... wait a second, that's not how the song goes!
```

**Challenge Files**

[alphabet_soup.cs](files/alphabet_soup/alphabet_soup.cs)

### Flag

```
flag{b6cfb6656ea0ac92849a06ead582456c}
```

### Summary

The script contains a large blob of text which contains a file encoded with a modified `base64`. Modify the script to save the file instead of execute it. Use `strings` on the file to get the flag.

### Solution

We are provided with a `C#` script which contains some obfuscated code and a very large blob of text:

```cs
using System; using System.Collections.Generic; using System.Text;using System.IO; using System.Reflection; using System.Linq;
namespace RAKSVwqLMTDsnB { class pcuMyzvAxeBhINN { private static string zcfZIEShfvKnnsZ(string t, string k) {
string bnugMUJGJayaT = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
string WgUWdaUGBFwgN = ""; Dictionary<char, char> OrnBLfjI = new Dictionary<char, char>();
for (int i = 0; i < bnugMUJGJayaT.Length; ++i){ OrnBLfjI.Add(k[i], bnugMUJGJayaT[i]); }
for (int i = 0; i < t.Length; ++i){ if ((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= 'a' && t[i] <= 'z')) { WgUWdaUGBFwgN += OrnBLfjI[t[i]];}
else { WgUWdaUGBFwgN += t[i]; }} return WgUWdaUGBFwgN; }
static void Main() {
string pTIxJTjYJE =
...
;
string YKyumnAOcgLjvK = "lQwSYRxgfBHqNucMsVonkpaTiteDhbXzLPyEWImKAdjZFCOvJGrU";
Assembly smlpjtpFegEH = Assembly.Load(Convert.FromBase64String(zcfZIEShfvKnnsZ(pTIxJTjYJE, YKyumnAOcgLjvK)));
MethodInfo nxLTRAWINyst = smlpjtpFegEH.EntryPoint;
nxLTRAWINyst.Invoke(smlpjtpFegEH.CreateInstance(nxLTRAWINyst.Name), null);
}}}
```

If we tidy up the code a bit and rename the variables, we get something that looks like this:

```cs
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Reflection;
using System.Linq;
namespace alphabet_soup {
    class hide_flag {
        private static string substitution(string t, string k) {
            string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string result = "";
            Dictionary < char, char > substitute = new Dictionary < char, char > ();
            for (int i = 0;
            i < alphabet.Length; ++i) {
                substitute.Add(k[i], alphabet[i]);
            }

            for (int i = 0;
            i < t.Length; ++i) {
                if ((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= 'a' && t[i] <= 'z'))  {
                    result += substitute[t[i]];
                } else {
                    result += t[i];
                }

            }

            return result;
        }

        static void Main() {
            string text =
            ...
            ;
            string key = "lQwSYRxgfBHqNucMsVonkpaTiteDhbXzLPyEWImKAdjZFCOvJGrU";
            Assembly file = Assembly.Load(Convert.FromBase64String(substitution(text, key)));
            MethodInfo file_entry = file.EntryPoint;
            file_entry.Invoke(file.CreateInstance(file_entry.Name), null);
        }

    }

}
```

Cool, now it's a lot easier to understand what's going on. It looks like the first function is just a simple substitution cipher. In `Main`, it runs the substitution cipher on the large blob of text and then attempts to run it. Of course, you should never execute random code on your computer, even if it came from a CTF challenge. So I commented out the lines that attempt to execute the code. Instead, I added a couple lines of code to write the contents to a file for me to reverse engineer.

```cs
            using (BinaryWriter writer = new BinaryWriter(File.Open("out", FileMode.Create)))
            {
                writer.Write(Convert.FromBase64String(scramble_alphabet(data, key)));
            }
            // Assembly decoded = Assembly.Load(Convert.FromBase64String(scramble_alphabet(data, key)));
            // MethodInfo what = decoded.EntryPoint;
            // what.Invoke(decoded.CreateInstance(what.Name), null);
```

Luckily, there wasn't any reverse engineering needed.

```bash
$ egrep -aio "flag\{[^\}]+\}" out
flag{b6cfb6656ea0ac92849a06ead582456c}
```

[*Back to top*](#nahamcon-ctf-2021)

---

## Andra

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Solves: 605](https://img.shields.io/badge/Solves-605-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Mobile](https://img.shields.io/badge/Mobile-green)

**Challenge Description**

```
Author: dead#4282 & @JohnHammond#6971

You know what to do. :)
```

**Challenge Files**

[andra.apk](files/andra/andra.apk)

### Flag

```
flag{d9f72316dbe7ceab0db10bed1a738482}
```

### Solution

Unzip the apk and `grep` for the flag.

```bash
$ unzip -q andra.apk
$ egrep -aior "flag\{[^\}]+\}"
res/layout-v17/activity_flag.xml:flag{d9f72316dbe7ceab0db10bed1a738482}
res/layout/activity_flag.xml:flag{d9f72316dbe7ceab0db10bed1a738482}
```

[*Back to top*](#nahamcon-ctf-2021)

---

## Car Keys

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Solves: 844](https://img.shields.io/badge/Solves-844-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Warmups](https://img.shields.io/badge/Warmups-yellow)

**Challenge Description**

```
Author: @JohnHammond#6971

We found this note on someone's key chain! It reads... ygqa{6y980e0101e8qq361977eqe06508q3rt}? There was another key that was engraved with the word QWERTY, too...
```

### Flag

```
flag{6f980c0101c8aa361977cac06508a3de}
```

### Solution

The flag is encrypted with a `Keyed Caesar` cipher. You can decrypt it with [Rumkin](http://rumkin.com/tools/cipher/caesar-keyed.php).

![car_keys1.jpg](img/screenshots/car_keys1.jpg)

[*Back to top*](#nahamcon-ctf-2021)

---

## Chicken Wings

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Solves: 1111](https://img.shields.io/badge/Solves-1111-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Warmups](https://img.shields.io/badge/Warmups-yellow)

**Challenge Description**

```
Author: @JohnHammond#6971

I ordered chicken wings at the local restaurant, but uh... this really isn't what I was expecting...
```

**Challenge Files**

[chicken_wings](files/chicken_wings/chicken_wings)

### Flag

```
flag{e0791ce68f718188c0378b1c0a3bdc9e}
```

### Solution

The flag is encoded in `Wingdings`. Copy and paste into [dcode.fr](https://www.dcode.fr/wingdings-font) to get the flag.

[*Back to top*](#nahamcon-ctf-2021)

---

## Dice Roll

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 201](https://img.shields.io/badge/Solves-201-brightgreen) ![Points: 406](https://img.shields.io/badge/Points-406-blue)

**Challenge Category**

![Cryptography](https://img.shields.io/badge/Cryptography-blue)

**Challenge Description**

```
Author: @JohnHammond#6971

When you have just one source of randomness, it's "a die", but when you can have muliple -- it's 'dice!'

NOTE: You are welcome to "brute force" this challenge if you feel you need to. ;)
```

**Challenge Files**

[dice_roll.py](files/dice_roll/dice_roll.py)

### Flag

```
flag{e915b62b2195d76bfddaac0160ed3194}
```

### Summary

The program uses the `random` module to generate the dice rolls. The `random` module is insecure because it can be predicted after a certain amount of iterations. Use the [Mersenne Twister Predictor](https://github.com/kmyk/mersenne-twister-predictor) to recover the seed and guess the next dice roll.

### Solution

This challenge is a standard PRNG (Pseudo-Random Number Generator) predictor challenge. Since they provided us with the source code, we don't even need to connect to the server to figure out how to solve it.

Here's the relevant snippets of code to figure out that it was a PRNG predictor challenge and how to solve it:

```python
dice_bits = 32
```

This tells us how many bits are being used during each iteration. You will need to provide this to the predictor so it can work properly.

```python
random.seed(os.urandom(dice_bits))
```

The important thing to note is that the seed will only be changed if you select option `2`. This is important because the PRNG that the `random` module uses, the [Mersenne Twister Predictor](https://github.com/kmyk/mersenne-twister-predictor), can be recover the seed after 624 iterations using the same seed.

And that's all you need to know to solve the challenge. Now we just have to write our solver script and run it.

```python
#!/usr/bin/env python3
from pwn import *
from mt19937predictor import MT19937Predictor


context.log_level = 'warning'
def connect(host, port):
    conn = remote(host, port)
    conn.recvuntil(b'>')
    return conn

def roll_dice(conn):
    conn.sendline(b'2')
    conn.recvuntil(b'the sum was:\n')
    roll = conn.recvuntil(b'\n')
    conn.recvuntil(b'>')
    return int(roll)

def recover_seed(conn):
    predictor = MT19937Predictor()
    for _ in range(624):
        i = roll_dice(conn)
        predictor.setrandbits(i, 32)
    return predictor


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise ValueError(f'Usage: {sys.argv[0]} host port')
    r = connect(sys.argv[1], sys.argv[2])
    p = recover_seed(r)
    assert roll_dice(r) == p.getrandbits(32)
    r.sendline(b'3')
    r.recvuntil(b'>')
    r.sendline(str(p.getrandbits(32)).encode())
    r.recvuntil(b'Here is your flag:\n')
    print(r.recvline(False).decode())
```

```bash
$ python dice.py challenge.nahamcon.com 31781
flag{e915b62b2195d76bfddaac0160ed3194}
```

### References

[Mersenne Twister Predictor](https://github.com/kmyk/mersenne-twister-predictor)

[*Back to top*](#nahamcon-ctf-2021)

---

## Eighth Circle

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Solves: 839](https://img.shields.io/badge/Solves-839-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Warmups](https://img.shields.io/badge/Warmups-yellow)

**Challenge Description**

```
Author: @JohnHammond#6971

Abandon all hope, ye who enter here...
```

**Challenge Files**

[eighth_circle](files/eighth_circle/eighth_circle)

### Flag

```
flag{bf201f669b8c4adf8b91f09165ec8c5c}
```

### Solution

The challenge name hints towards [Malbolge](https://en.wikipedia.org/wiki/Malbolge). Use an online [interpreter](https://malbolge.doleczek.pl/) to retrieve the flag.

[*Back to top*](#nahamcon-ctf-2021)

---

## esab64

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Solves: 1846](https://img.shields.io/badge/Solves-1846-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Warmups](https://img.shields.io/badge/Warmups-yellow)

**Challenge Description**

```
Author: @JohnHammond#6971

Was it a car or a cat I saw?
```

**Challenge Files**

[esab64](files/esab64/esab64)

### Flag

```
flag{fb5211b498afe87b1bd0db601117e16e}
```

### Solution

File contains a reversed base64 encoded string of the flag, which is also reversed.

```
$ rev esab64 | base64 -d | rev
flag{fb5211b498afe87b1bd0db601117e16e}_
```

[*Back to top*](#nahamcon-ctf-2021)

---

## Gone Batty

![Difficulty: Hard](https://img.shields.io/badge/Difficulty-Hard-red) ![Solves: 79](https://img.shields.io/badge/Solves-79-brightgreen) ![Points: 489](https://img.shields.io/badge/Points-489-blue)

**Challenge Category**

![Miscellaneous](https://img.shields.io/badge/Miscellaneous-purple)

**Challenge Description**

```
Author: @JohnHammond#6971

Happy 100th, Trickbot!
```

**Challenge Files**

[gone_batty](files/gone_batty/gone_batty)

### Flag

```
flag{b395cc3e33cdebbec9d117292bd2e81c}
```

### Summary

The flag is obfuscated with a lot of layers of substitution. The individual portions of the flag are hidden in comments so running the script will not show the flag. You have to evaluate the script line by line to recover the comments, then parse the comments for the flag.

### Solution

For this challenge, we are provided with a 7MB `bat` file. The file is large because the flag was heavily obfuscated behind layers and layers of substitutions using the `set` command. We can parse the file and recover the flag using this [script](files/gone_batty/batty.py):

```python
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
```

```bash
$ ./batty.py
flag{b395cc3e33cdebbec9d117292bd2e81c}
```

[*Back to top*](#nahamcon-ctf-2021)

---

## Henpeck

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 382](https://img.shields.io/badge/Solves-382-brightgreen) ![Points: 124](https://img.shields.io/badge/Points-124-blue)

**Challenge Category**

![Forensics](https://img.shields.io/badge/Forensics-darkorange)

**Challenge Description**

```
Author: @JohnHammond#6971

So I'll be honest, I never actually went through the Mavis Beacon program...
```

**Challenge Files**

[henpeck.pcap](files/henpeck/henpeck.pcap)

### Flag

```
flag{f7733e0093b7d281dd0a30fcf34a9634}
```

### Summary

The pcap contains keyboard input traffic. Decode the data using `Table 12` of [HID Usage Tables](https://usb.org/sites/default/files/documents/hut1_12v2.pdf) to retrieve the flag.

### Solution

For this challenge, we are provided with a pcap of USB data. Based off the source and destination addresses, we can see that there are four different USB devices in this pcap, but only one is sending data to the host, device `9`. We can probably assume the device is a keyboard and it is typing out the flag. That means we probably only care about the inputs from the device. We can filter on that by using the filter `usb.urb_type == URB_COMPLETE`. We also see a bunch of packets where all the data is `\x00`. We don't need that so we can filter it out as well. Great. Now let's extract the data so we can decode it.

```bash
tshark -nr henpeck.pcap -Y "usb.capdata && (usb.device_address == 9) && (usb.urb_type == 'C') && !(usb.capdata == 00:00:00:00:00:00:00:00)" -T fields -e usb.capdata > henpeck.txt
```

Now to decode it. We can use the [HID Usage Tables](https://usb.org/sites/default/files/documents/hut1_12v2.pdf) as a reference to the character mappings. The keyboard layout is in `Table 12`. It's also important to note that if the first byte has the value `\x02`, it indicates the `Shift` key is being pressed.

```python
MODIFIER_CODES = {
    0x01: '[LCTRL]', 0x02: '[LSHIFT]', 0x04: '[LALT]', 0x08: '[LMETA]',
    0x10: '[RCTRL]', 0x20: '[RSHIFT]', 0x40: '[RALT]', 0x80: '[RMETA]'
}

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
```

```bash
$ ./henpeck.py
so the answer is flag{f7733e0093b7d281dd0a30fcf34a9634} hahahah lol
[LCTRL]c
```

### References

[HID Usage Tables](https://usb.org/sites/default/files/documents/hut1_12v2.pdf)

[*Back to top*](#nahamcon-ctf-2021)

---

## Imposter

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 71](https://img.shields.io/badge/Solves-71-brightgreen) ![Points: 492](https://img.shields.io/badge/Points-492-blue)

**Challenge Category**

![Web](https://img.shields.io/badge/Web-brightgreen)

**Challenge Description**

```
Author: @congon4tor#2334

Are you who you say you are? How can you be not?
```

### Flag

```
flag{9cd73159b385acb823ad1b4d3f9a924c}
```

### Summary

Send a password reset for the `admin` account by concatenating it to the end of your password reset. Then recreate the `admin` account's TOTP authentication code to login with.

### Solution

We start off by creating an account on the website. Make sure you use a real email for the signup. After you create your account, you should see a QR code. I used the username `user`.

![imposter1.jpg](img/screenshots/imposter1.jpg)

The QR code is intended to be used along with a `Google Authenticator` app. However, depending on the length of the username you signed up with, the QR code may not scan correctly. If you decode the QR code, it should look something like this:

```
otpauth://totp/2Password:user?secret=OVZWK4RRGIZTINJWG44DS%3D%3D%3D&issuer=2Password
```

The `Google Authenticator` app will not accept a QR code with the padding on the secret. If you want it to scan properly, remove the `%3D`s from the secret and regenerate a QR code with the new link. Before we move on, let's try to understand how this uri is created. If you need to, create one or two more accounts to compare against.

The first part, `otpauth://totp` is static. The next part `2Password` and the last part `&issuer=2Password` are also static.

The `:user` is obviously based on the username.

Last, but not least, we have the `?secret=OVZWK4RRGIZTINJWG44DS%3D%3D%3D`. It turns out the secret is encoded with base32.

This is what it decodes to:

```
user123456789
```

It looks like the secret is just the username + `123456789`.

Interesting. Using this format, we can generate a valid code for the `admin` account.

![imposter2.jpg](img/screenshots/imposter2.jpg)

Now we just have to figure out how to get in the `admin` account.

We see there's a password reset on the home page. Maybe we can trigger a password reset for the admin account?

If we watch the password reset process in `Burp Suite`, we can see this is what a normal password reset looks like:

![imposter3.jpg](img/screenshots/imposter3.jpg)

If you follow through with the process, you should receive a password reset at the email you signed up with. After a bit of messing around, we find out that we can trigger a password reset for `admin` by doing this:

![imposter4.jpg](img/screenshots/imposter4.jpg)

This triggers a password reset for `admin`, but the reset link is sent to your email instead. If you follow through with the reset password process, you can change the admin password to anything you want. Now we can just log in to the `admin` account and get the flag.

![imposter5.jpg](img/screenshots/imposter5.jpg)

[*Back to top*](#nahamcon-ctf-2021)

---

## Microscopium

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 108](https://img.shields.io/badge/Solves-108-brightgreen) ![Points: 476](https://img.shields.io/badge/Points-476-blue)

**Challenge Category**

![Mobile](https://img.shields.io/badge/Mobile-green)

**Challenge Description**

```
Author: @congon4tor#2334

This cool app will keep your secrets!
```

**Challenge Files**

[microscopium.apk](files/microscopium/microscopium.apk)

### Flag

```
flag{06754e57e02b0c505149cd1055ba5e0b}
```

### Summary

The flag is hidden within the `assets/index.android.bundle` file in the apk. Reverse the function containing the flag and decode the text to get the flag.

### Solution

We start of by unzipping the contents of `microscopium.apk` to see the source code:

```bash
unzip microscopium.apk
```

Let's start by seeing if there are any interesting strings in any of theses files:

```bash
grep -ir flag
```

This came back with a lot more results than I wanted, but one of the results caught my eye.

![microscopium1.jpg](img/screenshots/microscopium1.jpg)

Let's take a closer look at this function.

If we clean it up a bit, we see this:

```js
function b() {
    var t;
    (0, o.default)(this, b);
    for (var n = arguments.length, l = new Array(n) , u = 0;
    u < n;
    u++)l[u] = arguments[u];
    return(t = v.call.apply(v, [this].concat(l))).state = {
        output:'Insert the pin to get the flag', text:''
    }, t.partKey = "pgJ2K9PMJFHqzMnqEgL", t.cipher64 = "AA9VAhkGBwNWDQcCBwMJB1ZWVlZRVAENW1RSAwAEAVsDVlIAV00=", t.onChangeText = function(n) {
        t.setState( {
            text:n
        }

        )
    }, t.onPress = function() {
        var n = p.Base64.toUint8Array(t.cipher64), o = y.sha256.create();
        o.update(t.partKey), o.update(t.state.text);
        for (var l = o.hex() , u = "", c = 0;
        c < n.length;
        c++)u += String.fromCharCode(n[c]^l.charCodeAt(c));
        t.setState( {
            output:u
        }

        )
    }, t
}
```

Let's reverse this function and try to brute force the pin:

```python
#!/usr/bin/env python3
from base64 import b64decode
from hashlib import sha256
from itertools import product
from re import fullmatch
from string import digits


if __name__ == '__main__':
    cipher = b64decode('AA9VAhkGBwNWDQcCBwMJB1ZWVlZRVAENW1RSAwAEAVsDVlIAV00=')
    for c in product(digits, repeat=4):
        pin = ''.join(c).encode()
        key = sha256(b"pgJ2K9PMJFHqzMnqEgL" + pin)
        hash_str = key.hexdigest().encode()
        text = ''.join([chr(c ^ h) for c, h in zip(cipher, hash_str)])
        if fullmatch('^flag\{[0-9a-f]{32}\}$', text):
            print(f'Pin: {pin.decode()}')
            print(text)
            break
```

```bash
$ ./microscopium.py
Pin: 4784
flag{06754e57e02b0c505149cd1055ba5e0b}
```

[*Back to top*](#nahamcon-ctf-2021)

---

## Prison Break

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 170](https://img.shields.io/badge/Solves-170-brightgreen) ![Points: 436](https://img.shields.io/badge/Points-436-blue)

**Challenge Category**

![Miscellaneous](https://img.shields.io/badge/Miscellaneous-purple)

**Challenge Description**

```
Author: @JohnHammond#6971

Read the flag.txt file that is /just/out/of/reach.
```

### Flag

```
flag{1345fd3cb55434ba17d9b64ca350ec78}
```

### Solution

Quote the path to the file and read it.

```bash
user@host:/home/user$ cat '/just/out/of/reach/flag.txt'
cat '/just/out/of/reach/flag.txt'
flag{1345fd3cb55434ba17d9b64ca350ec78}
```

[*Back to top*](#nahamcon-ctf-2021)

---

## Shoelaces

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Solves: 2248](https://img.shields.io/badge/Solves-2248-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Warmups](https://img.shields.io/badge/Warmups-yellow)

**Challenge Description**

```
Author: @JohnHammond#6971

Do you double-knot your shoelaces? You gotta keep'em tied!
```

**Challenge Files**

[shoelaces.jpg](files/shoelaces/shoelaces.jpg)

### Flag

```
flag{137288e960a3ae9b148e8a7db16a69b0}
```

### Solution

The name of the challenge hints towards `strings`. Search for a string matching the flag format in the file.

```bash
$ egrep -aio 'flag\{[^\}]+\}' shoelaces.jpg
flag{137288e960a3ae9b148e8a7db16a69b0}
```

---

## The Mission — Introduction

### The Mission

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Solves: 1991](https://img.shields.io/badge/Solves-1991-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Mission](https://img.shields.io/badge/Mission-orange)

**Challenge Description**

```
Author: @JohnHammond#6971

Enter the flag you find on The Mission page to open the gates and unlock challenges for The Mission. Please note, your participation in "The Mission" serves as permission for us to share your e-mail address with our sponsors, for potential career opportunities and private invitations to vulnerability disclosure and bug bounty programs.
```

#### Flag

```
flag{48e117a1464c3202714dc9a350533a59}
```

#### Solution

Flag is in the source code of [The Mission](https://ctf.nahamcon.com/mission).

```html
<!-- Thank you for reading the rules! Your flag is: -->
<!--   flag{48e117a1464c3202714dc9a350533a59}       -->
```

[*Back to top*](#nahamcon-ctf-2021)

---

### Bionic

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Solves: 1353](https://img.shields.io/badge/Solves-1353-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Mission](https://img.shields.io/badge/Mission-orange)

**Challenge Description**

```
Author: @JohnHammond#6971

Thank you for taking on The Mission. You can begin by exploring the CONSTELLATIONS public website, constellations.page.

CONSTELLATIONS has "tried" to reduce their attack surface by offering just a static website. But you might find some low-hanging fruit to get you started.

You should find the flag for this challenge ON THIS constellations.page website.

With the flag of this challenge, you should also find a new URL that will assist in the next challenge.

```

#### Flag

```
flag{33b5240485dda77430d3de22996297a1}
```

#### Solution

The title of the challenge, `Bionic`, hints towards the `robots.txt` file.

```bash
$ curl https://constellations.page/robots.txt
User-agent: *
Disallow: /meet-the-team.html

flag{33b5240485dda77430d3de22996297a1}  # this flag is for `Bionic`
```

[*Back to top*](#nahamcon-ctf-2021)

---

### Meet The Team

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Solves: 873](https://img.shields.io/badge/Solves-873-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Mission](https://img.shields.io/badge/Mission-orange)

**Challenge Description**

```
Author: @JohnHammond#6971

Recover the list of employees working at CONSTELLATIONS.

With the flag of this challenge, you should find new information that will help with future challenges.

You should find the flag for this challenge ON THIS constellations.page website. You will not find it on GitHub.

HINT: "Can we please stop sharing our version control software out on our website?"

HINT AGAIN: you are looking for a publicly accessible version control software folder published on the constellations.page website itself
```

#### Flag

```
flag{4063962f3a52f923ddb4411c139dd24c}
```

#### Solution

We know from the previous challenge that there is a hidden page at `https://constellations.page/meet-the-team.html`. Unfortunately it has been redacted.

![meet_the_team1.jpg](img/screenshots/meet_the_team1.jpg)

Using a browser extension called `DotGit`, we find that there is an exposed [.git](files/meet_the_team/]) repository for this site.

![meet_the_team2.jpg](img/screenshots/meet_the_team2.jpg)

We extract the `.git` and start poking around:

```bash
$ git log
commit e7d4663ac6b436f95684c8bfc428cef0d7731455 (HEAD)
Author: Leo Rison <leo.rison@constellations.page>
Date:   Tue Feb 23 19:20:14 2021 -0500

    Management said I need to remove the team details so I redacted that page and added it to robots.txt

commit 4c88ac1c56fe228267cf415c3ef87d7c3b8abd60
Author: Leo Rison <leo.rison@constellations.page>
Date:   Tue Feb 23 19:19:32 2021 -0500

    Added the Meet The Team page

commit 1142cc3145fdba8d9eb8f9c9e7ee79bdfda64d9a
Author: Leo Rison <leo.rison@constellations.page>
Date:   Tue Feb 23 18:53:50 2021 -0500

    Added initial assets and landing page
```

Let's see what's on the `Meet The Team` page:

```bash
$ git checkout -q 4c88ac1c56fe228267cf415c3ef87d7c3b8abd60
$ ls
meet-the-team.html
$ egrep -io "flag\{[^\}]+\}" meet-the-team.html
flag{4063962f3a52f923ddb4411c139dd24c}
```

the `meet-the-team.html` also contains a list of names of people on the team:

```html
<li><h4><b>Orion Morra</b> &mdash; Support</h4></li>

<li><h4><b>Lyra Patte</b> &mdash; Marketing</h4></li>

<li><h4><b>Leo Rison</b> &mdash; Development</h4></li>

<li><h4><b>Gemini Coley</b> &mdash; Operations</h4></li>

<li><h4><b>Hercules Scoxland</b> &mdash; Sales</h4></li>

<li><h4><b>Vela Leray</b> &mdash; Management</h4></li>

<li><h4><b>Pavo Welly</b> &mdash; HR</h4></li>

<li><h4><b>Gus Rodry</b> &mdash; Accounting</h4></li>
```

This list will come in handy for the next part.

[*Back to top*](#nahamcon-ctf-2021)

---

## The Mission — Path 1

### Leo

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 283](https://img.shields.io/badge/Solves-283-brightgreen) ![Points: 298](https://img.shields.io/badge/Points-298-blue)

**Challenge Category**

![Mission](https://img.shields.io/badge/Mission-orange)

**Challenge Description**

```
Author: @JohnHammond#6971

This is Stage 1 of Path 1 in The Mission. After solving this challenge, you may need to refresh the page to see the newly unlocked challenges.

Use open-source intelligence to track down information on Leo.
```

#### Flag

```
flag{636db5f4f0e36908a4f1a4edc5b0676e}
```

#### Solution

Leo's full name is `Leo Rison`. The flag was hidden on his [Instagram](https://www.instagram.com/_leorison/) page.

If you look through the images on his instagram, there is an image of a QR code.

![leo1.jpg](img/screenshots/leo1.jpg)

The QR code decodes to:

```
flag{636db5f4f0e36908a4f1a4edc5b0676e}

A password for Leo is `constelleorising`
```

[*Back to top*](#nahamcon-ctf-2021)

---

## The Mission — Path 2

### Hercules

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 502](https://img.shields.io/badge/Solves-502-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Mission](https://img.shields.io/badge/Mission-orange)

**Challenge Description**

```
Author: @JohnHammond#6971

This is Stage 1 of Path 2 in The Mission. After solving this challenge, you may need to refresh the page to see the newly unlocked challenges.

Use open-source intelligence to track down information on Hercules.
```

#### Flag

```
flag{5bf9da15002d7ea53cb487f31781ce47}
```

#### Solution

Hercules' full name is `Hercules Scoxland`. We can find the flag for Hercules on his [GitHub](https://github.com/HerculesScox/maintenance) account.

The flag is contained in `connect.sh`, which also contains ssh credentials.

```bash
#!/bin/bash

IP=$1
PORT=$1

sshpass -p starstruckherc ssh hercules@$IP -p $PORT
#
# This flag can be submitted for the `Hercules` challenges, revealed after you solve `Meet The Team`, visible after you solve `Bionic`
# flag{5bf9da15002d7ea53cb487f31781ce47}
```

[*Back to top*](#nahamcon-ctf-2021)

---

## The Mission — Path 3

### Orion

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 361](https://img.shields.io/badge/Solves-361-brightgreen) ![Points: 156](https://img.shields.io/badge/Points-156-blue)

**Challenge Category**

![Mission](https://img.shields.io/badge/Mission-orange)

**Challenge Description**

```
Author: @JohnHammond#6971

This is Stage 1 of Path 3 in The Mission. After solving this challenge, you may need to refresh the page to see the newly unlocked challenges.

Use open-source intelligence to track down information on Orion.
```

#### Flag

```
flag{0bcffb17cbcbf4359a42ec45d0ccaf2}
```

#### Solution

Orion's full name is `Orion Morra`. You can find his flag on his [Twitter](https://twitter.com/OrionMorra) account.

![orion1.jpg](img/screenshots/orion1.jpg)

There is also a picture of credentials on his monitor.

![orion2.jpg](img/screenshots/orion2.jpg)

[*Back to top*](#nahamcon-ctf-2021)

---

## The Mission — Path 4

### Gus

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 803](https://img.shields.io/badge/Solves-803-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Mission](https://img.shields.io/badge/Mission-orange)

**Challenge Description**

```
Author: @JohnHammond#6971

This is Stage 1 of Path 4 in The Mission. After solving this challenge, you may need to refresh the page to see the newly unlocked challenges.

Use open-source intelligence to track down information on Gus.
```

#### Flag

```
flag{84d5cc7e162895fa0a5834f1efdd0b32}
```

#### Solution

Gus' full name is `Gus Rodry`. We can find the flag for Gus on his [GitHub](https://github.com/gusrodry/development) account.

The flag is in a file named `flag.txt` hidden in `config/.ssh`:

```
# NOTE:
# This flag submits for the `Gus` challenge you should see after solving `Meet The Team`, after you solve `Bionic`

flag{84d5cc7e162895fa0a5834f1efdd0b32}
```

The `.ssh` also contains a file with his a private key.

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
yijZOk41Lh95EAAAAKam9obkB4cHMxNQE=
-----END OPENSSH PRIVATE KEY-----
```

[*Back to top*](#nahamcon-ctf-2021)

---

## The Mission — Path 5

### Lyra

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Solves: 496](https://img.shields.io/badge/Solves-496-brightgreen) ![Points: 50](https://img.shields.io/badge/Points-50-blue)

**Challenge Category**

![Mission](https://img.shields.io/badge/Mission-orange)

**Challenge Description**

```
Author: @JohnHammond#6971

This is Stage 1 of Path 5 in The Mission. After solving this challenge, you may need to refresh the page to see the newly unlocked challenges.

Use open-source intelligence to track down information on Lyra.
```

#### Flag

```
flag{bd869e6193c27308d2fd3ad4b427e8c3}
```

#### Solution

Lyra's full name is `Lyra Patte`. You can find the location for the flag on her [Twitter](https://twitter.com/LyraPatte) account. In one of her tweets, she posts a link to [https://constellations.page/constellations-documents/1/](https://constellations.page/constellations-documents/1/).

If we change the number at the end, we can browse through the files on the server. We eventually find the flag at [https://constellations.page/constellations-documents/5/](https://constellations.page/constellations-documents/5/).

```
flag{bd869e6193c27308d2fd3ad4b427e8c3}
```

The file also contains a list of potential and passwords.

```
starstar
allstars
starstruck
starshine
starsky
popstars
starship
bluestars
pinkstars
superstars
ilovestars
rockstars
thestars
starscream
gostars
shootingstars
northstars
alpinestars
starsign
moonandstars
starsrock
luckystars
iluvstars
fivestars
redstars
mystars
lovestars
dallasstars
moonstars
sunmoonstars
starsailor
silverstars
sevenstars
lilstars
dotaallstars
sunstars
starsun
starsstars
starsareblind
pokerstars
magicstars
divastars
blackstars
starstarstar
starsearch
luvstars
greenstars
deathstars
brightstars
twinstars
starsinthesky
starshooter
starsha
threestars
summerstars
starspirit
starshollow
starsandstripes
starsandmoons
nightstars
metrostars
icstars
hoodstars
deadstars
citystars
```

[*Back to top*](#nahamcon-ctf-2021)
