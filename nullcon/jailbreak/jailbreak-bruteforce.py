#!/usr/bin/env python

import re
import string
import itertools

buf_00604160 = [
    18, 84, 2, 108, 82, 81, 75, 27, 107, 69, 82, 107, 0, 19, 87, 13, 13, 107,
    21, 89, 85, 80, 108, 18, 70, 9, 83, 0, 81, 13, 105, 3, 29, 108, 6, 0, 91,
    4, 81, 86
    ]

buf_006040b0 = [
    76, 4, 85, 61, 5, 80, 67, 26, 62, 66, 5, 111, 4, 70, 80, 1, 15, 103, 66, 80,
    1, 83, 57, 66, 19, 6, 86, 1, 7, 91, 59, 87, 77, 110, 1, 4, 91, 4, 2, 1
    ]

buf_00604210 = [
    71, 8, 4, 58, 0, 5, 21, 74, 109, 70, 7, 62, 84, 64, 81, 0, 8, 107, 76, 92, 5,
    13, 57, 69, 70, 7, 84, 82, 84, 12, 108, 91, 78, 110, 85, 3, 94, 85, 86, 86
    ]

charset = string.ascii_lowercase + '0134579_'
hexchars = [ord(c) for c in string.digits + 'abcdef']

wordlists = {}
wordlists['recon'] = '\n'.join([
    're', 'reverse', 'reversing', 'hack', 'crack', 'jail', 'break', 'jailbreak',
    'free', 'donfos', 'aravind', 'machiry', 'shellphish', 'goa', 'india',
    'nullcon', 'null'
    ])

with open('corncob_lowercase.txt') as f:
    wordlists['corncob'] = f.read()

def leet(c):
    return {
        'o': '0',
        'i': '1',
        'e': '3',
        'a': '4', 
        's': '5',
        't': '7',
        'g': '9',
        }.get(c, '')

def unleet(c):
    return {
        '0': 'o',
        '1': 'i',
        '3': 'e',
        '4': 'a', 
        '5': 's',
        '7': 't',
        '9': 'g',
        }.get(c, c)

def leetify(string, charsets):
    chars = []
    for i in range(len(string)):
        c = ''
        if string[i] in charsets[i]:
            c = string[i]
        if leet(string[i]) in charsets[i]:
            c += leet(string[i])

        chars.append(c)

    return [''.join(w) for w in itertools.product(*chars)]

def unleetify(string):
    return ''.join([unleet(c) for c in string])

def _search(chars, wordlist):
    ret = {}
    regex = unleetify('^[%s]$' % ']['.join(chars))
    candidates = re.findall(regex, wordlist, re.M)
    for candidate in candidates:
        print(candidate + ': ' + str(leetify(candidate, chars)))

def search(chars):
    print('==== WORD ====')
    print('possible characters: ' + str(chars))

    for wl in wordlists:
        print('---- %s ----' % wl)
        _search(chars, wordlists[wl])

    print('')

chars = []
for i in range(40):
    s1 = [chr(buf_00604160[i] ^ c) for c in hexchars
            if chr(buf_00604160[i] ^ c) in charset]
    s2 = [chr(buf_006040b0[i] ^ c) for c in hexchars
            if chr(buf_006040b0[i] ^ c) in charset]
    s3 = [chr(buf_00604210[i] ^ c) for c in hexchars 
            if chr(buf_00604210[i] ^ c) in charset]

    s = ''.join(set.intersection(set(s1), set(s2), set(s3)))
    
    if '_' in s:
        search(chars)
        chars = []
    else:
        chars.append(s)

search(chars)
