from itertools import izip_longest
import json
import re

with open('charfreqscores.json', 'r') as file:
    CHARACTER_FREQUENCY_SCORES = json.load(file)


def hex_decode(hex_string):
    pairs = izip_longest(*[iter(hex_string)]*2)

    result = bytearray()
    for pair in pairs:
        hex_octet = ''.join(pair)
        int_octet = int(hex_octet, 16)
        result.append(int_octet)

    return str(result)


def base64encode(ascii_string):
    bytes = bytearray(ascii_string)

    # Divide input stream into blocks of 3 bytes.
    blocks = izip_longest(*[iter(bytes)]*3)

    result = bytearray()
    for block in blocks:
        # Zero-pad any missing bytes and remember how many there are.
        num_missing = len([b for b in block if b is None])
        b1, b2, b3 = (block[0], block[1] or 0, block[2] or 0)

        # Split the 24 bits into groups of 6.
        chars = [
            b1 >> 2,                           # bits 1-6
            ((b1 & 0b11) << 4) + (b2 >> 4),    # bits 7-12
            ((b2 & 0b1111) << 2) + (b3 >> 6),  # bits 13-18
            b3 & 0b111111                      # bits 19-24
        ]

        # Apply character code map.
        for c in chars:
            if c < 26:
                result.append(ord('A') + c)
            elif c < 52:
                result.append(ord('a') + c - 26)
            elif c < 62:
                result.append(ord('0') + c - 52)
            elif c == 62:
                result.append('+')
            elif c == 63:
                result.append('/')
            else:
                raise Exception('bad base-64 int %s for block %s' % (c, block))

        # For every 0-padding byte, overwrite a trailing character with '='.
        for n in range(1, num_missing + 1):
            result[-n] = '='

    return str(result)


def fixed_length_xor(a, b):
    a = bytearray(a)
    b = bytearray(b)
    result = bytearray()

    for a_char, b_char in zip(a, b):
        result.append(a_char ^ b_char)

    return result


def find_single_byte_xor_key(ciphertext):
    ciphertext = bytearray(ciphertext)
    best_candidate = (None, -1, -1)
    for candidate in range(33, 127):
        decoded = single_byte_xor(ciphertext, candidate)
        score = score_character_frequency(decoded)
        if score > best_candidate[2]:
            best_candidate = (decoded, chr(candidate), score)

    return best_candidate


def single_byte_xor(input, key):
    return fixed_length_xor(input, [key] * len(input))


def score_character_frequency(input):
    input = str(input)

    score = 0
    for char in input:
        char = char.lower()
        if re.match('[a-z ]', char):
            score += CHARACTER_FREQUENCY_SCORES[char]

    length_normalized_score = score / len(input)
    return length_normalized_score


def test_s1c1():
    input = hex_decode('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert base64encode(input) == expected


def test_s1c2():
    input1 = hex_decode('1c0111001f010100061a024b53535009181c')
    input2 = hex_decode('686974207468652062756c6c277320657965')
    expected = hex_decode('746865206b696420646f6e277420706c6179')
    assert fixed_length_xor(input1, input2) == expected

def test_s1c3():
    input = hex_decode('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    expected_key = 'X'
    expected_plaintext = "Cooking MC's like a pound of bacon"
    decoded_plaintext, found_key, _ = find_single_byte_xor_key(input)
    assert (found_key, decoded_plaintext) == (expected_key, expected_plaintext)

def test_s1c4():
    with open('data-1-4.txt') as file:
        inputs = [hex_decode(l.strip()) for l in file.readlines()]

    expected_plaintext = "Now that the party is jumping\n"

    decoded_inputs = []
    for input in inputs:
        decoded, key, score = find_single_byte_xor_key(input)
        decoded_inputs.append((decoded, score))

    best_plaintext = sorted(decoded_inputs, key=lambda (decoded, score): score)[-1][0]
    assert best_plaintext == expected_plaintext
