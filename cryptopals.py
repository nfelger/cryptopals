from itertools import izip_longest


def hex2bytes(hex_string):
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
        for n in xrange(1, num_missing + 1):
            result[-n] = '='

    return str(result)


def test_s1c1():
    input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert base64encode(hex2bytes(input)) == expected
