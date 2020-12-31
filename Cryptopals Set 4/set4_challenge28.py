from __future__ import print_function
import hashlib  # for testing
import struct  # https://docs.python.org/3/library/struct.html


# https://en.wikipedia.org/wiki/Circular_shift
def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


# https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
# For challenge 29, we allow the passing of registers to allow for starting at a certain state
def sha1(message, ml=None, h=None):
    # h can contain values for the registers h0-h4 to use instead of the default ones
    if(h == None):
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0
    else:
        h0 = h[0]
        h1 = h[1]
        h2 = h[2]
        h3 = h[3]
        h4 = h[4]
    # Pre-processing:
    if(ml == None):
        ml = len(message) * 8

    message += b'\x80'
    while((len(message) * 8) % 512 != 448):
        message += b'\x00'

    message += struct.pack('!Q', ml)

    # Process the message in successive 512-bit chunks:
    w = [0] * 80
    for i in range(0, len(message), 64):
        # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        for j in range(16):
            w[j] = struct.unpack('!I', message[i + j * 4: i + j * 4 + 4])[0]

        # Extend the sixteen 32-bit integers into eighty 32-bit integers:
        for k in range(16, 80):
            w[k] = left_rotate(w[k - 3] ^ w[k - 8] ^ w[k - 14] ^ w[k - 16], 1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
        for l in range(80):
            if(l <= 19):
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif(20 <= l <= 39):
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif(40 <= l <= 59):
                f = (b & c) | (d & (b | c))
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = left_rotate(a, 5) + f + e + k + w[l] & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian) as a 160 bit number, hex formatted:
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


# SHA1(key || message)
def sha1_mac(key, message):
    return sha1(key + message)


if __name__ == '__main__':
    key = b'foobar'
    message = b'TestMessage'
    assert(sha1_mac(key, message) == hashlib.sha1(key + message).hexdigest())

