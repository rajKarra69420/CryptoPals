import numpy as np
import set3_challenge21 as mt

# used: https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html for both right and left unshifting


def unbitshift_right_xor(value, shift):
    result = 0
    for i in range(32 // shift + 1):
        result ^= value >> (shift * i)
    return np.uint32(result)


def unbitshift_left_xor(value, shift, mask):
    i = 0
    result = 0
    while (i * shift < 32):
        partMask = (0xffffffff >> (32 - shift)) << (shift * i)
        part = value & partMask
        value ^= (part << shift) & mask
        result += part
        i += 1
    return np.uint32(result)


def untemper(y):
    value = y
    value = unbitshift_right_xor(value, 18)
    value = unbitshift_left_xor(value, 15, 4022730752)
    value = unbitshift_left_xor(value, 7, 2636928640)
    value = unbitshift_right_xor(value, 11)
    return value

def clone_MT19937_prng(prng):
    return mt.MT19937(5489, [untemper(prng.extract_number()) for i in range(624)])


if __name__ == "__main__":
    rng = mt.MT19937()
    clone = clone_MT19937_prng(rng)
    for i in range(100000):
        assert(rng.extract_number() == clone.extract_number())
