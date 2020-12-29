import math
import time
import os
import random
import set3_challenge21 as mt

key = random.randint(1, (int(math.pow(2,16)) - 1))
prefix = bytes([random.randint(0,255) for i in range(random.randint(2,20))])


# get_keystream and transform are similar to the ones in set 3 challenge 18
def get_keystream(key):
    rng = mt.MT19937(key)
    while True:
        yield from int(rng.extract_number()).to_bytes(4, byteorder='little')


def transform(message, key):
    return bytes([x ^ y for (x, y) in zip(message, get_keystream(key))])


def get_seed(ciphertext):
    for i in range(int(math.pow(2, 16))):
        if transform(ciphertext, i).endswith(b'A'*14):
            return i


def get_reset_token():
    # we make sure the seed is a 16 bit int by masking with the max value of a 16 bit integer
    # typical password reset tokens are 16 bytes long according to:
    # https://security.stackexchange.com/questions/213975/how-to-properly-create-a-password-reset-token
    return bytes(next(get_keystream(int(time.time()) & (int(math.pow(2, 16)) - 1))) for i in range(16))


def check_mt19937(token):
    for i in range(int(math.pow(2, 16))):
        if bytes(next(get_keystream(i)) for j in range(16)) == token:
            return True
    return False


if __name__ == "__main__":
    ciphertext = transform(b'foobar', 5489)
    plaintext = transform(ciphertext, 5489)
    print(plaintext.decode())
    assert(plaintext.decode() == "foobar")
    assert(get_seed(transform(prefix + b'A' * 14, 5489)) == 5489)
    token = get_reset_token()
    assert(check_mt19937(token))
    # we use os.urandom to test for false positives
    # because python's random library is implemented using a mersenne twister
    assert(not check_mt19937(os.urandom(16)))

