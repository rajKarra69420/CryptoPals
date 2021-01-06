from Crypto.Util.number import getPrime
import os


def gcd(a, b):
    while(b != 0):
        a, b = b, a % b
    return a


def lcm(a, b):
    return a // gcd(a, b) * b


def encrypt(plaintext, n, e=3):
    return pow(int.from_bytes(plaintext, byteorder='big'), e, n)


def decrypt(ciphertext, d, n):
    return pow(ciphertext, d, n).to_bytes((pow(ciphertext, d, n).bit_length() + 7) // 8, 'big')


def get_keys(keysize, e=3):
    phi = 0
    while(gcd(e, phi) != 1):
        p = getPrime(keysize // 2, os.urandom)
        q = getPrime(keysize // 2, os.urandom)
        phi = lcm(p - 1, q - 1)
        n = p * q
    # this method of getting the multiplicative inverse only works with python 3.9
    return {'d': pow(e, -1, phi), 'e': e, 'n': n}


if __name__ == '__main__':
    rsa = get_keys(1024)
    assert(decrypt(encrypt(b"foobar", rsa['n']), rsa['d'], rsa['n']) == b"foobar")
