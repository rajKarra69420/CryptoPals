import set3_challenge18 as ctr
import random
import os

key = os.urandom(16)
nonce = os.urandom(8)

def ctr_encrypt(message):
    plaintext = (b'comment1=cooking%20MCs;userdata=' + message + b'comment2=%20like%20a%20pound%20of%20bacon'). \
        replace(b';', b'%3b').replace(b'=', b'%3d')
    return ctr.transform(plaintext, key, nonce)


def find_admin_role(ciphertext):
    return b';admin=true;' in ctr.transform(ciphertext, key, nonce)

# this is even easier than cbc because we don't have to worry about the previous block
# we can just xor at the index we want to change
def get_admin(encryptor):
    empty = bytearray(encryptor(b''))
    ciphertext = bytearray(encryptor(b'\x00admin\x00true\x00'))
    i = next((i for i in range(len(empty)) if empty[i] != ciphertext[i]), None)
    # by sending plaintext with the 0 byte, we have xor(\x00, b';') which evaluates to b';' (same for xor(\x00, b'='))
    ciphertext[i] ^= ord(b';')
    ciphertext[i + 6] ^= ord(b'=')
    ciphertext[i + 11] ^= ord(b';')
    return ciphertext


if __name__ == "__main__":
    print(find_admin_role(get_admin(ctr_encrypt)))
