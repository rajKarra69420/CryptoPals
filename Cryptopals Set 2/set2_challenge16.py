import random
import set2_challenge10 as CBC
import set2_challenge9 as pkcs7
import os
import collections

iv = bytes([random.randint(0,255) for i in range(16)])
key = bytes([random.randint(0,255) for i in range(16)])

def cbc_encrypt(message):
    plaintext = (b'comment1=cooking%20MCs;userdata=' + message + b'comment2=%20like%20a%20pound%20of%20bacon').\
        replace(b';', b'%3b').replace(b'=', b'%3d')
    return CBC.encrypt_cbc_with_ecb(pkcs7.PKCS7_pad(plaintext, 16), key, iv, 16)

def find_admin_role(ciphertext):
    return b';admin=true;' in CBC.decrypt_cbc_with_ecb(ciphertext, key, iv, 16)


def get_admin(oracle):
    # we cannot get ";admin=true;" without breaking cbc
    # we do this by taking advantage of 2 occurrences when a 1 bit error happens
    # this one bit error will completely scramble the current block
    # the identical 1 bit error will be produced in the next cipertext blocks
    # we take the ciphertext of the phrase xadminxtruex and we use the xor operator to make cbc decrypt the x to ; or =

    block_size = 1
    i = 1
    while (True):
        block_size = len(oracle(b'A' * i)) - len(oracle(bytearray()))
        if (block_size != 0):
            break
        i += 1

    num_prefix_blocks = len(os.path.commonprefix([oracle(b''), oracle(b'A')])) // block_size + 1

    #len of comment1=cooking%20MCs;userdata= + extra chars to fill blocks
    e = collections.deque()
    offset = 0
    for i in range(block_size):
        e.append(oracle(b'A' * i))
        if len(os.path.commonprefix(e)) == num_prefix_blocks * block_size:
            offset = i - 1
            break

        if (len(e) - 1 > 0):
            e.popleft()

    ciphertext = bytearray(oracle(b'A' * offset + b'XadminXtrueX'))

    #in order to place a value we want at a particular index of our ciphertext
    # we use the fact that xor(ciphertext[i], plaintext[i]) = key[i]
    # we do: ciphertext[i] = xor(ciphertext[i] ^ plaintext[i] ^ val_we_want)

    ciphertext[(num_prefix_blocks - 1) * block_size] ^= ord(b'X') ^ ord(b';')
    ciphertext[6 + (num_prefix_blocks - 1) * block_size] ^= ord(b'X') ^ ord(b'=')
    ciphertext[11 + (num_prefix_blocks - 1) * block_size] ^= ord(b'X') ^ ord(b';')
    return ciphertext

if __name__ == '__main__':
    print(find_admin_role(get_admin(cbc_encrypt)))
