import random
import binascii
import set2_challenge9 as pkcs7
from Crypto.Cipher import AES
import os
import collections

prefix = os.urandom(random.randint(1, 16))
key = bytes([random.randint(0,255) for i in range(16)]) # find block_size through code
string_to_decrypt = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' \
                 b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' \
                 b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' \
                 b'YnkK'


def oracle(message):
    #modify oracle to this form: AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    return AES.new(key, AES.MODE_ECB).encrypt(pkcs7.PKCS7_pad(prefix + message
                                                               + binascii.a2b_base64(string_to_decrypt), 16))


def byte_at_a_time_harder(oracle):
    #we can use the same logic as we did for challenge 12 if we know the length of the random prefix

    i = 1
    while(True):
        block_size = len(oracle(b'A' * i)) - len(oracle(bytearray()))
        if block_size != 0:
            break
        i += 1

    chunks = [oracle(b'A' * (3 * block_size))[i:i + block_size] for i in range(0, len(oracle(b'A' * 32)), block_size)]
    number_of_repetitions = len(chunks) - len(set(chunks))
    if (number_of_repetitions == 0):
        print("not ecb")
        exit()

    # https://docs.python.org/3/library/os.path.html#os.path.commonprefix
    # https://mail.python.org/pipermail/python-dev/2002-December/030947.html

    #number of blocks random prefix takes up
    random_prefix_num_blocks = 1
    while((random_prefix_num_blocks < int(len(oracle(b'A' * i)) / block_size)) and
           (len(os.path.commonprefix([oracle(b''), oracle(b'A')])) > block_size * random_prefix_num_blocks)):
        random_prefix_num_blocks += 1

    e = collections.deque()
    offset = 0

    #unknown string length
    for i in range(block_size):
        e.append(oracle(b'A' * i))
        unknown_string_length = len(e[0]) - len(os.path.commonprefix(e)) #why doesn't python have a peek method
        if len(e) > 1 and len(os.path.commonprefix(e)) >= block_size * random_prefix_num_blocks:
            offset = i - 1
            break
        if(len(e) - 1 > 0):
            e.popleft()

    #after we account for the random prefix, we can just use the logic from set 2 challenge 12

    plaintext = b''
    input_block = b'A' * (block_size + offset)
    for i in range(int(unknown_string_length / block_size)):
        plaintext_block = b''
        for j in reversed(range(offset, offset + block_size)):
            input_block = input_block[1:]
            last_bytes = {}
            for ascii_val in range(256):
                last_bytes[oracle(input_block + bytes([ascii_val]))
                [(random_prefix_num_blocks * block_size): (random_prefix_num_blocks * block_size) + block_size]] \
                    = bytes([ascii_val])
            one_byte_short = oracle(b'A' * j)[(block_size * i) + (random_prefix_num_blocks * block_size):
                                              (block_size * i) + (random_prefix_num_blocks * block_size) + block_size]
            if one_byte_short in last_bytes:
               plaintext_block += last_bytes[one_byte_short]
               input_block += last_bytes[one_byte_short]
        plaintext += plaintext_block
        input_block = (b'A' * offset) + plaintext_block
    return plaintext.decode()

if __name__ == '__main__':
    print(byte_at_a_time_harder(oracle))