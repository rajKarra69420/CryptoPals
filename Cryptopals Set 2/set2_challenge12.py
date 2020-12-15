import random
import binascii
import set2_challenge9 as pkcs7
from Crypto.Cipher import AES

key = bytes([random.randint(0,255) for i in range(16)]) # find block_size through code
string_to_decrypt = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' \
                 b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' \
                 b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' \
                 b'YnkK'

def oracle(message):
    return AES.new(key, AES.MODE_ECB).encrypt(pkcs7.PKCS7_pad(message + binascii.a2b_base64(string_to_decrypt), 16))

def byte_at_a_time(oracle):
    # find block size of the cipher
    block_size = 1
    i = 1
    while(True):
        # break when we find block_size
        # to find block size, we take advantage of padding
        # we add bytes till the length of the ciphertext changes
        # new_ciphertext_len - old_cipher_text_len = block_size
        block_size = len(oracle(b'A' * i)) - len(oracle(bytearray()))
        if(block_size != 0):
            break
        i += 1

    # find length of unknown string
    l = 1
    unknown_string_length = 1
    while(True):
        if(len(oracle(b'A' * l)) != len(oracle(bytearray()))):
            unknown_string_length = len(oracle(b'A' * i)) - l
            break
        l += 1
    # detect ecb
    # we use the logic from challenge 11 in set 2 and fill with 2 blocks of our plaintext
    chunks = [oracle(b'A' * 32)[i:i + 16] for i in range(0, len(oracle(b'A' * 32)), block_size)]
    number_of_repetitions = len(chunks) - len(set(chunks))
    if(number_of_repetitions == 0):
        print("not ecb")
        exit()

    # repeat for next byte
    plaintext = b''
    # Knowing the block size, craft an input block that is exactly 1 byte short
    input_block = b'A' * block_size
    for j in range(int(unknown_string_length / block_size)):
        plaintext_block = b''
        for k in reversed(range(0,block_size)):
            # Knowing the block size, craft an input block that is exactly 1 byte short
            input_block = input_block[1:]
            # Make a dictionary of every possible last byte by feeding different strings to the oracle
            last_bytes = {}
            for ascii_val in range(256):
                last_bytes[oracle(input_block + bytes([ascii_val]))[:block_size]] = bytes([ascii_val])

            one_byte_short = oracle(b'A' * k)[block_size * j: block_size * (j + 1)]
            # Match the output of the one-byte-short input to one of the entries in your dictionary
            if one_byte_short in last_bytes:
                plaintext_block += last_bytes[one_byte_short]
                input_block += last_bytes[one_byte_short]
        plaintext += plaintext_block
        input_block = plaintext_block
    return plaintext.decode()

if __name__ == '__main__':
    print(byte_at_a_time(oracle))
