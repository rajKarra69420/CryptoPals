import base64 # https://docs.python.org/3/library/base64.html
from Crypto.Cipher import AES

# https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC
# the diagram on this page explains the process well

def encrypt_cbc_with_ecb(plaintext, key, iv, block_size):
    prev = iv # in cbc we xor every block with the previous block and the first block with the iv
    ciphertext = b'' # we append our blocks here
    blocks = [plaintext[i: i + block_size] for i in range(0, len(plaintext), block_size)]

    for i in range(len(blocks)):
        ciphertext += AES.new(key, AES.MODE_ECB).encrypt(bytes(a ^ b for a, b in zip(blocks[i], prev)))
        prev = AES.new(key, AES.MODE_ECB).encrypt(bytes(a ^ b for a, b in zip(blocks[i], prev)))

    return ciphertext


def decrypt_cbc_with_ecb(ciphertext, key, iv, block_size):
    #reverses the encryption process
    plaintext = b''
    prev = iv
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

    for i in range(len(blocks)):
        plaintext += bytes(a ^ b for a,b in zip(AES.new(key,AES.MODE_ECB).decrypt(blocks[i]), prev))
        prev = blocks[i]

    return plaintext

f_decoded = base64.b64decode(open('set2_challenge10_encrypted.txt', 'r').read())
decrypted = decrypt_cbc_with_ecb(f_decoded, b'YELLOW SUBMARINE', bytes([0] * 16), 16)
print(decrypted) # make sure plaintext is correct by looking at output
reencrypted = encrypt_cbc_with_ecb(decrypted, b'YELLOW SUBMARINE',bytes([0] * 16) , 16)
# if our encryption and decryption is correct then decryption(encryption(p)) == p should hold
# where decryption and encryption are our functions above 
assert(f_decoded == reencrypted)
