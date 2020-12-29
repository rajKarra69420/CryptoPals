import os
import codecs
import set2_challenge10 as CBC
import set2_challenge9 as pkcs7


key = os.urandom(16)
iv = key


def cbc_encrypt(message):
    plaintext = (b'comment1=cooking%20MCs;userdata=' + message + b'comment2=%20like%20a%20pound%20of%20bacon').\
        replace(b';', b'%3b').replace(b'=', b'%3d')
    return CBC.encrypt_cbc_with_ecb(pkcs7.PKCS7_pad(plaintext, 16), key, iv, 16)


def cbc_decrypt(message):
    plaintext = CBC.decrypt_cbc_with_ecb(message, key, iv, 16)
    try:
        plaintext.decode(encoding='ascii')
    except UnicodeDecodeError:
        codecs.encode(plaintext, 'hex')
    return plaintext



def get_key(encryptor, decryptor):
    block_size = 1
    i = 1
    while (True):
        block_size = len(encryptor(b'A' * i)) - len(encryptor(bytearray()))
        if (block_size != 0):
            break
        i += 1

    ciphertext = cbc_encrypt(b'')
    # C_1, C_2, C_3 -> C_1, 0, C_1
    ciphertext_with0 = ciphertext[:block_size] + b'\x00' * block_size + ciphertext[:block_size] + ciphertext[3 * block_size:]
    modified_plaintext = decryptor(ciphertext_with0 )
    # P'_1 XOR P'_3
    return bytes([x ^ y for x, y in zip(modified_plaintext[:block_size], modified_plaintext[2 * block_size:3 * block_size])])


if __name__ == "__main__":
    assert(get_key(cbc_encrypt, cbc_decrypt) == key)




