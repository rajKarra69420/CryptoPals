import base64
from Crypto.Cipher import AES

def get_keystream(key, nonce):
    #https: // en.wikipedia.org / wiki / Block_cipher_mode_of_operation  # Counter_(CTR)
    # we can use a block cipher to make a keystream
    # we will use library ECB (note that we xor our keystream with the message
    # so we don't have the same vulnerabilities as ECB)
    c = 0
    while True:
        yield from AES.new(key, AES.MODE_ECB).encrypt((nonce + c.to_bytes(length=8, byteorder='little')))
        c += 1

def transform(text, key, nonce):
    #this function encrypts and decrypts
    return bytes([x ^ y for (x, y) in zip(text, get_keystream(key, nonce))])

if __name__ == "__main__":
    test_ciphertext = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    test_plaintext = transform(test_ciphertext, b'YELLOW SUBMARINE', bytes.fromhex('0000000000000000'))
    print(test_plaintext.decode())
    encrypted = transform(test_plaintext, b'YELLOW SUBMARINE', bytes.fromhex('0000000000000000'))
    assert(encrypted == test_ciphertext)
