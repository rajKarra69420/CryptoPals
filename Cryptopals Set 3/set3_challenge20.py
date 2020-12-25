import base64
import random
import set1_challenge3 as breakSingleXOR
import set3_challenge18 as CTR

def encrypt_with_ctr(plaintext):
    return [CTR.transform(line, bytes([random.randint(0, 255) for i in range(16)]), bytes.fromhex('0000000000000000')) for line in plaintext]


def break_ctr(ciphertext):
    # we take advantage of the fact that using a fixed nonce is mathematically equivalent to repeating key xor
    # the keystream would be the key
    return "".join([bytes(first_letters).decode()
            for first_letters in zip(*[breakSingleXOR.breakCipher(l)['message'] for l in zip(*ciphertext)])])

if __name__ == "__main__":
    f = open('set3_challenge20_encrypted.txt')
    plaintext = [base64.b64decode(line) for line in f]
    ciphertext = encrypt_with_ctr(plaintext)
    cracked_text = break_ctr(plaintext)
    print(cracked_text)