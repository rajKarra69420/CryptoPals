import set2_challenge10 as cbc
import set2_challenge9 as pkcs7
from Crypto.Cipher import AES
import random

def oracle(message):
    prepend = bytes([random.randint(0,255) for i in range(random.randint(5,10))])
    append = bytes([random.randint(0,255) for i in range(random.randint(5,10))])
    plaintext = prepend + message + append
    key = bytes([random.randint(0,255) for i in range(16)])
    ecb_or_cbc = random.randint(0,1)
    if( ecb_or_cbc == 0):
        #ebc
        pkcs7.PKCS7_pad(plaintext, 16)
        ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pkcs7.PKCS7_pad(plaintext, 16))
    else:
        #cbc
        iv = bytes([random.randint(0,255) for i in range(16)])
        ciphertext = cbc.encrypt_cbc_with_ecb(pkcs7.PKCS7_pad(plaintext, 16), key, iv, 16)

    return {'ciphertext': ciphertext, 'mode': ecb_or_cbc} #we need a way to check our guesses



def guess_mode(oracle, length):
    # here we use the idea from set 1 challenge 8 where we find repeating blocks
    # because ecb is stateless and deterministic
    rand_plaintext = bytes(random.randint(0,256)) * length
    actual = oracle(rand_plaintext)
    chunks = [actual['ciphertext'][i:i + 16] for i in range(0, len(actual['ciphertext']), 16)]
    number_of_repetitions = len(chunks) - len(set(chunks))
    return {'guess': 0, 'actual': actual['mode']} if number_of_repetitions != 0  else {'guess': 1, 'actual': actual['mode']}


if __name__ == '__main__':
    correct = 0
    for i in range(1000):
        # at 16 bytes per block, we need 32 + 10 = 42 bytes to guarantee
        # 2 blocks are filled with our plaintext
        guess = guess_mode(oracle, 42)
        if(guess['guess'] == guess['actual']):
            correct += 1
    print(correct/1000)