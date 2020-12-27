import random
import base64
import set2_challenge15 as validatePadding
import set2_challenge9 as pkcs7
import set2_challenge10 as CBC

# https://en.wikipedia.org/wiki/Padding_oracle_attack#Padding_oracle_attack_on_CBC_encryption

messages = list(map(base64.b64decode, [
        b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93', ]))

key = bytes([random.randint(0,255) for i in range(16)])


def cbc_encrypt(chosen_string):
    iv = bytes([random.randint(0,255) for i in range(16)])
    return {'ciphertext': CBC.encrypt_cbc_with_ecb(chosen_string, key, iv, 16), 'iv': iv}


def padding_oracle(encrypted_str, iv):
    try:
        validatePadding.validatePKCS7(CBC.decrypt_cbc_with_ecb(encrypted_str, key, iv, 16))
        return True
    except ValueError:
        return False


def generate_modified_c1(block, guess, padding_size, found_plaintext):
    # given two ciphertext blocks, C_1 C_2, we make a modified C_1 (our block paramter is C_1)
    new_c1 = block[:len(block) - padding_size] + bytes([block[len(block) - padding_size] ^ guess ^ padding_size])
    q = 0
    for i in range((16 - padding_size + 1), 16):
        new_c1 += bytes([block[i] ^ found_plaintext[q] ^ padding_size])
        q += 1
    return new_c1


def get_last_bytes(block, padding_size, found_plaintext, oracle, curr):
    last_bytes = []
    guess_blocks = [(generate_modified_c1(block, i, padding_size, found_plaintext), i) for i in range(256)]
    for block in guess_blocks:
        if(not oracle(curr, block[0])):
            continue
        last_bytes.append(block[1])
    return last_bytes


def get_plaintext(ciphertext, iv, oracle):
    plaintext = b''
    ciphertext_blocks = [iv] + [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    for block_index in range(len(ciphertext_blocks) - 1):
        plaintext_block = b''
        for i in range(16):
            last_bytes = get_last_bytes(ciphertext_blocks[block_index], len(plaintext_block) + 1,
            plaintext_block, oracle, ciphertext_blocks[block_index + 1])  # should never have len 0
            # checks if the decrypted block contains padding information or bytes used for padding
            # in which case we need to make an additional attempt
            if(len(last_bytes) > 1):
                for byte in last_bytes:
                    modified_c1s = [(generate_modified_c1(ciphertext_blocks[block_index], i,
                    len(plaintext_block) + 2, bytes([byte]) + plaintext_block), byte) for i in range(256)]
                    for c1 in modified_c1s:
                        # should only enter once since we resolve ambiguities here
                        if(oracle(ciphertext_blocks[block_index + 1], c1[0])):
                            last_byte = c1[1]
                            break
                plaintext_block = bytes([last_byte]) + plaintext_block
            else:
                plaintext_block = bytes([last_bytes[0]]) + plaintext_block
        plaintext += plaintext_block
    return plaintext


if __name__ == "__main__":
    to_encrypt = pkcs7.PKCS7_pad(messages[random.randint(0, len(messages)-1)], 16)
    encrypted = cbc_encrypt(to_encrypt)
    decrypted_string = get_plaintext(encrypted['ciphertext'], encrypted['iv'], padding_oracle)
    print(decrypted_string)
    assert(decrypted_string == to_encrypt)


