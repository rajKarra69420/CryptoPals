import set3_challenge18 as ctr
import base64
import os
import itertools  # https://stackoverflow.com/questions/2300756/get-the-nth-item-of-a-generator-in-python

key = os.urandom(16)
nonce = os.urandom(8)


def edit(ciphertext, key, nonce, offset, newtext):
    return ciphertext[:offset] + bytes([x ^ y
           for (x, y) in itertools.zip_longest(newtext,
           itertools.islice(ctr.get_keystream(key, nonce),offset, offset + len(newtext)),
           fillvalue=0)]) + ciphertext[offset + len(newtext):]


def api_call(ciphertext, newtext):
    return bytes([x ^ y
           for (x, y) in itertools.zip_longest(ciphertext,
           edit(ciphertext, key, nonce, 0, newtext), fillvalue=0)])


if __name__ == "__main__":
    f = open('set4_challenge25_encrypted.txt')
    # test edit function
    plaintext = base64.b64decode(f.read())
    ciphertext = ctr.transform(plaintext, key, bytes(nonce))
    edited_ciphertext = edit(ciphertext, key, nonce, 20, b'foobar')
    edited_plaintext = ctr.transform(edited_ciphertext, key, nonce)
    assert(b'foobar' in edited_plaintext)
    # actual attack is here
    recovered_plaintext = api_call(ciphertext, b'\x00' * len(ciphertext))
    assert(recovered_plaintext == plaintext)


