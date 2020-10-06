#https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)

import pycryptodome
import base64

f = open("set1_challenge7_encrypted.txt", "r")
p = new AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB).decrypt(base64.b64decode(f.read()))

