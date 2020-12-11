from Crypto.Cipher import AES
import base64

if __name__ == '__main__':
    f = open("set1_challenge7_encrypted.txt", "r")
    p = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB).decrypt(base64.b64decode(f.read()))
    print(p)