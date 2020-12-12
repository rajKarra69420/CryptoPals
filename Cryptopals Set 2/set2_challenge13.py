from Crypto.Cipher import AES
import set2_challenge9 as pkcs7
import os
import sys

key = os.urandom(16)

def parse(structured_cookie):
    vals = {}
    for i in structured_cookie.split("&"):
        tokens = i.split("=")
        vals[tokens[0]] = tokens[1]
    return vals

#profile for also encrpyts the profile with a random AES key
def profile_for(email):
    if(b'&' in email or b'=' in email):
        raise ValueError("Failed To Create Email")
    return AES.new(key, AES.MODE_ECB).encrypt(pkcs7.PKCS7_pad(b'email=' + email + b'&uid=10&role=user', 16))


def decypt_profile(profile):
    return bytes(AES.new(key, AES.MODE_ECB).decrypt(profile))


def cut_and_paste(oracle):
    i = 1
    block_size = 1
    while(True):
        block_size = len(oracle(b'A' * i)) - len(oracle(bytearray()))
        if(block_size != 0):
            break
        i += 1

    #profile to get admin as ciphertext
    get_admin_ciphertext = profile_for(b'A' * (block_size - len('admin') - 1) + b'admin')
    # pass random stuff to get normal email
    fake_profile = profile_for(b'A' * 13)
    # email=AAAAAAAAAAAAA&uid=10&role= + admin<bytes after> gives us an admin profile 
    ciphertext = fake_profile[:(block_size * 2)] + get_admin_ciphertext[block_size:(block_size * 2)]
    plaintext = decypt_profile(ciphertext)
    return plaintext

if __name__ == '__main__':
    print(cut_and_paste(profile_for))
