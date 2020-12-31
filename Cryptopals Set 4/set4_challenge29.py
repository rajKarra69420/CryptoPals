import set4_challenge28 as sha1
import struct
import binascii
import random


# even though sha1 is fatally broken, this length extension attack does not actually attack sha1
# we are exploiting the mac function
# this attack can be used on all kinds of hashes that use a mac such as md4, sha256, etc.

key = random.choice(open("/usr/share/dict/words").readlines()).rstrip().encode()
message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'


def generate_digest(message):
        return sha1.sha1_mac(key, message)


def validate(message, digest):
        return generate_digest(message) == digest


message_digest = generate_digest(message)

# directly from preprocessing code in last challenge in the sha1 function
def md_pad(message, ml):
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += struct.pack('>Q', ml)
    return message

def get_fake_message(message, message_digest, oracle):
     for i in range(69):
        if oracle(md_pad(b'\x69' * i + message, (len(b'A' * i + message) * 8))[i:] + b';admin=true',
				  sha1.sha1(b';admin=true', (i + len(md_pad(b'\x69' * i + message,
				  (len(b'A' * i + message) * 8))[i:] + b';admin=true')) * 8,
		struct.unpack('>5I', binascii.unhexlify(message_digest)))):
            return {'message': md_pad(b'\x69' * i + message, (len(b'A' * i + message) * 8))[i:] + b';admin=true',
					'digest': sha1.sha1(b';admin=true',
					(i + len(md_pad(b'\x69' * i + message, (len(b'A' * i + message) * 8))[i:] + b';admin=true')) * 8,
					struct.unpack('>5I', binascii.unhexlify(message_digest)))}


if __name__ == "__main__":
    f = get_fake_message(message, message_digest, validate)
    assert(b';admin=true' in f['message'])
    assert(validate(f['message'], f['digest']))


