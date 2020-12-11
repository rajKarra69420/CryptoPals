def PKCS7_pad(message, block_size):
    return message + bytearray([block_size - (len(message) % block_size)]
                               * (block_size - (len(message) % block_size)))
