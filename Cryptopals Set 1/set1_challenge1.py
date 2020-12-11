#used codecs documentation

import codecs

if __name__ == '__main__':
    hex = input()
    print(codecs.encode(codecs.decode(hex, 'hex'), 'base64').decode())

