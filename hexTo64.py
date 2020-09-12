#used codecs documentation

import codecs

hex = input()
print(codecs.encode(codecs.decode(hex, 'hex'), 'base64').decode())

