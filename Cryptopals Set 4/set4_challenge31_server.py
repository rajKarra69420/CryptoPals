import time
from set4_challenge28 import sha1
import binascii
import http.server
import urllib.parse
import random

key = random.choice(open("/usr/share/dict/words").readlines()).rstrip().encode()
delay = 0.05  # change this for challenge 32 to 0.0005
port = 42069


# https://en.wikipedia.org/wiki/HMAC#Implementation
def hmac_sha1(key, message):
    if(len(key) > 64):
        key = binascii.unhexlify(sha1(key))

    if(len(key) < 64):
        key += b'\x00' * (64 - len(key))

    o_key_pad = bytes([b1 ^ b2 for b1, b2 in zip(b'\x5c' * 64, key)])
    i_key_pad = bytes([b1 ^ b2 for b1, b2 in zip(b'\x36' * 64, key)])

    return sha1(o_key_pad + binascii.unhexlify(sha1(i_key_pad + message)))


def insecure_compare(s1, s2):
    for b1, b2 in zip(s1, s2):
        if(b1 != b2):
            return False
        time.sleep(delay)
    return True

# if we wanted to make a secure compare function, it should be constant time
# e.g something like this
def constant_time_compare(val1, val2):
    # taken from Django Source Code
    """
    Returns True if the two strings are equal, False otherwise.

    The time taken is independent of the number of characters that match.

    For the sake of simplicity, this function executes in constant time only
    when the two strings have the same length. It short-circuits when they
    have different lengths.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= x ^ y
    return result == 0


# https://pymotw.com/3/http.server/
# https://gist.github.com/bradmontgomery/2219997
# https://docs.python.org/3/library/urllib.parse.html
class MyHandler(http.server.BaseHTTPRequestHandler):
    def _set_headers(self):
        # don't do self.send_response(200) because we can send a 200 or 500
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        if(urllib.parse.urlparse(self.path).path == '/test'):
            file = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)['file'][0].encode('ascii')
            digest = hmac_sha1(key, file).encode()
            signature = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)['signature'][0].encode()
            if(insecure_compare(digest, signature)):
                self.send_response(200)
                self._set_headers()
            else:
                self.send_response(500)
                self._set_headers()
        else:
            self.send_response(500)
            self._set_headers()


# https://docs.python.org/3/library/http.server.html
def run(server_class, handler_class):
    server_address = ('localhost', port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


if __name__ == '__main__':
    run(http.server.HTTPServer, MyHandler)
