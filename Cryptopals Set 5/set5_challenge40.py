import set5_challenge39 as RSA


# the ints passed in are too big for pow(n ** (1/3)) which causes accuracy loss so we use the bisection method
def find_root(x,n=3):
    high = 1
    while(high ** n < x):
        high *= 2
    low = high // 2
    while(low < high):
        mid = (low + high) // 2
        if(low < mid and mid**n < x):
            low = mid
        elif(high > mid and mid ** n > x):
            high = mid
        else:
            return mid
    return mid + 1


def get_plaintext(ciphertexts):
    t0 = (ciphertexts[0][0] * (ciphertexts[1][1] * ciphertexts[2][1]) *
          pow((ciphertexts[1][1] * ciphertexts[2][1]), -1, ciphertexts[0][1]))
    t1 = (ciphertexts[1][0] * (ciphertexts[0][1] * ciphertexts[2][1]) *
          pow((ciphertexts[0][1] * ciphertexts[2][1]), -1, ciphertexts[1][1]))
    t2 = (ciphertexts[2][0] * (ciphertexts[0][1] * ciphertexts[1][1]) *
          pow((ciphertexts[0][1] * ciphertexts[1][1]), -1, ciphertexts[2][1]))
    c = (t0 + t1 + t2) % (ciphertexts[0][1] * ciphertexts[1][1] * ciphertexts[2][1])
    return find_root(c).to_bytes((find_root(c).bit_length() + 7) // 8, 'big')


if __name__ == '__main__':
    plaintext = b"foobar"
    ciphertexts = []
    for i in range(3):
        rsa = RSA.get_keys(1024)
        ciphertexts.append((RSA.encrypt(plaintext, rsa['n']), rsa['n']))
    assert(get_plaintext(ciphertexts) == plaintext)


