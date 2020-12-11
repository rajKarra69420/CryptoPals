#used https://en.wikipedia.org/wiki/XOR_cipher

def fixedXOR(text, key):
    arr = bytearray()
    for i, j in zip(text, key):
        arr.append(i ^ j)
    return arr

if __name__ == '__main__':
    print("enter the input")
    useCipher = input()
    print("enter the key")
    key = input()
    print(fixedXOR(bytes.fromhex(useCipher),  bytes.fromhex(key)).hex())