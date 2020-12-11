import base64
import set1_challenge3 as breakSingleXor
import set1_challenge5 as repeatingXor

def getHammingDistance(str1, str2):
    if(len(str1) != len(str2)):
        raise Exception("The two strings must have the same length")
    distance = 0
    for i, j in zip(str1, str2):
        d = i ^ j
        for k in bin(d):
            distance += 1 if k == '1' else 0
    return distance

def getKeySize(text):
    l = []
    for i in range(2,41):
        l.append({'keysize': i, 'average':(getHammingDistance(text[:i], text[i: 2 * i]) +
             getHammingDistance(text[i: 2 * i], text[i * 2: i * 3]) +
             getHammingDistance(text[i * 2: i * 3], text[i * 3: i * 4])) / (3 * i)})
    l = sorted(l, key = lambda x : x['average'])
    return [l[0], l[1], l[2]]


def crack(distances, text):
    p = []
    for i in distances:
        key = b''
        for j in range(i['keysize']):
            b = b''
            for k in range(j, len(text), i['keysize']):
                b += bytes([text[k]])
            key += bytes([breakSingleXor.breakCipher(b)['key']])
        p.append((repeatingXor.repeatingXOR(text, key), key))
    return(sorted(p, key=lambda x: breakSingleXor.findCharFrequencies(x[0]))[len(p) - 1])


if __name__ == '__main__':
    f = open("set1_challenge6_encrypted.txt", "r")
    c = base64.b64decode(f.read())
    assert(getHammingDistance(bytes("this is a test", 'utf-8'), bytes("wokka wokka!!!", 'utf-8')) == 37)
    m = getKeySize(c)
    text = crack(m,c)
    print(text)

