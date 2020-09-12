#I got the table from https://en.wikipedia.org/wiki/Letter_frequency and i just guessed space frequency till I got the
# right output
character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .03000
}


def findCharFrequencies(input):
    return sum([character_frequencies.get(chr(byte), 0) for byte in input.lower()])


def breakCipher(ciphertext):
    result = b''
    l = []
    for i in range(256):
        for b in ciphertext:
            result += bytes([b ^ i])
        l.append({'message': result, 'score': findCharFrequencies(result),'key': i})
        result = b''
    return sorted(l, key = lambda x : x['score'])


#decrypt = input()
#l = breakCipher(bytes.fromhex(decrypt))
#print(l[len(l) - 1])








