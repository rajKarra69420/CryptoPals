import set1_challenge3 as s

f = open("set1_challenge4_strings.txt", "r")
l = f.readlines()
d = []

for i in l:
        d.append(s.breakCipher(bytes.fromhex(i)))

if __name__ == '__main__':
        d = sorted(d, key = lambda x : x['score'])
        print(d[len(d) - 1])

