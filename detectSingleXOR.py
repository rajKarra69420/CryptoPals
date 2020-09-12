import singleByteXOR as s

f = open("encrypted.txt", "r")
l = f.readlines()
d = [] #list of dictionaries

for i in l:
        r = s.breakCipher(bytes.fromhex(i))
        d.append(r[len(r) - 1])

d = sorted(d, key = lambda x : x['score'])
print(d[len(d) - 1])

