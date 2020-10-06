def repeatingXOR(text, key):
    result = b''
    a = 0
    for i in text:
        result += bytes([i ^ key[a]])
        a = (a + 1) % len(key)
    return result

#print("enter the message")
#message = input()
#print("enter the key")
#key = input()
#print(repeatingXOR(str.encode(message), str.encode(key)).hex())

