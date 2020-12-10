def find_max_repetitions(encrypted_lines):
    result = []
    for line in encrypted_lines:
        chunks = [line[i:i + 16] for i in range(0, len(line), 16)]
        # number of bytes - number of unique bytes = repetitions
        number_of_repetitions = len(chunks) - len(set(chunks))
        result.append({'ciphertext': line, 'repetitions': number_of_repetitions})
    return sorted(result, key=lambda x: x['repetitions'])[len(result) - 1]['ciphertext']

f = open("set1_challenge8_strings.txt", "r")
lines = f.read().splitlines()
lines = [bytes.fromhex(l) for l in lines]
print(find_max_repetitions(lines))