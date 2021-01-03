import binascii
import statistics
import requests


def get_hmac(filename, num_samples):
    signature = b''
    # we hardcode the length of the hmac but in practice we can just download a valid file to get the hmac length
    while len(signature) < 20:
        compare_times = [[] for i in range(256)]
        # we want to take more than one sample per byte
        # at 1 sample per byte, the hmac I got was just flat out wrong every time
        for i in range(num_samples):
            for j in range(256):
                compare_times[j].append(requests.get('http://localhost:42069/test?file=' + filename +
                '&signature=' + binascii.hexlify(signature + bytes([j]) +
                (b'\x00' * ((20 - len(signature)) - 1))).decode()).elapsed.total_seconds())
        # we take the median rather than the mean because the mean is more vulnerable to outliers (due to network or other issues)
        # using the median ensures that our attack will be accurate as long as we don't drop the sleep time too low and we have enough samples
        signature += bytes([max(range(256), key=lambda b: [statistics.median(t) for t in compare_times][b])])
    return binascii.hexlify(signature).decode() if(requests.get('http://localhost:42069/test?file=' + filename + '&signature=' + signature).status_code == 200) else None


# you won't get the same hmac when you run the program more than once because the key is randomly generated
if __name__ == '__main__':
    print(get_hmac("test_file", 5))

