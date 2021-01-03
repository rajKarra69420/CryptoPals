import set4_challenge31 as break_hmac

# we still use the server from challenge 31 but change the delay time
# when challenge 31 breaks, we can increase the number of samples we collect per byte
if __name__ == "__main__":
    # we may not need to increase samples to 100 but it does guarantee that our attack works at lower sleep times
    print(break_hmac.get_hmac("test_file", 100))

