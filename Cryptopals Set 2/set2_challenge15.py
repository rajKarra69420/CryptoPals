def validatePKCS7(byte_string: bytes)->bytes:
    if len(byte_string) < byte_string[-1] :
        return ValueError("invalid padding")
    for i in range(byte_string[-1], 0, -1):
        if byte_string[-i] != byte_string[-1]:
            raise ValueError("invalid padding")
    return byte_string[:-byte_string[-1]]

if __name__ == '__main__':
    print(validatePKCS7(bytes("ICE ICE BABY\x04\x04\x04\x04", 'utf-8')))
    try:
        print(validatePKCS7(bytes("ICE ICE BABY\x01\x02\x03\x04", 'utf-8')))
    except(ValueError):
        print("correct")
    else:
        print("expected a ValueError")

    try:
        print(validatePKCS7(bytes("ICE ICE BABY\x01\x02\x03\x04", 'utf-8')))
    except(ValueError):
        print("correct")
    else:
        print("expected a ValueError")