def decodeLittleEndian(b: int, bits: int) -> bytes:
    return sum([b[i] << 8 * i for i in range((bits + 7) // 8)])


def encodeLittleEndian(n: int, bits: int):
    return bytes([(n >> 8 * i) & 0xff for i in range((bits + 7) // 8)])