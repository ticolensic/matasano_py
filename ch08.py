from collections import Counter


def detect_ecb(data: bytes, s=16) -> bool:
    blocks = [data[i:i + s] for i in range(0, len(data), s)]
    count = Counter(blocks)
    return count.most_common(1)[0][1] > 1
