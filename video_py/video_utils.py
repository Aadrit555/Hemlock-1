import hashlib

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def chained_hash(curr: bytes, prev: bytes) -> bytes:
    return sha256(prev + curr)
