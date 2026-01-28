import sys
import os
import imageio.v3 as iio
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from video_utils import chained_hash

def sign_video(video_path: str):
    # Ensure provenance directory exists
    os.makedirs("provenance", exist_ok=True)
    
    # Check if private key exists
    if not os.path.exists("keys/private_key.pem"):
        print("Error: keys/private_key.pem not found")
        sys.exit(1)
    
    with open("keys/private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=None)

    prev_hash = b"\x00" * 32
    chain = []

    for frame in iio.imiter(video_path):
        frame_bytes = frame.astype(np.uint8).tobytes()
        curr_hash = chained_hash(frame_bytes, prev_hash)
        chain.append(curr_hash)
        prev_hash = curr_hash

    with open("provenance/video_chain.bin", "wb") as f:
        for h in chain:
            f.write(h)

    signature = private_key.sign(prev_hash, ec.ECDSA(hashes.SHA256()))
    with open("provenance/video_sig.bin", "wb") as f:
        f.write(signature)

    print("✔ Video signed successfully")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python video_sign.py <video.mp4>")
        sys.exit(1)
    sign_video(sys.argv[1])
