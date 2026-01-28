import sys
import numpy as np
import imageio.v3 as iio
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from video_utils import chained_hash


# -----------------------------
# Paths
# -----------------------------

PROVENANCE_DIR = Path("provenance")
KEYS_DIR = Path("keys")

PROVENANCE_DIR.mkdir(exist_ok=True)


# -----------------------------
# Core logic
# -----------------------------

def sign_video(video_path: str):
    # Load private key
    with open(KEYS_DIR / "private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    prev_hash = b"\x00" * 32
    frame_count = 0

    chain_path = PROVENANCE_DIR / "video_chain.bin"

    # Build chained hashes for every frame
    with open(chain_path, "wb") as chain_file:
        for frame in iio.imiter(video_path):
            frame_bytes = frame.astype(np.uint8).tobytes()
            curr_hash = chained_hash(frame_bytes, prev_hash)

            chain_file.write(curr_hash)
            prev_hash = curr_hash
            frame_count += 1

    # Sign the final hash of the chain
    signature = private_key.sign(
        prev_hash,
        ec.ECDSA(hashes.SHA256())
    )

    with open(PROVENANCE_DIR / "video_sig.bin", "wb") as f:
        f.write(signature)

    # Console output
    print("✔ Video signed successfully")
    print(f"✔ Total frames signed: {frame_count}")
    print("✔ Hash chain stored")
    print("✔ Signature generated")


# -----------------------------
# CLI entry
# -----------------------------

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python video_sign.py <video.mp4>")
        sys.exit(1)

    sign_video(sys.argv[1])
