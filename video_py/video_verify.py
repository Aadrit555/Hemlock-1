import sys
import json
import numpy as np
import imageio.v3 as iio

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from video_utils import chained_hash


# ----------------------------
# Helpers
# ----------------------------

def load_chain(path):
    chain = []
    with open(path, "rb") as f:
        while True:
            h = f.read(32)
            if not h:
                break
            chain.append(h)
    return chain


def save_mismatch_overlay(video_path: str, frame_index: int):
    """
    Save the mismatched frame with a red forensic overlay.
    """
    for idx, frame in enumerate(iio.imiter(video_path)):
        if idx == frame_index:
            frame = frame.copy()
            h, w, _ = frame.shape

            thickness = 10  # border thickness

            # Red border
            frame[:thickness, :, :] = [255, 0, 0]
            frame[-thickness:, :, :] = [255, 0, 0]
            frame[:, :thickness, :] = [255, 0, 0]
            frame[:, -thickness:, :] = [255, 0, 0]

            out_path = f"provenance/mismatch_frame_{frame_index}.png"
            iio.imwrite(out_path, frame)

            print(f"🖼️  Mismatch frame saved to {out_path}")
            return


# ----------------------------
# Main verification
# ----------------------------

def verify_video(video_path: str):
    report = {
        "file": video_path,
        "status": "UNKNOWN",
        "failure_type": None,
        "first_mismatched_frame": None,
        "total_frames_checked": 0,
        "signed_by": "ECDSA-P256",
        "verified_with_public_key": True
    }

    # Load public key
    with open("keys/public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Load stored hash chain
    stored_chain = load_chain("provenance/video_chain.bin")

    prev_hash = b"\x00" * 32
    last_valid_frame = -1

    # Frame-by-frame verification
    for idx, frame in enumerate(iio.imiter(video_path)):
        report["total_frames_checked"] += 1

        frame_bytes = frame.astype(np.uint8).tobytes()
        curr_hash = chained_hash(frame_bytes, prev_hash)

        if idx >= len(stored_chain) or curr_hash != stored_chain[idx]:
            report["status"] = "FAILED"
            report["failure_type"] = "FRAME_HASH_MISMATCH"
            report["first_mismatched_frame"] = idx
            break

        prev_hash = curr_hash
        last_valid_frame = idx
    else:
        # Frame chain matched → verify signature
        try:
            with open("provenance/video_sig.bin", "rb") as f:
                signature = f.read()

            public_key.verify(
                signature,
                prev_hash,
                ec.ECDSA(hashes.SHA256())
            )

            report["status"] = "VERIFIED"

        except InvalidSignature:
            report["status"] = "FAILED"
            report["failure_type"] = "SIGNATURE_MISMATCH"
            report["first_mismatched_frame"] = last_valid_frame + 1

    # Write JSON report
    with open("provenance/video_verification_report.json", "w") as f:
        json.dump(report, f, indent=2)

    # Console output + visual evidence
    if report["status"] == "VERIFIED":
        print("✔ Video verified successfully")
    else:
        print("✘ Video verification failed")
        print(f"  Reason: {report['failure_type']}")
        print(f"  First mismatched frame: {report['first_mismatched_frame']}")
        save_mismatch_overlay(video_path, report["first_mismatched_frame"])

    return report


# ----------------------------
# CLI entry
# ----------------------------

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python video_verify.py <video.mp4>")
        sys.exit(1)

    verify_video(sys.argv[1])