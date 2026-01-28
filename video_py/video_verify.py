import sys
import json
import numpy as np
import imageio.v3 as iio
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from video_utils import chained_hash


PROVENANCE = Path("provenance")
PROVENANCE.mkdir(exist_ok=True)


# -----------------------------
# Helpers
# -----------------------------

def load_chain(path):
    chain = []
    with open(path, "rb") as f:
        while True:
            h = f.read(32)
            if not h:
                break
            chain.append(h)
    return chain


def save_heatmap(frame, diff, idx):
    """
    Creates a red heatmap overlay on the mismatched regions
    """
    norm = diff / diff.max()
    heat = np.zeros_like(frame)
    heat[..., 0] = (norm * 255).astype(np.uint8)

    overlay = frame.copy()
    alpha = 0.6
    overlay = (overlay * (1 - alpha) + heat * alpha).astype(np.uint8)

    out = PROVENANCE / f"mismatch_frame_{idx}_heatmap.png"
    iio.imwrite(out, overlay)

    raw = PROVENANCE / f"mismatch_frame_{idx}.png"
    iio.imwrite(raw, frame)

    return [str(raw), str(out)]


# -----------------------------
# Main Verification
# -----------------------------

def verify_video(video_path: str):
    report = {
        "file": video_path,
        "status": "UNKNOWN",
        "total_frames": 0,
        "mismatched_frames": 0,
        "first_mismatched_frame": None,
        "last_mismatched_frame": None,
        "tamper_percentage": 0.0,
        "visual_evidence": []
    }

    # Load public key
    with open("keys/public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Load stored hash chain
    chain = load_chain("provenance/video_chain.bin")

    prev_hash = b"\x00" * 32
    mismatch_frames = []
    first_visual_done = False

    for idx, frame in enumerate(iio.imiter(video_path)):
        report["total_frames"] += 1

        frame_bytes = frame.astype(np.uint8).tobytes()
        curr_hash = chained_hash(frame_bytes, prev_hash)

        if idx >= len(chain) or curr_hash != chain[idx]:
            mismatch_frames.append(idx)

            if not first_visual_done:
                ref_frame = np.frombuffer(
                    frame_bytes, dtype=np.uint8
                ).reshape(frame.shape)

                diff = np.abs(frame.astype(int) - ref_frame.astype(int)).sum(axis=2)
                report["visual_evidence"] = save_heatmap(frame, diff, idx)
                first_visual_done = True

        else:
            prev_hash = curr_hash

    report["mismatched_frames"] = len(mismatch_frames)

    if mismatch_frames:
        report["status"] = "FAILED"
        report["first_mismatched_frame"] = mismatch_frames[0]
        report["last_mismatched_frame"] = mismatch_frames[-1]
        report["tamper_percentage"] = round(
            100 * len(mismatch_frames) / report["total_frames"], 2
        )
    else:
        try:
            with open("provenance/video_sig.bin", "rb") as f:
                sig = f.read()

            public_key.verify(sig, prev_hash, ec.ECDSA(hashes.SHA256()))
            report["status"] = "VERIFIED"

        except InvalidSignature:
            report["status"] = "FAILED"
            report["mismatched_frames"] = report["total_frames"]

    with open(PROVENANCE / "video_verification_report.json", "w") as f:
        json.dump(report, f, indent=2)

    # Console output
    if report["status"] == "VERIFIED":
        print("✔ Verification successful")
        print(f"✔ Total frames checked: {report['total_frames']}")
        print("✔ Mismatched frames: 0")
    else:
        print("✘ Verification failed")
        print(f"Total frames checked: {report['total_frames']}")
        print(f"Mismatched frames: {report['mismatched_frames']}")
        print(f"First mismatch at frame: {report['first_mismatched_frame']}")
        print(f"Last mismatch at frame: {report['last_mismatched_frame']}")
        print(f"Tamper severity: {report['tamper_percentage']}%")
        print("✔ Visual evidence generated")

    return report


# -----------------------------
# CLI Entry
# -----------------------------

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python video_verify.py <video.mp4>")
        sys.exit(1)

    verify_video(sys.argv[1])
