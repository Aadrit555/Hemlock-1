from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pathlib import Path

Path("keys").mkdir(exist_ok=True)

private_key = ec.generate_private_key(ec.SECP256R1())

with open("keys/private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

with open("keys/public_key.pem", "wb") as f:
    f.write(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

print("✔ Keys generated")