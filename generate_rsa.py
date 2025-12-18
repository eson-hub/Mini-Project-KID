import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(user_id: str):
    os.makedirs("punkhazard-keys", exist_ok=True)

    # Generate RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Simpan private key
    with open(f"punkhazard-keys/{user_id}_rsa_priv.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Simpan public key
    with open(f"punkhazard-keys/{user_id}_rsa_pub.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"RSA key pair untuk user '{user_id}' berhasil dibuat")

# CONTOH PEMAKAIAN
if __name__ == "__main__":
    generate_rsa_keypair("jule")
    # generate_rsa_keypair("jaki")
    # generate_rsa_keypair("udin")
