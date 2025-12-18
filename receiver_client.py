import base64
import requests

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

SERVER = "http://localhost:8080"

RECEIVER = "jule"
RECEIVER_TOKEN = "izin-token-123"

# LOAD PRIVATE RSA KEY (RECEIVER)
with open("punkhazard-keys/jule_rsa_priv.pem", "rb") as f:
    receiver_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

headers = {
    "Authorization": f"Bearer {RECEIVER_TOKEN}"
}

# LIAT INBOX DARI SERVER
response = requests.get(
    f"{SERVER}/inbox/{RECEIVER}",
    headers=headers
)

messages = response.json()["messages"]

print("=== RECEIVER ===")

# DECRYPT TIAP MESSAGE
for idx, msg in enumerate(messages, start=1):
    encrypted_sym_key = base64.b64decode(msg["encrypted_sym_key"])
    encrypted_message = base64.b64decode(msg["encrypted_message"])

    # DECRYPT SYMMETRIC KEY (RSA PRIVATE KEY)
    symmetric_key = receiver_private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # DECRYPT MESSAGE (AES / Fernet)
    cipher = Fernet(symmetric_key)
    plaintext = cipher.decrypt(encrypted_message)

    print(f"Pesan {idx} dari {msg['from']}: {plaintext.decode()}")
