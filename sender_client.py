import base64
import requests

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

SERVER = "http://localhost:8080"
SENDER = "nasihuy"
TOKEN = "izin-token"
RECEIVER = "jule"

# LOAD PRIVATE KEY (Ed25519)
with open("punkhazard-keys/priv19.pem", "rb") as f:
    sign_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# LOAD PUBLIC KEY RECEIVER (RSA)
receiver_pubkey_path = f"punkhazard-keys/{RECEIVER}_rsa_pub.pem"

with open(receiver_pubkey_path, "rb") as f:
    receiver_public_key = serialization.load_pem_public_key(f.read())

# PLAINTEXT MESSAGE
plaintext_message = (
    "Data eksperimen Seraphim S-Bear batch 07 siap dianalisis"
)

# SYMMETRIC ENCRYPTION (AES / Fernet)
symmetric_key = Fernet.generate_key()
cipher = Fernet(symmetric_key)
ciphertext = cipher.encrypt(plaintext_message.encode())

# ENCRYPT SYMMETRIC KEY (RSA RECEIVER)
encrypted_symmetric_key = receiver_public_key.encrypt(
    symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# SIGN CIPHERTEXT (Ed25519)
signature = sign_private_key.sign(ciphertext)
signature_b64 = base64.b64encode(signature).decode()


# PAYLOAD UNTUK RELAY
payload = {
    "sender_id": SENDER,
    "receiver_id": RECEIVER,
    "encrypted_message": base64.b64encode(ciphertext).decode(),
    "encrypted_sym_key": base64.b64encode(encrypted_symmetric_key).decode(),
    "signature": signature_b64
}

headers = {
    "Authorization": f"Bearer {TOKEN}"
}

# KIRIM KE SERVER
response = requests.post(
    f"{SERVER}/relay",
    json=payload,
    headers=headers
)

# OUTPUT 
print("=== SENDER ===")
print("Sender      :", SENDER)
print("Receiver    :", RECEIVER)
print("Plaintext   :", plaintext_message)
print("Ciphertext  :", ciphertext.decode())
print("Signature   :", signature_b64)
print("Encrypted Sym Key :", base64.b64encode(encrypted_symmetric_key).decode())
print("Server Resp :", response.json())
