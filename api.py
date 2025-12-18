from fastapi import FastAPI, HTTPException, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
import base64, os


app = FastAPI(title="Security Service - STELLA")

ALLOWED_USERS = {"nasihuy", "jule"}
TOKENS = {
    "nasihuy": "izin-token",
    "jule": "izin-token-123"
}

os.makedirs("data", exist_ok=True)


def check_token(user_id: str, authorization: str):
    if authorization != f"Bearer {TOKENS.get(user_id)}":
        raise HTTPException(status_code=401, detail="Invalid token")

# MODELS
class StoreKeyRequest(BaseModel):
    user_id: str
    public_key: str

class VerifyRequest(BaseModel):
    user_id: str
    encrypted_message: str
    signature: str

class RelayRequest(BaseModel):
    sender_id: str
    receiver_id: str
    encrypted_message: str
    encrypted_sym_key: str
    signature: str

class VerifyPDFRequest(BaseModel):
    user_id: str
    pdf_hash: str
    signature: str


# ENDPOINTS
@app.get("/health")
def health():
    return {"status": "running"}

# STORE PUBLIC KEY 
@app.post("/store")
def store_key(data: StoreKeyRequest, authorization: str = Header(..., alias="Authorization")):
    if data.user_id not in ALLOWED_USERS:
        raise HTTPException(403, "User not allowed")

    check_token(data.user_id, authorization)

    with open(f"data/{data.user_id}_pubkey.txt", "w") as f:
        f.write(data.public_key)
    
    serialization.load_pem_public_key(data.public_key.encode())

    return {"message": "Public key stored", "user": data.user_id}

# VERIFY SIGNATURE N INTEGRITY
@app.post("/verify")
def verify(data: VerifyRequest, authorization: str = Header(..., alias="Authorization")):
    check_token(data.user_id, authorization)

    pub_path = f"data/{data.user_id}_pubkey.txt"
    if not os.path.exists(pub_path):
        raise HTTPException(404, "Public key not found")

    with open(pub_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    ciphertext = data.encrypted_message.encode()
    signature = base64.b64decode(data.signature)

    # original
    try:
        public_key.verify(signature, ciphertext)
        original_valid = True
    except InvalidSignature:
        original_valid = False

    # tampered
    tampered = ciphertext + b"x"
    try:
        public_key.verify(signature, tampered)
        tampered_valid = True
    except InvalidSignature:
        tampered_valid = False

    return {
        "original_valid": original_valid,
        "tampered_valid": tampered_valid
    }

# RELAY MESSAGE
@app.post("/relay")
def relay(data: RelayRequest, authorization: str = Header(..., alias="Authorization")):
    # 1. cek token
    check_token(data.sender_id, authorization)

    # 2. cek receiver
    if data.receiver_id not in ALLOWED_USERS:
        raise HTTPException(404, "Receiver not found")

    # 3. Load sender public key (signature verification)
    pub_path = f"data/{data.sender_id}_pubkey.txt"
    if not os.path.exists(pub_path):
        raise HTTPException(404, "Sender public key not found")

    with open(pub_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # 4. Decode signature
    signature = base64.b64decode(data.signature)
    ciphertext = base64.b64decode(data.encrypted_message)

    # 5. Verify signature 
    try:
        public_key.verify(signature, ciphertext)
    except InvalidSignature:
        raise HTTPException(400, "Invalid signature")

    # 6. Relay 
    return {
        "status": "relayed securely",
        "verified": True,
        "from": data.sender_id,
        "to": data.receiver_id,
        "encrypted_message": data.encrypted_message,
        "encrypted_sym_key": data.encrypted_sym_key
    }


# PDF SIGN 
@app.post("/sign-pdf")
async def sign_pdf(
    user_id: str,
    file: UploadFile = File(...),
    authorization: str = Header(..., alias="Authorization")
):
    if user_id not in ALLOWED_USERS:
        raise HTTPException(403, "User not allowed")

    check_token(user_id, authorization)

    # 🔥 FIX DI SINI
    content = await file.read()

    if not content:
        raise HTTPException(400, "Uploaded PDF is empty")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(content)
    pdf_hash = digest.finalize()

    with open("punkhazard-keys/priv19.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    signature = private_key.sign(pdf_hash)

    return {
        "user": user_id,
        "pdf_hash": base64.b64encode(pdf_hash).decode(),
        "signature": base64.b64encode(signature).decode(),
        "algorithm": "SHA-256 + Ed25519",
        "status": "PDF signed successfully"
    }

    # 6. SIGN HASH
    signature = private_key.sign(pdf_hash)

    return {
        "user": user_id,
        "pdf_hash": base64.b64encode(pdf_hash).decode(),
        "signature": base64.b64encode(signature).decode(),
        "algorithm": "SHA-256 + Ed25519",
        "status": "PDF signed successfully"
    }


@app.post("/verify-pdf")
def verify_pdf_signature(data: VerifyPDFRequest):
    public_key = f"data/{data.user_id}_pubkey.txt"

    try:
        public_key.verify(
            base64.b64decode(data.signature),
            base64.b64decode(data.pdf_hash)
        )
        return {"verified": True}
    except Exception:
        return {"verified": False}

