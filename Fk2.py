import base64
import zlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_script(encrypted_data_b64: str, salt_b64: str, password: str):
    try:
        encrypted_data = base64.b64decode(encrypted_data_b64)
        salt = base64.b64decode(salt_b64)
        key = derive_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data)
        source_code = zlib.decompress(decrypted).decode()
        return source_code
    except Exception as e:
        return f"فشل فك التشفير: {e}"
