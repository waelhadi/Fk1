def run_decryption(data_b64, salt_b64, password):
    import base64, zlib, traceback
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

    try:
        salt = base64.b64decode(salt_b64)
        data = base64.b64decode(data_b64)
        key = derive_key(password, salt)
        decrypted = Fernet(key).decrypt(data)
        code = zlib.decompress(decrypted).decode()

        # الحل السحري هنا:
        exec("import os\n" + code, globals())

    except Exception as e:
        print("فشل في فك التشفير أو التنفيذ:")
        traceback.print_exc()
