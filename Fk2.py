def run_decryption(data_b64, salt_b64, password):
    import base64, zlib, hashlib
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad

    def derive_key(password: str, salt: bytes):
        return PBKDF2(password, salt, dkLen=32, count=390000, hmac_hash_module=hashlib.sha256)

    try:
        salt = base64.b64decode(salt_b64)
        data = base64.b64decode(data_b64)

        key = derive_key(password, salt)
        iv = data[:16]
        ciphertext = data[16:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        code = zlib.decompress(decrypted).decode()

        exec(code)
        del code

    except Exception as e:
        print("فشل في فك التشفير أو التنفيذ:", e)
