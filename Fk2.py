import base64, zipfile, tempfile, os, runpy

def run_encrypted(encrypted_zip_b64, password_enc_b64):
    password = base64.b64decode(password_enc_b64)
    zip_bytes = base64.b64decode(encrypted_zip_b64)

    with tempfile.TemporaryDirectory() as tmpdirname:
        zip_path = os.path.join(tmpdirname, 'hidden.zip')
        with open(zip_path, 'wb') as tmpzip:
            tmpzip.write(zip_bytes)

        with zipfile.ZipFile(zip_path) as zf:
            zf.setpassword(password)
            zf.extractall(tmpdirname)

        script_path = os.path.join(tmpdirname, 'script.py')
        runpy.run_path(script_path)
