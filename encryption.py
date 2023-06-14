from argon2 import PasswordHasher
import os

from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

class PasswordEncryption:

    def encrypt_password(password):
        ph = PasswordHasher()
        return ph.hash(password)
    
    
    def verify_password(password, hash):
        ph = PasswordHasher()
        try:
            ph.verify(hash, password)
            return True
        except:
            return False
        

class dataEncryption:
    
    def data_encrypt(key, data, filetype):

        nonce = os.urandom(16)

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
        ).encryptor()

        encryptor.authenticate_additional_data(filetype)

        ciphertext = encryptor.update(data) + encryptor.finalize()

        return (nonce, ciphertext, encryptor.tag)
    

    def data_decrypt(key, nonce, tag, ciphertext, filetype):
            
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
            ).decryptor()
    
            decryptor.authenticate_additional_data(filetype)
    
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
            return plaintext


if __name__ == "__main__":
    print("working")

    #test encryption functions
    print(dataEncryption.data_encrypt(b"YELLOW SUBMARINE", b"Hello World", b"txt"))
    print(dataEncryption.data_decrypt(b"YELLOW SUBMARINE", b'\xd2\xbc\xf9\xfa\xc8\x059TS\xd6\xbb\x03\xbb\xd9%\x8f', b'9\xc7\xf9\xc7N\xf44A\x05k\xb6\xcbR\xcc\x05A', b'\xa9\x85q\xff1p\x12\x96m\x1fc', b"txt"))

