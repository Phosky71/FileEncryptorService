import os

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESCipher:
    def __init__(self, username):
        self.key = self.get_key_from_server(username)
        self.backend = default_backend()
        self.block_size = algorithms.AES.block_size

    @staticmethod
    def get_key_from_server(username):
        url = os.getenv('SERVER_URL') + f"/get_key/{username}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()["key"].encode('utf-8')
        else:
            raise Exception(f"Failed to retrieve key: {response.text}")

    def encrypt_file(self, file_path):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(self.block_size).padder()

        with open(file_path, 'rb') as file:
            file_data = file.read()

        padded_data = padder.update(file_data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        with open(file_path, 'wb') as file:
            file.write(iv + ciphertext)

    def decrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            iv = file.read(16)
            ciphertext = file.read()

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(self.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        with open(file_path, 'wb') as file:
            file.write(plaintext)
