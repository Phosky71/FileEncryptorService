# database.py
from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

# Obtener la URI de MongoDB desde las variables de entorno
mongo_uri = os.getenv('MONGO_URI')
client = MongoClient(mongo_uri)
db = client['file_db']
collection = db['encrypted_files']
decrypted_collection = db['decrypted_files']
key_collection = db['encryption_keys']