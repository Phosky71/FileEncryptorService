from typing import List

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from database import collection, decrypted_collection, key_collection

app = FastAPI()


# Modelo para los datos de archivos
class FileData(BaseModel):
    file_name: str
    data: str


class KeyData(BaseModel):
    username: str
    key: str


# Sistema de gestión de conexiones WebSocket
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

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
async def websocket_endpoint(websocket: WebSocket):
    """
    Endpoint para gestionar conexiones WebSocket.
    """
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(f"Mensaje recibido: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Endpoints existentes
@app.post("/save_file/")
async def save_file(file_data: FileData):
    try:
        collection.insert_one(file_data.dict())
        return {"message": "File saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/save_key/")
async def save_key(key_data: KeyData):
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
async def get_key(username: str):
    try:
        key_data = key_collection.find_one({"username": username})
        if key_data:
            return {"key": key_data["key"]}
        else:
            raise HTTPException(status_code=404, detail="Key not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/move_decrypted_file/")
async def move_decrypted_file(file_data: FileData):
    try:
        collection.delete_one({"file_name": file_data.file_name})
        decrypted_collection.insert_one(file_data.dict())
        return {"message": "File moved to decrypted collection successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Configuración HTTPS con certificados SSL
if __name__ == "__main__":
    import uvicorn

    # Ruta a los certificados SSL generados con OpenSSL
    ssl_certfile = "cert.pem"
    ssl_keyfile = "key.pem"

    uvicorn.run(app, host="0.0.0.0", port=443, ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)
