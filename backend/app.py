from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import json
import asyncio
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import uuid
from datetime import datetime
from typing import List, Dict
import os
from fastapi.middleware.cors import CORSMiddleware
import threading

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (you can specify frontend URL)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Mount the frontend build directory
FRONTEND_BUILD_PATH = os.path.join(os.path.dirname(__file__), "../frontend/build")

# Check if frontend exists before mounting
if os.path.exists(FRONTEND_BUILD_PATH):
    app.mount("/", StaticFiles(directory=FRONTEND_BUILD_PATH, html=True), name="frontend")
    print("✅ Frontend is being served from:", FRONTEND_BUILD_PATH)
else:
    print("⚠️ Warning: Frontend build directory does not exist. Skipping frontend.")

# In-memory storage for client data
CLIENT_DATA = {}
BASELINE_SAMPLES = 60  # Minimum samples for baseline
MODEL_FILE = "isolation_forest_model.joblib"
SCALER_FILE = "scaler.joblib"
ALERTS = []  # Store alerts

class NetworkData(BaseModel):
    client_id: str
    download: float
    upload: float
    latency: float
    packets_received: int
    packets_sent: int
    cpu: float
    memory: float
    timestamp: datetime

class Alert(BaseModel):
    client_id: str
    message: str
    severity: str
    timestamp: datetime
    details: dict

# WebSocket connections manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"Error broadcasting to client: {e}")
                # Don't disconnect here, as it could modify the list during iteration

manager = ConnectionManager()

@app.get("/api/data")
async def get_network_data():
    """Fetch latest network data and alerts for frontend"""
    # Convert all timestamps to ISO strings
    samples = []
    if CLIENT_DATA:
        client_id = list(CLIENT_DATA.keys())[-1]
        raw_samples = CLIENT_DATA[client_id].get("samples", [])[-30:]
        samples = [{
            **s,
            "timestamp": s["timestamp"].isoformat() if isinstance(s["timestamp"], datetime) else s["timestamp"]
        } for s in raw_samples]

    return {
        "network_history": samples,
        "alerts": [{
            **a,
            "timestamp": a["timestamp"].isoformat() if isinstance(a["timestamp"], datetime) else a["timestamp"]
        } for a in ALERTS[-10:]],
        "current_stats": samples[-1] if samples else {},
        "baseline": CLIENT_DATA.get(client_id, {}).get("baseline") if CLIENT_DATA else None,
        "model_status": {
            "training": False,
            "trained": CLIENT_DATA.get(client_id, {}).get("model") is not None if CLIENT_DATA else False,
            "samples_collected": len(samples)
        }
    }
    
@app.get("/api/status")
async def get_status():
    """Check if the backend is running and return model status"""
    return {
        "status": "running",
        "model_trained": any(client.get("model") is not None for client in CLIENT_DATA.values()) if CLIENT_DATA else False,
        "samples_collected": sum(len(client.get("samples", [])) for client in CLIENT_DATA.values()),
        "clients": list(CLIENT_DATA.keys()),
    }

@app.post("/api/metrics")
async def receive_metrics(data: NetworkData):
    client_id = data.client_id
    
    # Initialize client storage if not exists
    if client_id not in CLIENT_DATA:
        CLIENT_DATA[client_id] = {
            "samples": [],
            "baseline": None,
            "model": None,
            "scaler": None
        }
    
    # Convert to dict including timestamp using new method
    data_dict = data.model_dump()
    # Convert datetime to ISO string
    data_dict["timestamp"] = data_dict["timestamp"].isoformat()
    
    # Store the sample
    CLIENT_DATA[client_id]["samples"].append(data_dict)
    
    # Keep only last 100 samples
    if len(CLIENT_DATA[client_id]["samples"]) > 100:
        CLIENT_DATA[client_id]["samples"] = CLIENT_DATA[client_id]["samples"][-100:]
    
    # Send update to frontend via WebSocket
    await manager.broadcast({
        "type": "client_id",
        "client_id": client_id
    })
    return {"status": "success"}
    
    # Check for anomalies if model is trained
    if CLIENT_DATA[client_id]["model"] is not None:
        try:
            # Run anomaly detection
            anomaly_result = await detect_anomaly_internal(client_id)
            
            # If anomaly detected, create an alert
            if anomaly_result["anomaly"]:
                alert = Alert(
                    client_id=client_id,
                    message=f"Anomaly detected for client {client_id}",
                    severity="high" if anomaly_result["score"] < -0.2 else "medium",
                    timestamp=datetime.now().isoformat(),  # Convert to ISO string
                    details={
                        "score": anomaly_result["score"],
                        "features": anomaly_result["features"]
                        }
                    )
                
                # Store the alert
                ALERTS.append(alert.model_dump())
                
                # Keep only the last 100 alerts
                if len(ALERTS) > 100:
                    ALERTS.pop(0)
                
                # Send alert to frontend
                await manager.broadcast({
                    "type": "alert",
                    "alert": alert.model_dump()  # Updated method
})
        except Exception as e:
            print(f"Error detecting anomaly: {e}")
    
    # Check if we have enough samples to train model
    if CLIENT_DATA[client_id]["model"] is None and len(CLIENT_DATA[client_id]["samples"]) >= BASELINE_SAMPLES:
        # Trigger model training in background
        asyncio.create_task(train_model_internal(client_id))
    
    return {"status": "success"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive, wait for messages from frontend
            data = await websocket.receive_text()
            
            # Process message if needed
            if data:
                try:
                    message = json.loads(data)
                    if message.get("type") == "get_status":
                        status = await get_status()
                        await websocket.send_json({"type": "status", "data": status})
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)

@app.post("/api/train-model/{client_id}")  # Changed from @app.get
async def train_model_endpoint(client_id: str):
    if client_id not in CLIENT_DATA:
        raise HTTPException(status_code=404, detail="Client not found")
    
    result = await train_model_internal(client_id)
    return result

async def train_model_internal(client_id: str):
    try:
        samples = CLIENT_DATA[client_id]["samples"]
        
        await manager.broadcast({
            "type": "model_status",
            "status": "training",
            "client_id": client_id
        })

        # Run CPU-intensive task in thread pool
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, 
            lambda: train_model_sync(client_id, samples)
        )

        CLIENT_DATA[client_id]["training"] = False
        await manager.broadcast({
            "type": "model_status",
            "status": "trained",
            "client_id": client_id
        })
        return result
    except Exception as e:
        CLIENT_DATA[client_id]["training"] = False
        await manager.broadcast({
            "type": "model_status",
            "status": "error",
            "client_id": client_id,
            "error": str(e)
        })
        return {"status": "error", "message": str(e)}

def train_model_sync(client_id: str, samples: list):
    """Synchronous model training"""
    features = [
        [
            s['download'], 
            s['upload'], 
            s['latency'], 
            s['packets_received']
        ] for s in samples
    ]
    
    scaler = StandardScaler()
    X = scaler.fit_transform(features)
    
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)
    
    CLIENT_DATA[client_id]["model"] = model
    CLIENT_DATA[client_id]["scaler"] = scaler
    return {"status": "success"}

@app.get("/api/detect-anomaly/{client_id}")
async def detect_anomaly_endpoint(client_id: str):
    """API endpoint to detect anomalies"""
    if client_id not in CLIENT_DATA:
        raise HTTPException(status_code=404, detail="Client not found")
    
    result = await detect_anomaly_internal(client_id)
    return result

async def detect_anomaly_internal(client_id: str):
    """Internal function to detect anomalies"""
    if client_id not in CLIENT_DATA:
        raise HTTPException(status_code=404, detail="Client not found")
    
    model = CLIENT_DATA[client_id]["model"]
    scaler = CLIENT_DATA[client_id]["scaler"]
    if not model or not scaler:
        raise HTTPException(status_code=400, detail="Model not trained")
    
    if not CLIENT_DATA[client_id]["samples"]:
        raise HTTPException(status_code=400, detail="No samples available")
    
    latest_sample = CLIENT_DATA[client_id]["samples"][-1]
    features = [
        latest_sample['download'],
        latest_sample['upload'],
        latest_sample['latency'],
        latest_sample['packets_received'],
        latest_sample['packets_sent'],
        latest_sample['cpu'],
        latest_sample['memory']
    ]
    
    X_scaled = scaler.transform([features])
    prediction = model.predict(X_scaled)
    score = model.decision_function(X_scaled)
    
    is_anomaly = prediction[0] == -1
    return {
        "anomaly": bool(is_anomaly),
        "score": float(score[0]),
        "features": features,
        "timestamp": latest_sample["timestamp"]
    }

@app.get("/api/alerts")
async def get_alerts():
    """Get recent alerts"""
    return {"alerts": ALERTS[-10:]}  # Return the 10 most recent alerts

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)