import asyncio
import csv
import json
import os
import psutil
import numpy as np
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest
import pickle
from datetime import datetime
import logging
from fastapi import Request
import time
from typing import Dict, List
import uuid
from ping3 import ping
from contextlib import asynccontextmanager
from collections import deque
import threading
import uvicorn

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WebSocketManager:
    def __init__(self):
        self.clients: Dict[str, WebSocket] = {}

    def connect(self, websocket: WebSocket, client_id: str):
        self.clients[client_id] = websocket
        logger.info(f"Connected WebSocket for client_id: {client_id}")

    def disconnect(self, client_id: str):
        if client_id in self.clients:
            del self.clients[client_id]
            logger.info(f"Disconnected WebSocket for client_id: {client_id}")

    async def send_to_client(self, client_id: str, message: dict):
        if client_id in self.clients:
            try:
                await self.clients[client_id].send_json(message)
                logger.debug(f"Sent message to {client_id}: {message}")
            except Exception as e:
                logger.error(f"Error sending message to {client_id}: {str(e)}")
                self.disconnect(client_id)

transfer_rate = deque(maxlen=1)
network_thread = None

def calc_ul_dl(rate, dt=1):
    try:
        interfaces = psutil.net_io_counters(pernic=True).keys()
        logger.info(f"Available network interfaces: {list(interfaces)}")
        t0 = time.time()
        last_counters = {iface: psutil.net_io_counters(pernic=True)[iface] for iface in interfaces}
        while True:
            time.sleep(dt)
            t1 = time.time()
            ul_total, dl_total = 0, 0
            for iface in interfaces:
                try:
                    counter = psutil.net_io_counters(pernic=True)[iface]
                    last = last_counters[iface]
                    ul = (counter.bytes_sent - last.bytes_sent) / (t1 - t0) / 1000.0
                    dl = (counter.bytes_recv - last.bytes_recv) / (t1 - t0) / 1000.0
                    if ul > 0 or dl > 0:
                        logger.debug(f"Interface {iface}: upload={ul:.2f} kB/s, download={dl:.2f} kB/s")
                    ul_total += ul if ul > 0 else 0
                    dl_total += dl if dl > 0 else 0
                    last_counters[iface] = counter
                except Exception as e:
                    logger.warning(f"Error monitoring interface {iface}: {str(e)}")
            rate.append((ul_total, dl_total))
            logger.debug(f"Total rates: upload={ul_total:.2f} kB/s, download={dl_total:.2f} kB/s")
            t0 = t1
    except Exception as e:
        logger.error(f"Error in network monitoring: {str(e)}")

def start_network_monitoring():
    global network_thread
    if network_thread is None or not network_thread.is_alive():
        network_thread = threading.Thread(target=calc_ul_dl, args=(transfer_rate, 1))
        network_thread.daemon = True
        network_thread.start()
        logger.info("Started network monitoring thread")

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_csv()
    start_network_monitoring()
    ws_manager = WebSocketManager()
    app.state.ws_manager = ws_manager
    task = asyncio.create_task(collect_and_broadcast(ws_manager))
    logger.info("Application startup complete")
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            logger.info("Background task cancelled")
        for client_id in list(ws_manager.clients.keys()):
            ws_manager.disconnect(client_id)
        logger.info("Application shutdown complete")

app = FastAPI(lifespan=lifespan)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Received request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Response headers: {response.headers}")
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

DATA_DIR = "data"
MODEL_DIR = "models"
CSV_FILE = os.path.join(DATA_DIR, "network_data.csv")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

class NetworkStats(BaseModel):
    timestamp: str
    download: float
    upload: float
    latency: float
    packets_received: int
    cpu: float
    memory: float

client_data: Dict[str, Dict] = {}
blocked_ips: List[str] = []
prevention_enabled: Dict[str, bool] = {}
attack_status: Dict[str, str] = {}
model_status: Dict[str, Dict] = {}

def init_csv():
    try:
        if not os.path.exists(CSV_FILE):
            with open(CSV_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'download', 'upload', 'latency', 'packets_received', 'cpu', 'memory'])
            logger.info(f"Created CSV file with headers at {CSV_FILE}")
        else:
            with open(CSV_FILE, 'r') as f:
                reader = csv.reader(f)
                headers = next(reader, None)
                expected = ['timestamp', 'download', 'upload', 'latency', 'packets_received', 'cpu', 'memory']
                if headers != expected:
                    logger.warning(f"Invalid CSV headers: {headers}, recreating file")
                    with open(CSV_FILE, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(expected)
                    logger.info(f"Recreated CSV file with correct headers at {CSV_FILE}")
    except Exception as e:
        logger.error(f"Failed to initialize CSV file: {str(e)}")
        raise

def get_network_stats():
    try:
        ul, dl = (0, 0) if not transfer_rate else transfer_rate[-1]
        net_io = psutil.net_io_counters()
        latency = ping('8.8.8.8', unit='ms', timeout=2)
        stats = {
            'timestamp': datetime.now().isoformat(),
            'download': dl if dl >= 0 else 0,
            'upload': ul if ul >= 0 else 0,
            'latency': latency if latency is not None else 0,
            'packets_received': net_io.packets_recv if net_io.packets_recv else 0,
            'cpu': psutil.cpu_percent(interval=0.1) or 0,
            'memory': psutil.virtual_memory().percent or 0
        }
        logger.debug(f"Network stats: {stats}")
        return stats
    except Exception as e:
        logger.error(f"Error getting network stats: {str(e)}")
        return {
            'timestamp': datetime.now().isoformat(),
            'download': 0,
            'upload': 0,
            'latency': 0,
            'packets_received': 0,
            'cpu': 0,
            'memory': 0
        }

def save_to_csv(data):
    try:
        numeric_fields = ['download', 'upload', 'latency', 'packets_received', 'cpu', 'memory']
        for field in numeric_fields:
            if not isinstance(data[field], (int, float)) or data[field] < 0:
                logger.warning(f"Invalid value for {field}: {data[field]}, setting to 0")
                data[field] = 0
        with open(CSV_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                data['timestamp'],
                data['download'],
                data['upload'],
                data['latency'],
                data['packets_received'],
                data['cpu'],
                data['memory']
            ])
        logger.debug(f"Saved data to CSV: {data}")
    except Exception as e:
        logger.error(f"Error saving to CSV: {str(e)}")

def calculate_baseline(client_id: str):
    if len(client_data.get(client_id, {}).get('network_history', [])) < 50:
        return None
    history = client_data[client_id]['network_history']
    return {
    'downloadSpeed': np.percentile([x['download'] for x in history], 90),
    'uploadSpeed': np.percentile([x['upload'] for x in history], 90),
    'latency': np.percentile([x['latency'] for x in history], 90),
    'packetsReceived': np.percentile([x['packets_received'] for x in history], 90)
}

def train_model(client_id: str, ws_manager: WebSocketManager):
    try:
        model_status[client_id] = {
            'training': True,
            'trained': False,
            'samples_collected': 0
        }
        asyncio.run(ws_manager.send_to_client(client_id, {
            'type': 'model_status',
            'status': 'training_started',
            'client_id': client_id
        }))
        data = []
        try:
            with open(CSV_FILE, 'r') as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    logger.error("CSV file has no headers")
                    asyncio.run(ws_manager.send_to_client(client_id, {
                        'type': 'model_status',
                        'status': 'training_error',
                        'error': 'CSV file has no headers',
                        'client_id': client_id
                    }))
                    return
                expected = ['timestamp', 'download', 'upload', 'latency', 'packets_received', 'cpu', 'memory']
                if set(expected[1:]) - set(reader.fieldnames):
                    logger.error(f"CSV missing required fields: {set(expected[1:]) - set(reader.fieldnames)}")
                    asyncio.run(ws_manager.send_to_client(client_id, {
                        'type': 'model_status',
                        'status': 'training_error',
                        'error': 'CSV missing required fields',
                        'client_id': client_id
                    }))
                    return
                for row in reader:
                    try:
                        entry = [
                            float(row['download']) if row['download'] and row['download'].replace('.', '', 1).isdigit() else 0,
                            float(row['upload']) if row['upload'] and row['upload'].replace('.', '', 1).isdigit() else 0,
                            float(row['latency']) if row['latency'] and row['latency'].replace('.', '', 1).isdigit() else 0,
                            float(row['packets_received']) if row['packets_received'] and row['packets_received'].isdigit() else 0,
                            float(row['cpu']) if row['cpu'] and row['cpu'].replace('.', '', 1).isdigit() else 0,
                            float(row['memory']) if row['memory'] and row['memory'].replace('.', '', 1).isdigit() else 0
                        ]
                        data.append(entry)
                    except (ValueError, KeyError) as e:
                        logger.warning(f"Skipping invalid CSV row: {row}, error: {str(e)}")
                        continue
        except FileNotFoundError:
            logger.error(f"CSV file not found: {CSV_FILE}")
            asyncio.run(ws_manager.send_to_client(client_id, {
                'type': 'model_status',
                'status': 'training_error',
                'error': 'CSV file not found',
                'client_id': client_id
            }))
            return
        if len(data) < 50:
            logger.error(f"Not enough valid data to train model: {len(data)} samples")
            asyncio.run(ws_manager.send_to_client(client_id, {
                'type': 'model_status',
                'status': 'training_error',
                'error': f'Not enough valid data samples ({len(data)})',
                'client_id': client_id
            }))
            return
        model = IsolationForest(contamination=0.01, random_state=42)
        model.fit(data)
        model_path = os.path.join(MODEL_DIR, f"isolation_forest_{client_id}.pkl")
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        baseline = calculate_baseline(client_id)
        if baseline:
            asyncio.run(ws_manager.send_to_client(client_id, {
        'type': 'baseline_update',
        'baseline': baseline,
        'client_id': client_id
    }))

        logger.info(f"Saved model to {model_path}")
        model_status[client_id] = {
            'training': False,
            'trained': True,
            'samples_collected': len(data)
        }
        asyncio.run(ws_manager.send_to_client(client_id, {
            'type': 'model_status',
            'status': 'training_completed',
            'client_id': client_id,
            'samples_collected': len(data)
        }))
    except Exception as e:
        logger.error(f"Training failed for {client_id}: {str(e)}")
        model_status[client_id] = {
            'training': False,
            'trained': False,
            'samples_collected': model_status[client_id].get('samples_collected', 0)
        }
        asyncio.run(ws_manager.send_to_client(client_id, {
            'type': 'model_status',
            'status': 'training_error',
            'error': str(e),
            'client_id': client_id
        }))

def detect_anomaly(client_id: str, data_point):
    try:
        model_path = os.path.join(MODEL_DIR, f"isolation_forest_{client_id}.pkl")
        if not os.path.exists(model_path):
            logger.info(f"No model found for {client_id}")
            return {'is_anomaly': False}
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        features = np.array([[
            data_point['download'],
            data_point['upload'],
            data_point['latency'],
            data_point['packets_received'],
            data_point['cpu'],
            data_point['memory']
        ]])
        prediction = model.predict(features)
        raw_score = model.decision_function(features)[0]
        max_negative_score = np.abs(model.score_samples([[0]*6])[0])
        confidence = min(max(np.abs(raw_score) / max_negative_score, 0), 1)
        confidence_percent = confidence * 100
        logger.info(f"Anomaly detection for {client_id}: is_anomaly={prediction[0] == -1}, "
                    f"raw_score={raw_score:.4f}, confidence_percent={confidence_percent:.2f}%, "
                    f"features={data_point}")
        if prediction[0] == -1:
            return {
                'is_anomaly': True,
                'score': raw_score,
                'confidence_percent': confidence_percent,
                'features': ['download', 'upload', 'latency', 'packets_received', 'cpu', 'memory']
            }
        return {'is_anomaly': False}
    except Exception as e:
        logger.error(f"Anomaly detection failed for {client_id}: {str(e)}")
        return {'is_anomaly': False}

async def simulate_attack(client_id: str, ws_manager: WebSocketManager):
    attack_status[client_id] = 'started'
    threading.Thread(target=train_model, args=(client_id, ws_manager)).start()
    await ws_manager.send_to_client(client_id, {
        'type': 'attack_status',
        'status': 'started',
        'client_id': client_id
    })
    logger.info(f"Started attack simulation for {client_id}")
    return True

def stop_attack(client_id: str, ws_manager: WebSocketManager):
    attack_status[client_id] = 'stopped'
    loop = asyncio.get_event_loop()
    if loop.is_running():
        loop.create_task(ws_manager.send_to_client(client_id, {
            'type': 'attack_status',
            'status': 'stopped',
            'client_id': client_id
        }))
    else:
        loop.run_until_complete(ws_manager.send_to_client(client_id, {
            'type': 'attack_status',
            'status': 'stopped',
            'client_id': client_id
        }))
    logger.info(f"Stopped attack simulation for {client_id}")
    return True

async def collect_and_broadcast(ws_manager: WebSocketManager):
    sample_count = 0
    while True:
        client_ids = list(ws_manager.clients.keys())
        logger.debug(f"Active clients: {client_ids}, client_data keys: {list(client_data.keys())}")
        if not client_ids:
            logger.debug("No active clients, skipping broadcast")
        else:
            logger.debug(f"Broadcasting to clients: {client_ids}")
        for client_id in client_ids:
            if client_id not in client_data:
                logger.warning(f"Client {client_id} not found in client_data, removing from clients")
                ws_manager.disconnect(client_id)
                continue
            try:
                stats = get_network_stats()
                if not all(isinstance(stats[field], (int, float)) and stats[field] >= 0 
                          for field in ['download', 'upload', 'latency', 'packets_received', 'cpu', 'memory']):
                    logger.warning(f"Invalid network stats for {client_id}: {stats}")
                    continue
                if attack_status.get(client_id, 'stopped') == 'started':
                    multiplier = np.random.uniform(40, 55)
                    stats['download'] *= multiplier
                    stats['upload'] *= multiplier
                    stats['latency'] *= multiplier
                    stats['packets_received'] *= multiplier
                    # stats['cpu'] *= multiplier
                    # stats['memory'] *= multiplier
                    logger.debug(f"Simulated attack for {client_id} with multiplier {multiplier:.2f}x")
                save_to_csv(stats)
                sample_count += 1
                client_data[client_id]['network_history'].append(stats)
                client_data[client_id]['network_history'] = client_data[client_id]['network_history'][-50:]
                await ws_manager.send_to_client(client_id, {
                    'type': 'data_update',
                    'data': stats,
                    'client_id': client_id
                })
                if model_status.get(client_id, {}).get('trained', False):
                    anomaly_result = detect_anomaly(client_id, stats)
                    if anomaly_result.get('is_anomaly'):
                        alert = {
                            'message': 'Anomaly detected in network traffic',
                            'details': {
                                'score': anomaly_result['score'],
                                'confidence_percent': anomaly_result['confidence_percent'],
                                'features': anomaly_result['features']
                            },
                            'timestamp': stats['timestamp'],
                            'source_ip': '192.168.1.1',
                            'client_id': client_id
                        }
                        client_data[client_id]['alerts'].append(alert)
                        client_data[client_id]['alerts'] = client_data[client_id]['alerts'][-5:]
                        await ws_manager.send_to_client(client_id, {
                            'type': 'alert',
                            'alert': alert,
                            'client_id': client_id
                        })
                        logger.info(f"Sent alert to {client_id}: confidence_percent={alert['details']['confidence_percent']:.2f}%")
                        if prevention_enabled.get(client_id, False) and alert['source_ip'] not in blocked_ips:
                            blocked_ips.append(alert['source_ip'])
                            logger.info(f"Blocked IP (simulated): {alert['source_ip']}")
                            await ws_manager.send_to_client(client_id, {
                                'type': 'blocked_ip',
                                'ip': alert['source_ip'],
                                'client_id': client_id
                            })
                if sample_count >= 50 and not model_status.get(client_id, {}).get('trained', False):
                    logger.info(f"Starting model training for {client_id}")
                    threading.Thread(target=train_model, args=(client_id, ws_manager)).start()
            except Exception as e:
                logger.error(f"Error in data collection for {client_id}: {str(e)}")
        await asyncio.sleep(1)

@app.get("/get-client-id", response_class=PlainTextResponse)
async def get_client_id():
    client_id = str(uuid.uuid4())
    client_data[client_id] = {'network_history': [], 'alerts': []}
    model_status[client_id] = {'training': False, 'trained': False, 'samples_collected': 0}
    attack_status[client_id] = 'stopped'
    prevention_enabled[client_id] = False
    logger.info(f"Generated client ID: {client_id}")
    return client_id

@app.get("/status")
async def check_status():
    return {"status": "ok"}

@app.get("/data")
async def get_data():
    response = {}
    for client_id in client_data:
        response[client_id] = client_data[client_id]
        baseline = calculate_baseline(client_id)
        if baseline:
            response[client_id]['baseline'] = baseline
    return response

@app.post("/train-model/{client_id}")
async def train_model_endpoint(client_id: str):
    if client_id not in client_data:
        logger.error(f"Client not found: {client_id}")
        raise HTTPException(status_code=404, detail="Client not found")
    logger.info(f"Triggering model training for {client_id}")
    threading.Thread(target=train_model, args=(client_id, app.state.ws_manager)).start()
    return {"status": "Training started"}

@app.post("/simulate-attack/{client_id}")
async def simulate_attack_endpoint(client_id: str):
    try:
        if client_id not in client_data:
            logger.error(f"Client not found: {client_id}")
            raise HTTPException(status_code=404, detail="Client not found")
        await simulate_attack(client_id, app.state.ws_manager)
        return JSONResponse(status_code=200, content={"status": "Attack started"})
    except Exception as e:
        logger.error(f"Error simulating attack: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/stop-attack/{client_id}")
async def stop_attack_endpoint(client_id: str):
    try:
        if client_id not in client_data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        stop_attack(client_id, app.state.ws_manager)
        
        return JSONResponse(
            status_code=200,
            content={"status": "Attack stopped"}
        )
    except Exception as e:
        logger.error(f"Error stopping attack: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/toggle-prevention/{client_id}")
async def toggle_prevention(client_id: str, status: dict):
    if client_id not in client_data:
        logger.error(f"Client not found: {client_id}")
        raise HTTPException(status_code=404, detail="Client not found")
    prevention_enabled[client_id] = status.get('prevention', False)
    await app.state.ws_manager.send_to_client(client_id, {
        'type': 'prevention_status',
        'status': prevention_enabled[client_id],
        'client_id': client_id
    })
    logger.info(f"Prevention toggled for {client_id}: {prevention_enabled[client_id]}")
    return {"status": "Prevention toggled"}

@app.post("/unblock-ip/{ip}")
async def unblock_ip_endpoint(ip: str):
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        logger.info(f"Unblocked IP (simulated): {ip}")
        for client_id in app.state.ws_manager.clients.keys():
            await app.state.ws_manager.send_to_client(client_id, {
                'type': 'unblocked_ip',
                'ip': ip,
                'client_id': client_id
            })
    return {"status": "IP unblocked"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    ws_manager = app.state.ws_manager
    logger.info("WebSocket connection attempt received")
    await websocket.accept()
    logger.info("WebSocket handshake completed")
    try:
        while True:
            data = await websocket.receive_json()
            logger.info(f"Received WebSocket message: {data}")
            client_id = data.get('client_id', '').strip('"')
            if data.get('type') == 'register':
                if client_id and client_id in client_data:
                    ws_manager.connect(websocket, client_id)
                    await ws_manager.send_to_client(client_id, {
                        'type': 'client_id',
                        'client_id': client_id
                    })
                    logger.info(f"Registered client {client_id} via WebSocket")
                else:
                    logger.warning(f"Invalid or unregistered client_id: {client_id}")
                    await websocket.send_json({
                        'type': 'error',
                        'message': 'Invalid client_id. Please fetch a new client_id.'
                    })
                    await websocket.close(code=1008)
            elif data.get('type') == 'heartbeat':
                if client_id in ws_manager.clients:
                    logger.debug(f"Received heartbeat from client {client_id}")
                    await ws_manager.send_to_client(client_id, {'type': 'heartbeat_response'})
                else:
                    logger.warning(f"Heartbeat from unregistered client_id: {client_id}")
                    await websocket.close(code=1008)
    except WebSocketDisconnect:
        for client_id, ws in list(ws_manager.clients.items()):
            if ws == websocket:
                ws_manager.disconnect(client_id)
                break
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
        await websocket.close(code=1011)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)