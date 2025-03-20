import socket
import json
import time
import requests
import psutil
from datetime import datetime
import uuid
import random
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Generate a unique client ID using the hostname and a UUID
CLIENT_ID = f"client_{socket.gethostname()}_{str(uuid.uuid4())[:8]}"

# API endpoint for sending network metrics
API_URL = "http://localhost:8000/api/metrics"

# Initialize previous network counters for accurate speed calculation
prev_bytes_sent = 0
prev_bytes_recv = 0
prev_time = time.time()

def get_network_stats():
    """Collect real network statistics."""
    global prev_bytes_sent, prev_bytes_recv, prev_time
    
    try:
        current_time = time.time()
        time_diff = current_time - prev_time
        
        # Get network counters
        net_io = psutil.net_io_counters()
        
        # Calculate network speeds based on differences since last check
        if prev_bytes_recv > 0:
            bytes_recv_diff = net_io.bytes_recv - prev_bytes_recv
            bytes_sent_diff = net_io.bytes_sent - prev_bytes_sent
            
            # Convert to KB/s
            download_speed = (bytes_recv_diff / time_diff) / 1024
            upload_speed = (bytes_sent_diff / time_diff) / 1024
        else:
            # First run, set to 0
            download_speed = 0
            upload_speed = 0
        
        # Update previous values
        prev_bytes_recv = net_io.bytes_recv
        prev_bytes_sent = net_io.bytes_sent
        prev_time = current_time
        
        # Get system resource usage
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent

        # Calculate latency (using Google DNS for testing)
        try:
            start_time = time.time()
            socket.create_connection(("8.8.8.8", 53), timeout=2)
            latency = (time.time() - start_time) * 1000  # Convert to ms
        except socket.error as e:
            logger.warning(f"Unable to measure latency: {e}")
            latency = 100  # Default value if unavailable

        # Build the data dictionary
        data = {
            "download": round(download_speed, 2),
            "upload": round(upload_speed, 2),
            "latency": round(latency, 2),
            "packets_received": net_io.packets_recv,
            "packets_sent": net_io.packets_sent,
            "cpu": cpu_usage,
            "memory": memory_usage,
            "timestamp": datetime.now().isoformat(),
        }
        
        return data
    except Exception as e:
        logger.error(f"Error collecting network stats: {e}")
        return None

def inject_anomaly(data, probability=0.05):
    """Occasionally inject anomalies for testing (5% chance by default)"""
    if random.random() < probability:
        logger.info("Injecting anomaly for testing purposes")
        # Pick a random field to make anomalous
        field = random.choice(["download", "upload", "latency", "cpu", "memory"])
        
        # Multiply by a factor to create an anomaly
        if field in ["download", "upload"]:
            data[field] *= random.uniform(5, 10)  # 5-10x increase
        elif field == "latency":
            data[field] *= random.uniform(5, 15)  # 5-15x increase
        elif field in ["cpu", "memory"]:
            data[field] = min(100, data[field] * random.uniform(1.5, 3))  # 1.5-3x increase, max 100%
            
    return data

def send_network_data():
    """Collect and send network metrics to the backend."""
    while True:
        try:
            network_data = get_network_stats()
            if network_data:
                payload = {
                    "client_id": CLIENT_ID,
                    **network_data
                }
                
                response = requests.post(
                    API_URL,
                    json=payload,
                    timeout=1
                )
                
                if response.status_code == 200:
                    logger.debug("Data sent successfully")
                else:
                    logger.error(f"Failed to send data: {response.text}")
            
            # Strict 1 second interval
            time.sleep(1 - (time.time() % 1))
            
        except Exception as e:
            logger.error(f"Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    import sys
    
    logger.info(f"📡 Starting network data capture with client ID: {CLIENT_ID}")
    logger.info(f"🔗 Sending data to: {API_URL}")
    
    if "--inject-anomalies" in sys.argv:
        logger.info("⚠️ Anomaly injection enabled for testing")
    
    send_network_data()