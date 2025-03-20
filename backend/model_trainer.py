import time
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from fastapi import HTTPException

def background_trainer():
    while True:
        time.sleep(3600)  # Retrain every hour
        for client_id in CLIENT_DATA:
            samples = CLIENT_DATA[client_id]["samples"]
            if len(samples) < BASELINE_SAMPLES:
                continue
            
            features = []
            for sample in samples[-BASELINE_SAMPLES:]:
                features.append([
                    sample['download'],
                    sample['upload'],
                    sample['latency'],
                    sample['packets_received'],
                    sample['packets_sent'],
                    sample['cpu'],
                    sample['memory']
                ])
            
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(features)
            
            model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42
            )
            model.fit(X_scaled)
            
            CLIENT_DATA[client_id]["model"] = model
            CLIENT_DATA[client_id]["scaler"] = scaler
            print(f"Retrained model for {client_id}")

# Start training thread
training_thread = threading.Thread(target=background_trainer)
training_thread.daemon = True
training_thread.start()