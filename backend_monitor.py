import time
import subprocess
import re
import pickle
import numpy as np
import json
import sys
import os
import logging
from collections import deque

# Suppress TensorFlow logs
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
import tensorflow as tf
from tensorflow.keras.models import load_model

# --- Configuration ---
MODEL_DIR = "models"
SEQUENCE_LENGTH = 5 # Must match Phase 2
STRACE_REGEX = re.compile(r'^(\w+)\((.*)\)\s+=\s+([-0-9a-fx\?]+).*\s+<([0-9\.]+)>')

class IntelligentMonitor:
    def __init__(self):
        self.logger = self._setup_logger()
        self.logger.info("Loading AI Models...")
        
        try:
            # Load Preprocessing Tools
            with open(f"{MODEL_DIR}/label_encoder.pkl", "rb") as f:
                self.le = pickle.load(f)
            with open(f"{MODEL_DIR}/scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)
            
            # Load Models
            with open(f"{MODEL_DIR}/isolation_forest.pkl", "rb") as f:
                self.iso_forest = pickle.load(f)
            
            self.lstm_model = load_model(f"{MODEL_DIR}/lstm_model.keras")
            
            # Sequence Buffer for LSTM (stores last N encoded syscalls)
            self.sequence_buffer = deque(maxlen=SEQUENCE_LENGTH)
            
            # Cache known classes to handle unseen syscalls gracefully
            self.known_syscalls = set(self.le.classes_)
            
            self.logger.info("Models loaded successfully.")
            
        except FileNotFoundError as e:
            self.logger.error(f"Model file missing: {e}. Did you run Phase 2?")
            sys.exit(1)

    def _setup_logger(self):
        logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
        return logging.getLogger("Monitor")

    def preprocess_input(self, syscall, latency):
        """Converts raw data into model-ready format."""
        # 1. Encode Syscall
        if syscall in self.known_syscalls:
            encoded_syscall = self.le.transform([syscall])[0]
        else:
            # Handle unknown syscalls (assign to a default or skip)
            # For simplicity, we use the first class (or you could retrain)
            encoded_syscall = 0 
            
        # 2. Normalize Latency
        # Scaler expects 2D array [[latency]]
        norm_latency = self.scaler.transform([[latency]])[0][0]
        
        return encoded_syscall, norm_latency

    def get_prediction(self):
        """Predicts the NEXT system call using LSTM."""
        if len(self.sequence_buffer) < SEQUENCE_LENGTH:
            return "Gathering Data..."
        
        # Prepare input: Reshape to (1, 5, 1)
        input_seq = np.array(self.sequence_buffer).reshape(1, SEQUENCE_LENGTH, 1)
        
        # Predict
        probs = self.lstm_model.predict(input_seq, verbose=0)
        predicted_index = np.argmax(probs)
        
        # Decode back to string
        prediction = self.le.inverse_transform([predicted_index])[0]
        return prediction

    def detect_anomaly(self, encoded_syscall, norm_latency):
        """Checks if the current call is an anomaly using Isolation Forest."""
        # Input shape: [[syscall_code, latency]]
        features = np.array([[encoded_syscall, norm_latency]])
        
        # Prediction: 1 = Normal, -1 = Anomaly
        score = self.iso_forest.predict(features)[0]
        return "Normal" if score == 1 else "ANOMALY"

    def start_monitoring(self, pid):
        self.logger.info(f"Attaching to PID {pid}...")
        
        cmd = ["strace", "-T", "-e", "trace=all", "-p", str(pid)]
        
        try:
            process = subprocess.Popen(
                cmd, 
                stderr=subprocess.PIPE, 
                universal_newlines=True,
                bufsize=1
            )
            
            print("\n--- Live AI Monitor Running (JSON Output) ---")
            
            for line in iter(process.stderr.readline, ''):
                match = STRACE_REGEX.search(line.strip())
                if match:
                    syscall_name = match.group(1)
                    latency_str = match.group(4)
                    
                    try:
                        latency = float(latency_str)
                        
                        # Preprocess
                        enc_syscall, norm_latency = self.preprocess_input(syscall_name, latency)
                        
                        # Update Buffer
                        self.sequence_buffer.append(enc_syscall)
                        
                        # Run Inference
                        prediction = self.get_prediction()
                        status = self.detect_anomaly(enc_syscall, norm_latency)
                        
                        # Create Output Object
                        result = {
                            "timestamp": time.time(),
                            "current_syscall": syscall_name,
                            "latency": latency,
                            "predicted_next": prediction,
                            "status": status
                        }
                        
                        # Print JSON (for the future GUI to parse)
                        print(json.dumps(result))
                        # Flush stdout to ensure real-time delivery
                        sys.stdout.flush()
                        
                    except Exception as e:
                        continue # Skip malformed lines
                        
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped.")
        except Exception as e:
            self.logger.error(f"Error attaching to process: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 backend_monitor.py <PID>")
        sys.exit(1)
        
    pid = sys.argv[1]
    monitor = IntelligentMonitor()
    monitor.start_monitoring(pid)