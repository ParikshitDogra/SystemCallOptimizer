import time
import subprocess
import re
import pickle
import numpy as np
import json
import sys
import os
import logging
import warnings
from collections import deque
from datetime import datetime # Added for readable timestamps

# --- 1. Suppress Warnings & TensorFlow Logs ---
warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 

import tensorflow as tf
from tensorflow.keras.models import load_model

# --- Configuration ---
MODEL_DIR = "models"
SEQUENCE_LENGTH = 5 
LOG_FILE = "anomaly_log.json" # New: File to store anomalies
STRACE_REGEX = re.compile(r'^(\w+)\((.*)\)\s+=\s+([-0-9a-fx\?]+).*\s+<([0-9\.]+)>')

class IntelligentMonitor:
    def __init__(self):
        self.logger = self._setup_logger()
        self.logger.info("Initializing AI Engine...")
        
        self._send_json_status("Loading AI Models (this may take a few seconds)...")

        # Initialize/Create the log file if it doesn't exist
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w') as f:
                json.dump([], f)

        try:
            with open(f"{MODEL_DIR}/label_encoder.pkl", "rb") as f:
                self.le = pickle.load(f)
            with open(f"{MODEL_DIR}/scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)
            with open(f"{MODEL_DIR}/isolation_forest.pkl", "rb") as f:
                self.iso_forest = pickle.load(f)
            
            self.lstm_model = load_model(f"{MODEL_DIR}/lstm_model.keras")
            
            self.sequence_buffer = deque(maxlen=SEQUENCE_LENGTH)
            self.known_syscalls = set(self.le.classes_)
            
            self.logger.info("AI Models loaded successfully.")
            self._send_json_status("AI Models Ready. Attaching to process...")
            
        except FileNotFoundError as e:
            err_msg = f"Model file missing: {e}. Run Phase 2 first."
            self.logger.error(err_msg)
            self._send_json_status(err_msg, is_error=True)
            sys.exit(1)

    def _setup_logger(self):
        logging.basicConfig(format='[Backend] %(message)s', level=logging.INFO, stream=sys.stderr)
        return logging.getLogger("Monitor")

    def _send_json_status(self, msg, is_error=False):
        data = { "type": "status", "msg": msg, "error": is_error }
        print(json.dumps(data))
        sys.stdout.flush()

    def _log_anomaly(self, syscall, latency, prediction, timestamp):
        """
        Appends a detected anomaly to the JSON log file.
        """
        entry = {
            "time_readable": datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            "timestamp": timestamp,
            "syscall": syscall,
            "latency": latency,
            "predicted_next": prediction,
            "reason": "Abnormal Latency/Sequence"
        }
        
        try:
            # Read existing logs
            with open(LOG_FILE, 'r') as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
            
            # Append new entry
            logs.append(entry)
            
            # Write back to file
            with open(LOG_FILE, 'w') as f:
                json.dump(logs, f, indent=4)
                
        except Exception as e:
            self.logger.error(f"Failed to write log: {e}")

    def preprocess_input(self, syscall, latency):
        if syscall in self.known_syscalls:
            encoded_syscall = self.le.transform([syscall])[0]
        else:
            encoded_syscall = 0 
        norm_latency = self.scaler.transform([[latency]])[0][0]
        return encoded_syscall, norm_latency

    def get_prediction(self):
        if len(self.sequence_buffer) < SEQUENCE_LENGTH:
            return "Analyzing..."
        input_seq = np.array(self.sequence_buffer).reshape(1, SEQUENCE_LENGTH, 1)
        probs = self.lstm_model.predict(input_seq, verbose=0)
        predicted_index = np.argmax(probs)
        return self.le.inverse_transform([predicted_index])[0]

    def detect_anomaly(self, encoded_syscall, norm_latency):
        features = np.array([[encoded_syscall, norm_latency]])
        score = self.iso_forest.predict(features)[0]
        return "Normal" if score == 1 else "ANOMALY"

    def start_monitoring(self, pid):
        if not os.path.exists(f"/proc/{pid}"):
            self._send_json_status(f"Process {pid} not found!", is_error=True)
            return

        cmd = ["strace", "-T", "-e", "trace=all", "-p", str(pid)]
        
        try:
            process = subprocess.Popen(
                cmd, 
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            self._send_json_status(f"Attached to PID {pid}. Streaming Data...")
            
            for line in iter(process.stderr.readline, ''):
                clean_line = line.strip()
                if not clean_line: continue

                match = STRACE_REGEX.search(clean_line)
                if match:
                    syscall_name = match.group(1)
                    latency_str = match.group(4)
                    
                    try:
                        latency = float(latency_str)
                        enc_syscall, norm_latency = self.preprocess_input(syscall_name, latency)
                        self.sequence_buffer.append(enc_syscall)
                        
                        prediction = self.get_prediction()
                        status = self.detect_anomaly(enc_syscall, norm_latency)
                        
                        # NEW: If status is ANOMALY, save it to file!
                        current_time = time.time()
                        if status == "ANOMALY":
                            self._log_anomaly(syscall_name, latency, prediction, current_time)

                        result = {
                            "type": "data",
                            "timestamp": current_time,
                            "current_syscall": syscall_name,
                            "latency": latency,
                            "predicted_next": prediction,
                            "status": status
                        }
                        
                        print(json.dumps(result))
                        sys.stdout.flush()
                        
                    except Exception:
                        continue
                else:
                    if len(clean_line) > 5 and "resuming" not in clean_line:
                         self._send_json_status(f"[STRACE] {clean_line}")
                        
        except Exception as e:
            self.logger.error(f"Strace Error: {e}")
            self._send_json_status(f"Strace Error: {e}", is_error=True)
        finally:
            if 'process' in locals():
                process.terminate()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 backend_monitor.py <PID>")
        sys.exit(1)
    
    # Ensure logs aren't owned by root if using sudo (optional safety)
    if os.environ.get('SUDO_UID'):
        os.chown(LOG_FILE, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))

    pid = sys.argv[1]
    monitor = IntelligentMonitor()
    monitor.start_monitoring(pid)
