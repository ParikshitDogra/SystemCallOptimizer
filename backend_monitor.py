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
from datetime import datetime

# --- 1. Suppress Warnings & TensorFlow Logs ---
warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 

import tensorflow as tf
from tensorflow.keras.models import load_model

# --- Configuration ---
MODEL_DIR = "models"
SEQUENCE_LENGTH = 5 
LOG_FILE = "anomaly_log.json"
FLAG_FILE = "ai_enabled.flag" # File to check if AI Mode is ON
# Regex matches: openat(AT_FDCWD, "file", ...) = 3 <0.00015>
STRACE_REGEX = re.compile(r'^(\w+)\((.*)\)\s+=\s+([-0-9a-fx\?]+).*\s+<([0-9\.]+)>')

class IntelligentMonitor:
    def __init__(self):
        self.logger = self._setup_logger()
        self.logger.info("Initializing AI Engine...")
        
        # State tracking for optimization
        self.last_opt_time = 0 
        
        self._send_json_status("Loading AI Models (this may take a few seconds)...")

        # Initialize Log File
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w') as f:
                json.dump([], f)

        try:
            # Load Models
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
        """Helper to send status updates to the UI via JSON"""
        data = {
            "type": "status", 
            "msg": msg, 
            "error": is_error
        }
        print(json.dumps(data))
        sys.stdout.flush()

    def _log_anomaly(self, syscall, latency, prediction, timestamp):
        """Appends a detected anomaly to the JSON log file."""
        entry = {
            "time_readable": datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            "timestamp": timestamp,
            "syscall": syscall,
            "latency": latency,
            "predicted_next": prediction,
            "reason": "Abnormal Latency/Sequence"
        }
        try:
            with open(LOG_FILE, 'r') as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
            logs.append(entry)
            with open(LOG_FILE, 'w') as f:
                json.dump(logs, f, indent=4)
        except Exception as e:
            self.logger.error(f"Failed to write log: {e}")

    # --- NEW: Optimization Logic with Flag Check ---
    def _optimize_process(self, pid):
        """
        Active Optimization: Boosts process priority if AI Mode is enabled.
        """
        # 1. Check if AI Mode is enabled (by checking for flag file)
        if not os.path.exists(FLAG_FILE):
            # AI is OFF (Passive Mode) - Do nothing but log internally if needed
            return

        # 2. Cooldown Check
        if time.time() - self.last_opt_time < 10:
            return

        self._send_json_status(f"⚡ Anomaly Detected! AI Engaging Optimization for PID {pid}...", is_error=False)
        
        try:
            # Optimize by renicing process to higher priority (-5)
            cmd = ["renice", "-n", "-5", "-p", str(pid)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self._send_json_status(f"🚀 OPTIMIZATION SUCCESS: Priority boosted to -5.")
                self.last_opt_time = time.time()
            else:
                self._send_json_status(f"❌ Optimization Failed: {result.stderr.strip()}", is_error=True)
                self.last_opt_time = time.time()
                
        except Exception as e:
            self._send_json_status(f"Optimization Error: {e}", is_error=True)

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
                        
                        current_time = time.time()
                        
                        # --- TRIGGER OPTIMIZATION ---
                        if status == "ANOMALY":
                            self._log_anomaly(syscall_name, latency, prediction, current_time)
                            self._optimize_process(pid)

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
    
    # Optional: Fix file ownership if running as sudo
    if os.environ.get('SUDO_UID'):
        if os.path.exists(LOG_FILE):
             os.chown(LOG_FILE, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))

    pid = sys.argv[1]
    monitor = IntelligentMonitor()
    monitor.start_monitoring(pid)
