This Project works on Linux.
# AI-Enhanced System Call Monitoring & Optimization System

This project provides a real-time AI-powered system for monitoring Linux system calls, detecting anomalies, and automatically optimizing process performance. It includes:

- A live web dashboard
- A backend strace-based syscall tracer
- Machine learning models (LSTM + Isolation Forest)
- Dataset collection utilities
- A synthetic workload generator

---

## 📁 Project Structure

### `dashboard.html`
Interactive dashboard with:
- Real-time latency graphs  
- Syscall distribution charts  
- Live terminal logs  
- Process selection & controls  
- AI Auto-Pilot toggle  

### `backend_monitor.py`
Backend runtime engine that:
- Attaches to a PID via `strace`
- Streams syscall and latency data
- Predicts next syscall (LSTM)
- Flags anomalies (Isolation Forest)
- Renices the process automatically when AI mode is enabled

### `dummy_app.py`
Synthetic workload generator producing:
- File I/O syscalls  
- Sleep syscalls  
- CPU computation syscall patterns  

### `ml_model_trainer.py`
Trains:
1. Isolation Forest (anomaly detector)
2. LSTM model (syscall sequence predictor)

Outputs saved to `/models`.

### `data_collector.py`
Runs the dummy app under `strace` and generates:
- `syscall_dataset.csv` for model training

### `web_server.py`
Flask-SocketIO server that:
- Serves the dashboard
- Starts/stops backend monitoring threads
- Streams real-time JSON data to the UI
- Handles AI toggle and priority resets

---

## 🚀 System Workflow

### **Phase 1 — Data Collection**
Generate dataset:
python3 data_collector.py

### **Phase 2 — Model Training**
Train ML models:

python3 ml_model_trainer.py


### **Phase 3 — Monitoring & Optimization**
Start the dashboard server:
python3 web_server.py
Open:
http://127.0.0.1:5000


### **Optional — Generate Syscalls**
python3 dummy_app.py

Use its PID in the dashboard.

---

## 🛠 How to Use the Dashboard

1. Click **Scan Processes**
2. Choose a target PID
3. Click **EXECUTE**
4. (Optional) Enable **AI Auto-Pilot**
5. Watch:
   - Latency graph update live  
   - Syscall distribution change  
   - Anomaly detection status  
   - Terminal logs  

---

## 🌟 Features

- Real-time system call visualization
- Syscall latency chart with 60-point sliding window
- Syscall frequency distribution graph
- Anomaly detection using Isolation Forest
- Sequence prediction using LSTM
- Auto-healing mode using renice priority boost
- Terminal-style live logs
- AI toggle for autonomous optimization

---

## 📦 Requirements

### Python Packages
tensorflow
numpy
pandas
scikit-learn
flask
flask-socketio
eventlet
psutil
matplotlib


### Linux Dependencies
- `strace` must be installed
- `sudo` recommended for renice operations

---

## ⚠ Notes & Limitations

- LSTM prediction accuracy depends heavily on dataset quality.
- strace incurs overhead; use eBPF in future for lower cost telemetry.
- Dummy app is synthetic; real-world data improves model reliability.
- Dashboard recommended in Chromium browsers.

---

## 🔮 Future Enhancements

- eBPF integration for kernel-level tracing  
- Multi-PID monitoring support  
- GPU-based accelerated inference  
- Alerting system with email/webhooks  
- Automated syscall pattern clustering  
- Process behavior fingerprinting  

---

## 📜 License
MIT — Feel free to modify and extend.

---
