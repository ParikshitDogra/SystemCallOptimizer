import eventlet
eventlet.monkey_patch() # Required for smooth background threads

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import subprocess
import json
import threading
import time
import os

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

monitor_process = None
thread = None
thread_lock = threading.Lock()
stop_event = threading.Event()

def background_monitor(pid):
    """Runs the backend monitor and streams output to the web client."""
    global monitor_process
    
    cmd = ["python3", "-u", "backend_monitor.py", str(pid)]
    
    try:
        # Start the backend monitor subprocess
        monitor_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        
        print(f"[Server] Attached to PID {pid}")
        
        # Read line by line
        for line in iter(monitor_process.stdout.readline, ''):
            if stop_event.is_set():
                break
                
            if line:
                try:
                    # Parse JSON from backend
                    data = json.loads(line.strip())
                    # Emit to all connected web clients
                    socketio.emit('new_data', data)
                except json.JSONDecodeError:
                    continue
                    
    except Exception as e:
        print(f"[Server] Error: {e}")
    finally:
        if monitor_process:
            monitor_process.kill()
        print("[Server] Monitor Stopped")

@app.route('/')
def index():
    return render_template('dashboard.html')

@socketio.on('start_monitor')
def handle_start(data):
    global thread, stop_event
    pid = data.get('pid')
    
    # Stop existing thread if running
    if thread and thread.is_alive():
        stop_event.set()
        thread.join()
    
    # Start new monitoring thread
    stop_event.clear()
    thread = socketio.start_background_task(background_monitor, pid)
    emit('status', {'msg': f'Monitoring PID {pid} started'})

@socketio.on('stop_monitor')
def handle_stop():
    global stop_event, monitor_process
    stop_event.set()
    if monitor_process:
        monitor_process.kill()
    emit('status', {'msg': 'Monitoring stopped'})

@socketio.on('scan_processes')
def handle_scan():
    """Scans for Python processes."""
    try:
        cmd = "pgrep -fl python"
        output = subprocess.check_output(cmd, shell=True).decode()
        processes = []
        for line in output.strip().split('\n'):
            if not line: continue
            parts = line.split(' ', 1)
            # Filter out the server and monitor scripts
            if "web_server.py" in line or "backend_monitor.py" in line:
                continue
            processes.append({'pid': parts[0], 'name': parts[1] if len(parts) > 1 else 'Python Process'})
        
        emit('scan_result', {'processes': processes})
    except Exception as e:
        emit('scan_result', {'processes': []})

if __name__ == '__main__':
    # Create templates folder if it doesn't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
        
    print("[*] Web Server running on http://127.0.0.1:5000")
    socketio.run(app, debug=True, port=5000)