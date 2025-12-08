import eventlet
eventlet.monkey_patch()  # REQUIRED: Must be the very first line for async to work

from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import subprocess
import json
import threading
import os
import signal
import psutil # optimized process management

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
# max_http_buffer_size allows larger JSON payloads from the backend
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', max_http_buffer_size=1e7)

class MonitorManager:
    """
    Singleton class to manage the background process and thread safely.
    Prevents race conditions and ensures processes are cleaned up.
    """
    def __init__(self):
        self.process = None
        self.thread = None
        self.lock = threading.Lock()
        self.active_pid = None

    def start_monitoring(self, target_pid):
        with self.lock:
            # 1. Stop any existing monitor before starting a new one
            self.stop_monitoring()
            
            self.active_pid = target_pid
            
            # 2. Start the background thread managed by Eventlet
            self.thread = socketio.start_background_task(self._stream_output, target_pid)
            print(f"[Server] Monitoring thread started for PID {target_pid}")

    def stop_monitoring(self):
        """Terminates the subprocess and resets state."""
        if self.process:
            print(f"[Server] Stopping monitor for PID {self.active_pid}...")
            # Try graceful termination first (SIGTERM)
            self.process.terminate()
            try:
                # Wait 1 second for it to close cleanly, otherwise force Kill (SIGKILL)
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                print("[Server] Process unresponsive, forcing kill.")
                self.process.kill()
            
            self.process = None
            self.active_pid = None

    def _stream_output(self, target_pid):
        """Internal method to run in background thread."""
        # Note: Ensure 'backend_monitor.py' is in the same directory
        cmd = ["python3", "-u", "backend_monitor.py", str(target_pid)]
        
        try:
            # UPDATED: stderr=subprocess.STDOUT to capture errors/crashes
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, 
                universal_newlines=True,
                bufsize=1  # Line buffered
            )

            # Read stdout line by line
            # iter(readline, '') creates an iterator that stops at EOF
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    try:
                        data = json.loads(line.strip())
                        socketio.emit('new_data', data)
                    except json.JSONDecodeError:
                        # UPDATED: Log raw output (errors) to the dashboard console
                        clean_msg = line.strip()
                        print(f"[Backend Log] {clean_msg}")
                        socketio.emit('new_data', {
                            'type': 'status', 
                            'msg': f"> {clean_msg}", 
                            'error': False
                        })
                
                # Check if process is still alive so we don't loop forever on a dead pipe
                if self.process.poll() is not None:
                    break
                    
        except Exception as e:
            print(f"[Server] Monitor Error: {e}")
            socketio.emit('error', {'msg': str(e)})
        finally:
            # Final cleanup check
            if self.process:
                try:
                    self.process.kill()
                except:
                    pass

# Initialize the manager instance
monitor_manager = MonitorManager()

@app.route('/')
def index():
    return render_template('dashboard.html')

@socketio.on('start_monitor')
def handle_start(data):
    pid = data.get('pid')
    if not pid:
        emit('error', {'msg': 'No PID provided'})
        return
        
    monitor_manager.start_monitoring(pid)
    emit('status', {'msg': f'Attached to PID {pid}'})

@socketio.on('stop_monitor')
def handle_stop():
    monitor_manager.stop_monitoring()
    emit('status', {'msg': 'Monitoring stopped'})

@socketio.on('scan_processes')
def handle_scan():
    """
    Scans for Python processes using psutil (Direct /proc access).
    Optimization: Avoids spawning new shell processes via subprocess.
    """
    processes = []
    
    try:
        # Iterate over all running processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # 1. Check if it's a python process
                proc_name = proc.info['name'] or ""
                cmdline = proc.info['cmdline'] or []
                
                if 'python' in proc_name.lower() or (cmdline and 'python' in cmdline[0]):
                    
                    full_cmd = " ".join(cmdline)
                    
                    # 2. Filter out the monitoring infrastructure itself
                    if "web_server.py" in full_cmd or "backend_monitor.py" in full_cmd:
                        continue
                        
                    # 3. Create a readable name
                    display_name = "Python Process"
                    if len(cmdline) > 1:
                        display_name = cmdline[1] # Usually the script name
                        
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': display_name
                    })
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        emit('scan_result', {'processes': processes})
        
    except Exception as e:
        print(f"[Scan Error] {e}")
        emit('scan_result', {'processes': [], 'error': str(e)})

if __name__ == '__main__':
    # Auto-create templates folder to prevent crash on first run
    if not os.path.exists('templates'):
        os.makedirs('templates')
        with open('templates/dashboard.html', 'w') as f:
            f.write("<h1>Monitor Dashboard Placeholder</h1><p>Replace this with real dashboard code.</p>") 

    print("[*] Web Server running on http://127.0.0.1:5000")
    socketio.run(app, debug=True, port=5000)
