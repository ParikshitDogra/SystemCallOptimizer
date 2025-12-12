import eventlet
eventlet.monkey_patch()  # REQUIRED: Must be the very first line

from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import subprocess
import json
import threading
import os
import psutil 

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', max_http_buffer_size=1e7)

class MonitorManager:
    """
    Singleton class to manage the background process and thread safely.
    """
    def __init__(self):
        self.process = None
        self.thread = None
        self.lock = threading.Lock()
        self.active_pid = None

    def start_monitoring(self, target_pid):
        with self.lock:
            self.stop_monitoring()
            self.active_pid = target_pid
            self.thread = socketio.start_background_task(self._stream_output, target_pid)
            print(f"[Server] Monitoring thread started for PID {target_pid}")

    def stop_monitoring(self):
        if self.process:
            print(f"[Server] Stopping monitor for PID {self.active_pid}...")
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
            self.active_pid = None

    def _stream_output(self, target_pid):
        # Ensure 'backend_monitor.py' is in the same directory
        cmd = ["python3", "-u", "backend_monitor.py", str(target_pid)]
        
        try:
            # stderr=subprocess.STDOUT captures crashes and logs
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, 
                universal_newlines=True,
                bufsize=1
            )

            for line in iter(self.process.stdout.readline, ''):
                if line:
                    try:
                        data = json.loads(line.strip())
                        socketio.emit('new_data', data)
                    except json.JSONDecodeError:
                        clean_msg = line.strip()
                        print(f"[Backend Log] {clean_msg}")
                        socketio.emit('new_data', {
                            'type': 'status', 
                            'msg': f"> {clean_msg}", 
                            'error': False
                        })
                
                if self.process.poll() is not None:
                    break
                    
        except Exception as e:
            print(f"[Server] Monitor Error: {e}")
            socketio.emit('error', {'msg': str(e)})
        finally:
            if self.process:
                try:
                    self.process.kill()
                except:
                    pass

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
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_name = proc.info['name'] or ""
                cmdline = proc.info['cmdline'] or []
                
                if 'python' in proc_name.lower() or (cmdline and 'python' in cmdline[0]):
                    full_cmd = " ".join(cmdline)
                    if "web_server.py" in full_cmd or "backend_monitor.py" in full_cmd:
                        continue
                    display_name = cmdline[1] if len(cmdline) > 1 else "Python Process"
                    processes.append({'pid': proc.info['pid'], 'name': display_name})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        emit('scan_result', {'processes': processes})
    except Exception as e:
        emit('scan_result', {'processes': [], 'error': str(e)})

# --- AI Toggle Logic ---
@socketio.on('toggle_ai')
def handle_toggle_ai(data):
    enabled = data.get('enabled', False)
    flag_file = "ai_enabled.flag"
    
    if enabled:
        with open(flag_file, 'w') as f:
            f.write("1")
        emit('new_data', {'type': 'status', 'msg': '🤖 AI Auto-Pilot ENABLED. System will self-heal.', 'error': False})
    else:
        if os.path.exists(flag_file):
            os.remove(flag_file)
        emit('new_data', {'type': 'status', 'msg': '🛑 AI Auto-Pilot DISABLED. Passive Monitoring Mode.', 'error': False})

# --- Reset Priority Logic ---
@socketio.on('reset_priority')
def handle_reset(data):
    pid = data.get('pid')
    if not pid: return
    
    print(f"[Server] Resetting priority for PID {pid}...")
    cmd = ["renice", "-n", "0", "-p", str(pid)]
    
    try:
        subprocess.run(cmd, check=True)
        emit('new_data', {'type': 'status', 'msg': f"🔄 RESET: Priority Normal (0) for PID {pid}.", 'error': False})
    except Exception as e:
        emit('new_data', {'type': 'status', 'msg': f"❌ Reset Failed: {e}", 'error': True})

if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
        with open('templates/dashboard.html', 'w') as f:
            f.write("<h1>Dashboard Placeholder</h1>") 

    # Clean up flag file on start so AI starts as OFF
    if os.path.exists("ai_enabled.flag"):
        os.remove("ai_enabled.flag")

    print("[*] Web Server running on http://127.0.0.1:5000")
    socketio.run(app, debug=True, port=5000)
