from flask import Flask, render_template, jsonify, request
import sqlite3
import threading
import configparser
import time
import os
import socket
import IDS 
import get_IoCs

app = Flask(__name__)
DB_FILE = 'ids_alerts.db'

#  Global values
ids_thread = None
stop_event = threading.Event()
ids_status = "Stopped"
ids_error = "" 

scan_thread = None
scan_stop_event = threading.Event()
scan_status = "Stopped"
scan_interval = 60 
scan_target = "127.0.0.1"
scan_once_status = "Idle"

database_status = "Idle"


# Database 
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  src_ip TEXT, 
                  dst_ip TEXT,
                  src_port TEXT,
                  dst_port TEXT,    
                  source TEXT, 
                  country TEXT,
                  attack_type TEXT,
                  comment TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS port_scans 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  target_ip TEXT, 
                  port INTEGER,
                  service TEXT,
                  status TEXT)''')
    conn.commit()
    conn.close()

#alert logging
def log_alert(src_ip, dst_ip, src_port, dst_port, source, country, attack_type, comment):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO alerts (timestamp, src_ip, dst_ip, src_port, dst_port, source, country, attack_type, comment) VALUES (datetime('now', 'localtime'), ?, ?, ?, ?, ?, ?, ?, ?)",
                  (src_ip, dst_ip, src_port, dst_port, source, country, attack_type, comment))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Error: {e}")

#port scan logging
def log_scan_result(target, port, service, status):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO port_scans (timestamp, target_ip, port, service, status) VALUES (datetime('now', 'localtime'), ?, ?, ?, ?)",
                  (target, port, service, status))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Error: {e}")

# config
def get_config_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, 'Conf.conf')

#  Background Processes 
# Remember threading.Event is a flag .set -> true , .clear -> false  
def run_ids_process():
    global ids_status, ids_error
    ids_status = "Running"
    ids_error = "" 
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = get_config_path()
    config = configparser.ConfigParser()
    
    if not os.path.exists(config_path):
        ids_status = "Error: Config Missing"
        return

    config.read(config_path)
    try:
        nic = config['settings']['NIC']
        mode = int(config['settings']['mode']) 
    except KeyError:
        ids_status = "Error: Config Invalid"
        return

    bloom_path = os.path.join(current_dir, 'malicious.bloom')
    if mode in [1, 2] and not os.path.exists(bloom_path): #if offline or hybrid
        ids_error = "No local Database found."
        ids_status = "Stopped"
        return
    
    print(f"Starting IDS on {nic} with Mode {mode}...") # debugging
    try:
        IDS._read_pcap(nic, mode, alert_callback=log_alert, stop_event=stop_event)
    except Exception as e:
        ids_error = f"IDS Error: {str(e)}"
    ids_status = "Stopped"

def execute_port_scan(target, stop_signal=None):
    # Full open tcp scan
    print(f"Performing full scan (1-65535) on {target}...")
    if stop_signal is None:
        stop_signal = threading.Event()

    open_ports_found = 0
    
    for port in range(1, 65536): 
        if stop_signal.is_set(): break
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP
        sock.settimeout(0.1) # Fast timeout (0.1s) to speed up , timeout needed so OS doesn't pick period
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                # Dynamic Service Lookup
                try:
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = "Unknown"

                log_scan_result(target, port, service, "OPEN")
                open_ports_found += 1
        except:
            pass
        finally:
            sock.close()
    
    print(f"Scan complete. Found {open_ports_found} open ports.")

def run_port_scan_process():
    global scan_status, scan_target, scan_interval
    scan_status = "Running"
    print(f"Starting Periodic Port Scan on {scan_target} every {scan_interval} seconds")
    while not scan_stop_event.is_set():
        execute_port_scan(scan_target, scan_stop_event)
        for _ in range(int(scan_interval)): # wait scan interval then scan again
            if scan_stop_event.is_set(): break
            time.sleep(1)     
    scan_status = "Stopped"

def run_single_scan_process(target):
    global scan_once_status
    scan_once_status = "Scanning..."
    execute_port_scan(target)
    scan_once_status = "Finished"
    time.sleep(3) 
    scan_once_status = "Idle"

def run_update_process():
    global database_status
    database_status = "Updating offline Database..."
    try:
        get_IoCs.update_from_IoCs()
        database_status = "Database successfully updated, Ready to start"
    except Exception as e:
        database_status = f"Update Failed: {str(e)}"
    
    

# Routes 
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    global ids_status
    
    display_status = ids_status
    current_dir = os.path.dirname(os.path.abspath(__file__))
    bloom_path = os.path.join(current_dir, 'malicious.bloom')
    
    # Only show missing file error if we are NOT updating right now
    if ids_status == "Stopped" and not os.path.exists(bloom_path) and database_status == "Idle":
        display_status = "Can't scan offline, Please update database"

    return jsonify({
        "ids_status": display_status, 
        "ids_error": ids_error,
        "scan_status": scan_status,
        "scan_once_status": scan_once_status,
        "database_status": database_status
    })

@app.route('/api/start', methods=['POST'])
def start_ids():
    global ids_thread, stop_event, ids_error, database_status
    
    if ids_status == "Running": 
        return jsonify({"message": "Already running"}), 400
        
    # Only block if it is updating
    # If it says "Successfully updated", allow start
    if "Updating" in database_status:
        config_path = get_config_path()
        config = configparser.ConfigParser()
        config.read(config_path)
        try:
            mode = int(config['settings']['mode'])
            if mode in [1, 2]:
                return jsonify({"message": "Cannot start IDS: Database is currently updating."}), 400
        except:
            pass
    
    # Reset DB status to Idle so the UI switches to "Running"
    database_status = "Idle"
    
    ids_error = ""
    stop_event.clear() # set to false
    ids_thread = threading.Thread(target=run_ids_process)
    ids_thread.daemon = True # to close thread when program is closed
    ids_thread.start()
    return jsonify({"message": "IDS Started"})

@app.route('/api/stop', methods=['POST'])
def stop_ids():
    global stop_event
    if ids_status == "Stopped": return jsonify({"message": "Already stopped"}), 400
    stop_event.set() # set flag to true
    return jsonify({"message": "Stopping IDS..."})

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    global scan_thread, scan_stop_event, scan_status, scan_target, scan_interval
    if scan_status == "Running": return jsonify({"message": "Scan already running"}), 400
    data = request.json
    scan_target = data.get('target', '127.0.0.1')
    try:
        minutes = int(data.get('interval', 1))
        scan_interval = minutes * 60
    except:
        scan_interval = 60
        minutes = 1
    scan_stop_event.clear() # set to false
    scan_thread = threading.Thread(target=run_port_scan_process)
    scan_thread.daemon = True
    scan_thread.start()
    return jsonify({"message": f"Auto-Scan Started on {scan_target} (Every {minutes} min)"})

@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    global scan_stop_event
    if scan_status == "Stopped": return jsonify({"message": "Already stopped"}), 400
    scan_stop_event.set()
    return jsonify({"message": "Stopping Port Scan..."})

@app.route('/api/scan/once', methods=['POST'])
def scan_once():
    global scan_once_status
    if scan_once_status == "Scanning...":
        return jsonify({"message": "Scan already in progress"}), 400
    data = request.json
    target = data.get('target', '127.0.0.1')
    t = threading.Thread(target=run_single_scan_process, args=(target,))
    t.daemon = True
    t.start()
    return jsonify({"message": f"One-time scan initiated on {target}"})

@app.route('/api/scan/results')
def get_scan_results():
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM port_scans ORDER BY id DESC LIMIT 50") 
        rows = c.fetchall()
        conn.close()
        return jsonify({"results": [dict(row) for row in rows]})
    except Exception as e:
        return jsonify({"results": []})

@app.route('/api/update_ioc', methods=['POST'])
def update_ioc():
    global database_status
    # Only block if updating
    if "Updating" in database_status:
         return jsonify({"message": "Update already in progress"}), 400
         
    t = threading.Thread(target=run_update_process)
    t.daemon = True
    t.start()
    return jsonify({"message": "Update started"})

@app.route('/api/config', methods=['GET', 'POST'])
def manage_config():
    config_path = get_config_path()
    config = configparser.ConfigParser()
    if request.method == 'POST':
        data = request.json
        config.read(config_path)
        if 'settings' not in config: config['settings'] = {}
        config['settings']['mode'] = str(data.get('mode', 1))
        config['settings']['NIC'] = data.get('nic', 'Wi-Fi')
        with open(config_path, 'w') as f: config.write(f)
        return jsonify({"message": "Configuration saved!"})
    else:
        config.read(config_path)
        try:
            return jsonify({"mode": int(config['settings']['mode']), "nic": config['settings']['NIC']})
        except:
            return jsonify({"mode": 1, "nic": "Wi-Fi"})

@app.route('/api/clear_logs', methods=['POST'])
def clear_logs():
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM alerts") 
        conn.commit()
        conn.close()
        return jsonify({"message": "IDS Logs cleared successfully!"})
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500

@app.route('/api/clear_scan_logs', methods=['POST'])
def clear_scan_logs():
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM port_scans") 
        conn.commit()
        conn.close()
        return jsonify({"message": "Scan Results cleared successfully!"})
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500

@app.route('/api/logs')
def get_logs():
    try:
        page = int(request.args.get('page', 1))
        per_page = 50
        offset = (page - 1) * per_page # how many rows to skip for current page before starting fetching data
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = c.fetchone()[0]
        total_pages = (total_alerts + per_page - 1) // per_page
        c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, offset))
        rows = c.fetchall()
        conn.close()
        return jsonify({"logs": [dict(row) for row in rows], "total_pages": total_pages, "current_page": page})
    except:
        return jsonify({"logs": [], "total_pages": 0, "current_page": 1})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)