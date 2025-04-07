from flask import Flask, render_template
import sqlite3
from datetime import datetime

app = Flask(__name__)

DB_PATH = "/var/lib/autoshield/database.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    
    attempts = conn.execute("SELECT ip, timestamp, details FROM attempts ORDER BY timestamp DESC LIMIT 20").fetchall()
    blocks = conn.execute("SELECT ip, block_timestamp, expiry_timestamp, block_count FROM blocks ORDER BY block_timestamp DESC LIMIT 20").fetchall()
    
    conn.close()
    return render_template('index.html', attempts=attempts, blocks=blocks, now=datetime.now())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
