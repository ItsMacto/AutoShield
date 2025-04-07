from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from datetime import datetime, timedelta
import sys
import os
import yaml


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.firewall import Firewall
from src.logger import Logger

app = Flask(__name__)
app.secret_key = 'autoshield_secret_key'

# Load config
CONFIG_PATH = os.environ.get('AUTOSHIELD_CONFIG', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'config.yaml'))
try:
    with open(CONFIG_PATH, 'r') as f:
        config = yaml.safe_load(f)
except Exception as e:
    print(f"Error loading configuration: {e}")
    sys.exit(1)

# Initialize logger and firewall
try:
    logger = Logger(config)
    firewall = Firewall(config, logger)
except Exception as e:
    print(f"Error initializing services: {e}")
    sys.exit(1)

DB_PATH = config['database']['path']

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    try:
        conn = get_db_connection()
        
        attempts = conn.execute("""
            SELECT ip, timestamp, details 
            FROM attempts 
            ORDER BY timestamp DESC 
            LIMIT 20
        """).fetchall()
        
        blocks = conn.execute("""
            SELECT b.ip, b.block_timestamp, b.expiry_timestamp, b.block_count 
            FROM blocks b
            INNER JOIN (
                SELECT ip, MAX(id) as max_id
                FROM blocks
                GROUP BY ip
            ) m ON b.ip = m.ip AND b.id = m.max_id
            WHERE b.expiry_timestamp > datetime('now')
            ORDER BY b.block_timestamp DESC
        """).fetchall()
        
        # Get current firewall status
        try:
            firewall_blocks = firewall.get_blocked_ips()
        except Exception as e:
            firewall_blocks = []
            flash(f"Unable to retrieve current firewall status: {str(e)}", "warning")
        
        conn.close()
        return render_template('index.html', 
                              attempts=attempts, 
                              blocks=blocks, 
                              firewall_blocks=firewall_blocks,
                              now=datetime.now())
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/block', methods=['POST'])
def add_block():
    ip = request.form.get('ip')
    try:
        duration = int(request.form.get('duration', 60))
    except ValueError:
        duration = 60  # Default if conversion fails
    
    if not ip:
        flash('IP address is required', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Block the IP
        success = firewall.block_ip(ip)
        
        if success:
            # Add to database
            block_start = datetime.now()
            block_end = block_start + timedelta(minutes=duration)
            logger.log_block(ip, block_start, block_end)
            flash(f'Successfully blocked IP {ip} for {duration} minutes', 'success')
        else:
            flash(f'Failed to block IP {ip}. It may be whitelisted or already blocked.', 'warning')
    except Exception as e:
        flash(f'Error blocking IP: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/unblock/<ip>', methods=['POST'])
def remove_block(ip):
    try:
        # Unblock the IP
        success = firewall.unblock_ip(ip)
        
        if success:
            logger.log_unblock(ip)
            flash(f'Successfully unblocked IP {ip}', 'success')
        else:
            flash(f'Failed to unblock IP {ip}. It may not be blocked.', 'warning')
    except Exception as e:
        flash(f'Error unblocking IP: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error="Internal server error"), 500

if __name__ == '__main__':
    # Check if running as root
    if os.geteuid() != 0:
        print("Warning: This application requires root privileges to modify firewall rules.")
        print("Consider running with sudo.")
    
    app.run(host='0.0.0.0', port=5000)