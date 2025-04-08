from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
from datetime import datetime, timedelta
import sys
import os
import yaml
import json
import re

# Add parent directory to path so we can import the src modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.firewall import Firewall
from src.logger import Logger

app = Flask(__name__)
app.secret_key = 'autoshield_secret_key'  # Used for flash messages

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

def format_datetime(dt_value):
    """Format datetime values for display"""
    if isinstance(dt_value, str):
        # Handle ISO format strings
        try:
            # Remove microseconds and timezone
            parts = dt_value.split('.')
            if len(parts) > 1:
                dt_clean = parts[0].replace('T', ' ')
                return dt_clean
            return dt_value.replace('T', ' ')
        except:
            return dt_value
    elif isinstance(dt_value, datetime):
        return dt_value.strftime('%Y-%m-%d %H:%M:%S')
    return str(dt_value)

def parse_details(details_str):
    """Extract useful information from the details string"""
    if not details_str:
        return "No details available"
    
    try:
        if "MESSAGE" in details_str:
            message_match = re.search(r"'MESSAGE':\s*'([^']*)'", details_str)
            if message_match:
                message = message_match.group(1)
                if "Failed password for" in message:
                    user_match = re.search(r"Failed password for ([^ ]+) from", message)
                    if user_match:
                        username = user_match.group(1)
                        return f"Failed login attempt - User: {username}"
                return message
        
        return "Failed login attempt"
    except:
        return "Failed login attempt"

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
        
        # Format the data
        formatted_attempts = []
        for attempt in attempts:
            formatted_attempt = dict(attempt)
            formatted_attempt['formatted_timestamp'] = format_datetime(attempt['timestamp'])
            formatted_attempt['parsed_details'] = parse_details(attempt['details'])
            formatted_attempts.append(formatted_attempt)
        
        formatted_blocks = []
        for block in blocks:
            formatted_block = dict(block)
            formatted_block['formatted_block_timestamp'] = format_datetime(block['block_timestamp'])
            formatted_block['formatted_expiry_timestamp'] = format_datetime(block['expiry_timestamp'])
            formatted_blocks.append(formatted_block)
        
        # Get current firewall status
        try:
            firewall_blocks = firewall.get_blocked_ips()
        except Exception as e:
            firewall_blocks = []
            flash(f"Unable to retrieve current firewall status: {str(e)}", "warning")
        
        conn.close()
        return render_template('index.html', 
                              attempts=formatted_attempts, 
                              blocks=formatted_blocks, 
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
    
    # Validate IP format
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if not ip_pattern.match(ip):
        flash('Invalid IP address format', 'danger')
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

# API routes for the modal
@app.route('/api/attempts/<ip>', methods=['GET'])
def get_ip_attempts(ip):
    try:
        conn = get_db_connection()
        
        # Get all attempts for this IP (limit to last 30 days)
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
        attempts = conn.execute("""
            SELECT ip, timestamp, details 
            FROM attempts 
            WHERE ip = ? AND timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 50
        """, (ip, thirty_days_ago)).fetchall()
        
        # Format the data
        formatted_attempts = []
        for attempt in attempts:
            formatted_attempt = {
                'ip': attempt['ip'],
                'timestamp': attempt['timestamp'],
                'details': attempt['details'],
                'formatted_timestamp': format_datetime(attempt['timestamp']),
                'parsed_details': parse_details(attempt['details'])
            }
            formatted_attempts.append(formatted_attempt)
        
        conn.close()
        return jsonify({'success': True, 'attempts': formatted_attempts})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/blocks/<ip>', methods=['GET'])
def get_block_history(ip):
    try:
        conn = get_db_connection()
        
        # Get block history for this IP
        blocks = conn.execute("""
            SELECT ip, block_timestamp, expiry_timestamp, block_count
            FROM blocks
            WHERE ip = ?
            ORDER BY block_timestamp DESC
            LIMIT 20
        """, (ip,)).fetchall()
        
        # Format the data
        formatted_blocks = []
        for block in blocks:
            formatted_block = {
                'ip': block['ip'],
                'block_timestamp': block['block_timestamp'],
                'expiry_timestamp': block['expiry_timestamp'],
                'block_count': block['block_count'],
                'formatted_block_timestamp': format_datetime(block['block_timestamp']),
                'formatted_expiry_timestamp': format_datetime(block['expiry_timestamp'])
            }
            formatted_blocks.append(formatted_block)
        
        conn.close()
        return jsonify({'success': True, 'blocks': formatted_blocks})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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