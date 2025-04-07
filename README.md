# AutoShield

AutoShield is a Linux-based security tool that monitors system logs for failed login attempts 
and automatically blocks offending IP addresses using nftables. It logs events to a file and 
an SQLite database, and provides reporting capabilities to help you track and analyze security incidents.

## Features

- **Real-Time Log Monitoring:** Watches systemd journals for failed login attempts.
- **Automated IP Blocking:** Blocks IPs via nftables when they exceed a configurable threshold.
- **Dynamic Firewall Rules:** Adjusts block durations with configurable multipliers.
- **Detailed Logging:** Logs events to both a file and a SQLite database.
- **Reporting:** Provides tools to query and visualize attempted logins and blocked IPs.
- **Daemon Mode:** Runs as a systemd service, starting automatically on boot.

## Prerequisites

- **Linux Distribution** with systemd and nftables.
- **Python 3.6+** installed.
- **Root Privileges:** Required for modifying firewall rules.
- **nftables:** Ensure nftables is installed.
- The following Python packages (installed in your virtual environment):
  - `pyyaml`
  - `systemd-python`

## Installation & Setup

### 1. Clone the Repository

Clone the repository to your local machine and navigate to the project directory:

git clone https://github.com/yourusername/autoshield.git
cd autoshield

### 2. Setup Python Virtual Environment

python3 -m venv venv
source venv/bin/activate

### 3. Install Required Python Packages

pip install pyyaml systemd-python

### 4. Configure AutoShield

Edit the following file with your desired rules:
- cd config/config.yaml

### 5. Running AutoShield Manually

To run AutoShield manually on each boot:
- python3 -m src.main

### 6. Running AutoShield as a Daemon

To run AutoShield in the background as a daemon:

1. Navigate to the service file:
- sudo nano /etc/systemd/system/autoshield.service

2. Paste the following into the .service file, replacing the paths inside <>:
```ini
[Unit]
Description=AutoShield Daemon
After=network.target

[Service]
Type=simple
ExecStart=<your AutoShield directory>/venv/bin/python -m src.main
Restart=on-failure
User=root
WorkingDirectory=<your AutoShield directory>

[Install]
WantedBy=multi-user.target
```

3. Reload systemd and enable the service
- sudo systemctl daemon-reload
- sudo systemctl enable autoshield
- sudo systemctl start autoshield
- sudo systemctl status autoshield (this will tell you if the daemon is running or not)

### 7. View Logs

1. View AutoShield.log:
- tail -f /var/log/autoshield.log

2. View Systemd Journal:
- sudo journalctl -u autoshield -f

3. View Database Tables:
- sqlite3 /var/lib/autoshield/database.db
- SELECT * FROM attempts;
- SELECT * FROM blocks;