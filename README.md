# AutoShield 🛡️

AutoShield is a Linux-based security tool that monitors system logs for failed login attempts 
via ssh and automatically blocks offending IP addresses using nftables. It logs events to a log file and 
an SQLite database, and provides reporting capabilities to help you track and analyze security incidents.


## Features

- **Real-Time Log Monitoring:** Watches systemd journals for failed login attempts.
- **Automated IP Blocking:** Blocks IPs via nftables when they exceed a configurable threshold.
- **Dynamic Firewall Rules:** Adjusts block durations with configurable multipliers (repeat offender gets expansionary more time).
- **Detailed Logging:** Logs events to both a file and a SQLite database.
- **Reporting:** Provides web interface to query and visualize attempted logins and blocked IPs.
- **Daemon Mode:** Runs as a systemd service, starting automatically on boot.

## Prerequisites

- **Linux Distribution** with systemd and nftables.
- **Python 3.6+** installed.
- **Root Privileges:** Required for modifying firewall rules.
- **nftables:** Ensure nftables is installed.

## Installation & Setup

### Quick Install
``` bash
# Clone the repository
git clone git@github.com:ItsMacto/AutoShield.git
cd AutoShield

# Make the installer executable
chmod +x install.sh

# Edit config for whitelist, blocking, and directory locations

# Run the installer with sudo
sudo ./install.sh
```
