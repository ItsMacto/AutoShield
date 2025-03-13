# AutoShield

Idea for set up:

AutoShield/
├── README.md
├── setup.py
├── requirements.txt
├── config/
│   └── default.yaml
├── src/
│   ├── log_monitor/
│   │   ├── parsers/
│   │   │   ├── syslog_parser.py
│   │   │   └── etc. for more logs
│   │   └── monitor.py
│   ├── rules/
│   │   ├── rules.py
│   │   └── engine.py
│   ├── firewall/
│   │   ├── nftables_manager.py
│   │   └── other like iptables if needed 
│   ├── storage/
│   │   ├── __init__.py
│   │   └── db.py
│   └── service.py
├── tests/
└── scripts/
    ├── install_service.sh
    └── AutoShield.service


