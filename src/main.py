import os
import sys
import yaml
import signal
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Callable
from datetime import datetime

from logger import Logger
from src.firewall import Firewall
from src.rules import RuleEngine
from monitor import Monitor

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load config from file
    
    Args:
        config_path: A path to the config file
        
    Returns:
        Config dictionary
    """
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        sys.exit(1)

def main() -> None:
    """
    Main Function for AutoShield
    Serves as the start point that calls the other functions and logic
    """

    SCRIPT_DIR = Path(__file__).resolve().parent
    DEFAULT_CONFIG_PATH = SCRIPT_DIR.parent / 'config' / 'config.yaml'
    
    CONFIG_PATH = os.environ.get('AUTOSHIELD_CONFIG', DEFAULT_CONFIG_PATH)
    
    config = load_config(CONFIG_PATH)
    
    logger = Logger(config)
    log = logging.getLogger('autoshield')
    log.info("Starting AutoShield")
    
    firewall = Firewall(config, logger)
    
    rule_engine = RuleEngine(config, logger, firewall)
        
    rule_engine.start()
    
    # callback for monitor
    def event_callback(ip: str, timestamp: datetime, details: str) -> None:
        rule_engine.process_attempt(ip, timestamp, details)
    

    monitor = Monitor(config, event_callback)
    
    try:
        monitor.start()
    except Exception as e:
        log.error(f"Error in main loop: {e}")
    finally:
        rule_engine.stop()
        logger.close()

if __name__ == "__main__":
    main()