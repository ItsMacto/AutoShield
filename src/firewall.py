import subprocess
import logging
from typing import Dict, List, Set, Any, Optional, Union, Callable

class Firewall:
    def __init__(self, config: Dict[str, Any], logger: Any):
        """
        Initialize the firewall using nftables
        
        Args:
            config: Config dict from config.yaml
            logger: logger instance
        """
        self.config = config
        self.logger = logger
        self.whitelist = set(config['firewall']['whitelist'])
        

        self._initialize_nftables()
    
    def _initialize_nftables(self) -> None:
        """
        Initialize nftables with table and chain if they don't exist
        """
        try:
            # Check for tabless
            check_table = subprocess.run(
                ['nft', 'list', 'table', 'inet', 'autoshield'],
                capture_output=True, text=True
            )
            
            if check_table.returncode != 0:
                # Create table and chain
                subprocess.run([
                    'nft', 'add', 'table', 'inet', 'autoshield'
                ], check=True)
                
                subprocess.run([
                    'nft', 'add', 'chain', 'inet', 'autoshield', 'input',
                    '{ type filter hook input priority 0; policy accept; }'
                ], check=True)
                
                logging.getLogger('autoshield').info("Created nftables table and chain")
        except subprocess.CalledProcessError as e:
            logging.getLogger('autoshield').error(f"Failed to initialize nftables: {e}")
            raise
    
    def block_ip(self, ip: str) -> bool:
        """
        Block an IP 
        
        Args:
            ip: The IP to block
            
        Returns:
            True if IP was blocked
        """
        if ip in self.whitelist:
            logging.getLogger('autoshield').warning(f"Attempted to block whitelisted IP {ip}")
            return False
        
        try:
            # Check if IP already blocked
            check_cmd = subprocess.run(
                ['nft', 'list', 'chain', 'inet', 'autoshield', 'input'],
                capture_output=True, text=True
            )
            
            if f"ip saddr {ip}" in check_cmd.stdout:
                logging.getLogger('autoshield').info(f"IP {ip} is already blocked")
                return False
            
            subprocess.run([
                'nft', 'add', 'rule', 'inet', 'autoshield', 'input',
                'ip', 'saddr', ip, 'counter', 'drop'
            ], check=True)
            
            logging.getLogger('autoshield').info(f"Successfully blocked IP {ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            logging.getLogger('autoshield').error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock an IP address by removing the rule
        
        Args:
            ip: The IP to unblock
            
        Returns:
            True if the IP was unblocked
        """
        try:
            list_cmd = subprocess.run(
                ['nft', '-a', 'list', 'chain', 'inet', 'autoshield', 'input'],
                capture_output=True, text=True
            )
            
            # look for the rule from the output
            for line in list_cmd.stdout.splitlines():
                if f"ip saddr {ip}" in line and "handle" in line:
                    handle = line.split("handle")[-1].strip().split()[0]
                    
                    # delete the rule
                    subprocess.run([
                        'nft', 'delete', 'rule', 'inet', 'autoshield', 'input', 'handle', handle
                    ], check=True)
                    
                    logging.getLogger('autoshield').info(f"Successfully unblocked IP {ip}")
                    return True
            
            logging.getLogger('autoshield').info(f"IP {ip} was not found in blocked list")
            return False
            
        except subprocess.CalledProcessError as e:
            logging.getLogger('autoshield').error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def get_blocked_ips(self) -> List[str]:
        """
        Get a list of currently blocked IPs
        
        Returns:
            List of blocked IP addresses
        """
        try:
            list_cmd = subprocess.run(
                ['nft', 'list', 'chain', 'inet', 'autoshield', 'input'],
                capture_output=True, text=True
            )
            
            blocked_ips = []
            for line in list_cmd.stdout.splitlines():
                if "ip saddr" in line and "drop" in line:
                    ip = line.split("ip saddr")[1].split()[0]
                    blocked_ips.append(ip)
            
            return blocked_ips
            
        except subprocess.CalledProcessError as e:
            logging.getLogger('autoshield').error(f"Failed to get blocked IPs: {e}")
            return []