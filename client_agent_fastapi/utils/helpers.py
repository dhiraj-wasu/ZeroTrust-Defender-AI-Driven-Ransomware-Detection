import os
import hashlib
import json
import psutil
import socket
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import subprocess
import platform

class SystemHelpers:
    """System-level helper functions"""
    
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get comprehensive system information"""
        try:
            # Network information
            hostname = socket.gethostname()
            try:
                local_ip = socket.gethostbyname(hostname)
            except:
                local_ip = "127.0.0.1"
            
            # System information
            system_info = {
                "hostname": hostname,
                "local_ip": local_ip,
                "os_type": platform.system(),
                "os_version": platform.version(),
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "cpu_count": psutil.cpu_count(),
                "total_memory": psutil.virtual_memory().total,
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
            
            return system_info
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = "md5") -> Optional[str]:
        """Calculate file hash"""
        try:
            hash_func = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception:
            return None

    @staticmethod
    def get_file_entropy(file_path: str) -> float:
        """Calculate file entropy (measure of randomness)"""
        try:
            if not os.path.exists(file_path) or os.path.isdir(file_path):
                return 0.0
            
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return 0.0
            
            # Read sample for entropy calculation
            sample_size = min(file_size, 1024 * 1024)  # 1MB max
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
            
            if not data:
                return 0.0
            
            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    probability = count / len(data)
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception:
            return 0.0

    @staticmethod
    def is_suspicious_process(process_name: str) -> bool:
        """Check if process name is suspicious"""
        suspicious_patterns = [
            'crypto', 'encrypt', 'ransom', 'locker', 'wannacry',
            'petya', 'cerber', 'locky', 'cryptolocker', 'encrypted'
        ]
        process_lower = process_name.lower()
        return any(pattern in process_lower for pattern in suspicious_patterns)

    @staticmethod
    def get_network_connections() -> List[Dict[str, Any]]:
        """Get current network connections"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    connection_info = {
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "status": conn.status,
                        "pid": conn.pid
                    }
                    connections.append(connection_info)
        except Exception as e:
            print(f"Error getting network connections: {e}")
        
        return connections

class FileHelpers:
    """File system helper functions"""
    
    @staticmethod
    def safe_file_operation(func):
        """Decorator for safe file operations"""
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except PermissionError:
                print(f"Permission denied for file operation: {args}")
                return None
            except FileNotFoundError:
                print(f"File not found: {args}")
                return None
            except Exception as e:
                print(f"File operation error: {e}")
                return None
        return wrapper

    @staticmethod
    @safe_file_operation
    def make_file_readonly(file_path: str) -> bool:
        """Make file read-only"""
        if os.name == 'nt':  # Windows
            import stat
            os.chmod(file_path, stat.S_IREAD)
        else:  # Linux/Mac
            os.chmod(file_path, 0o444)
        return True

    @staticmethod
    @safe_file_operation
    def make_file_writable(file_path: str) -> bool:
        """Make file writable"""
        if os.name == 'nt':  # Windows
            import stat
            os.chmod(file_path, stat.S_IWRITE)
        else:  # Linux/Mac
            os.chmod(file_path, 0o666)
        return True

    @staticmethod
    def get_file_info(file_path: str) -> Dict[str, Any]:
        """Get comprehensive file information"""
        try:
            stat_info = os.stat(file_path)
            return {
                "path": file_path,
                "size": stat_info.st_size,
                "created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                "extension": os.path.splitext(file_path)[1].lower(),
                "entropy": SystemHelpers.get_file_entropy(file_path)
            }
        except Exception as e:
            return {"path": file_path, "error": str(e)}

class NetworkHelpers:
    """Network helper functions"""
    
    @staticmethod
    def block_ip_windows(ip_address: str) -> bool:
        """Block IP address using Windows Firewall"""
        try:
            # Create firewall rule to block IP
            rule_name = f"BlockRansomware_{ip_address}"
            
            # Block outbound
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_OUT',
                'dir=out',
                'action=block',
                f'remoteip={ip_address}',
                'enable=yes'
            ], capture_output=True, check=True)
            
            # Block inbound
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_IN',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}',
                'enable=yes'
            ], capture_output=True, check=True)
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip_address}: {e}")
            return False

    @staticmethod
    def unblock_ip_windows(ip_address: str) -> bool:
        """Unblock IP address from Windows Firewall"""
        try:
            rule_name = f"BlockRansomware_{ip_address}"
            
            # Remove outbound rule
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}_OUT'
            ], capture_output=True)
            
            # Remove inbound rule
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}_IN'
            ], capture_output=True)
            
            return True
        except Exception as e:
            print(f"Failed to unblock IP {ip_address}: {e}")
            return False

class ProcessHelpers:
    """Process management helper functions"""
    
    @staticmethod
    def terminate_process_by_name(process_name: str) -> bool:
        """Terminate process by name"""
        try:
            terminated = False
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
                    try:
                        proc.terminate()
                        terminated = True
                        print(f"Terminated process: {proc.info['name']} (PID: {proc.info['pid']})")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            return terminated
        except Exception as e:
            print(f"Error terminating process {process_name}: {e}")
            return False

    @staticmethod
    def get_process_tree(pid: int) -> List[Dict[str, Any]]:
        """Get process tree for a given PID"""
        try:
            process_tree = []
            parent = psutil.Process(pid)
            
            # Add parent
            process_tree.append({
                "pid": parent.pid,
                "name": parent.name(),
                "cpu_percent": parent.cpu_percent(),
                "memory_percent": parent.memory_percent()
            })
            
            # Add children
            for child in parent.children(recursive=True):
                process_tree.append({
                    "pid": child.pid,
                    "name": child.name(),
                    "cpu_percent": child.cpu_percent(),
                    "memory_percent": child.memory_percent()
                })
            
            return process_tree
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

class AlertHelpers:
    """Alert and notification helper functions"""
    
    @staticmethod
    def format_threat_alert(threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format threat alert for central system"""
        return {
            "type": "THREAT_ALERT",
            "payload": {
                "agent_id": threat_data.get("agent_id", "UNKNOWN"),
                "incident_id": threat_data.get("incident_id", f"INC-{datetime.now().strftime('%Y%m%d_%H%M%S')}"),
                "status": "infected",
                "threat_level": threat_data.get("threat_level", "critical"),
                "malware_process": threat_data.get("malware_process", "unknown"),
                "detection_confidence": threat_data.get("confidence", 0.0),
                "actions_taken": threat_data.get("actions_taken", []),
                "forensic_data": threat_data.get("forensic_data", {}),
                "timestamp": datetime.now().isoformat()
            }
        }

    @staticmethod
    def create_demo_alert() -> Dict[str, Any]:
        """Create a demo threat alert for testing"""
        return {
            "type": "THREAT_ALERT",
            "payload": {
                "agent_id": f"PC-{os.environ.get('COMPUTERNAME', 'TEST')}",
                "incident_id": f"DEMO-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "status": "infected",
                "threat_level": "critical",
                "malware_process": "crypto_locker.exe",
                "detection_confidence": 0.95,
                "actions_taken": ["process_killed", "backup_created", "files_locked", "network_isolated"],
                "forensic_data": {
                    "process_tree": ["explorer.exe", "crypto_locker.exe", "cmd.exe"],
                    "file_access_patterns": {
                        "files_modified": 47,
                        "extensions_changed": [".docx", ".pdf", ".xlsx"],
                        "encryption_detected": True,
                        "ransom_note_found": True,
                        "ransom_extension": ".encrypted"
                    },
                    "network_connections": [
                        {
                            "remote_host": "192.168.1.100",
                            "port": 445,
                            "protocol": "SMB",
                            "direction": "outbound"
                        }
                    ],
                    "system_metrics": {
                        "cpu_usage": 95.2,
                        "memory_usage": 87.5,
                        "disk_activity": "high"
                    }
                },
                "timestamp": datetime.now().isoformat()
            }
        }

# Import math for entropy calculation
import math  