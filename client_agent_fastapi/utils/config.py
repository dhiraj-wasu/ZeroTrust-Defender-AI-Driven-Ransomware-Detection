import os
import json
from typing import Dict, Any, List
from pydantic_settings import BaseSettings
from datetime import timedelta

class AgentConfig(BaseSettings):
    """Configuration management for the client agent"""
    
    # Agent Identification
    agent_id: str = f"PC-{os.environ.get('PC-1', 'Windows')}"
    agent_version: str = "2.0.0"
    
    # Central System Configuration
    central_system_url: str = "ws://localhost:8080"
    central_rest_url: str = "http://localhost:8080"
    reconnect_interval: int = 5  # seconds
    
    # Detection Thresholds
    thresholds: Dict[str, float] = {
        "critical": 0.85,
        "high": 0.70,
        "suspicious": 0.55,
        "low": 0.30
    }
    
    # Monitoring Intervals
    monitoring_intervals: Dict[str, int] = {
        "file_check": 2,
        "process_check": 3,
        "network_check": 5,
        "system_health": 10
    }
    
    # Prevention Settings
    prevention_actions: Dict[str, bool] = {
        "emergency_backup": True,
        "file_locking": True,
        "network_isolation": True,
        "process_termination": True,
        "zero_trust_enforcement": True
    }
    
    # Backup Settings
    backup_settings: Dict[str, Any] = {
        "max_backups": 10,
        "backup_interval": timedelta(hours=1),
        "emergency_backup_size_limit": 1024 * 1024 * 500,  # 500MB
        "compression_level": 6
    }
    
    # File Monitoring
    file_monitoring: Dict[str, Any] = {
        "monitor_subdirectories": True,
        "max_file_size": 1024 * 1024 * 100,  # 100MB
        "suspicious_extensions": [
            '.encrypted', '.locked', '.crypto', '.ransom', '.wncry',
            '.cryptolocker', '.cryptowall', '.cerber', '.zeppelin'
        ],
        "important_extensions": [
            '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.png', '.txt', '.csv', '.sql', '.db'
        ]
    }
    
    # Process Monitoring
    process_monitoring: Dict[str, Any] = {
        "suspicious_names": [
            'crypto', 'encrypt', 'ransom', 'locker', 'wannacry',
            'petya', 'cerber', 'locky', 'cryptolocker'
        ],
        "system_processes": [
            'svchost.exe', 'services.exe', 'lsass.exe', 'winlogon.exe',
            'csrss.exe', 'smss.exe', 'system'
        ],
        "high_resource_threshold": 80.0  # percentage
    }
    
    # Network Monitoring
    network_monitoring: Dict[str, Any] = {
        "suspicious_ports": [445, 3389, 135, 139, 22, 23],
        "monitor_localhost": False,
        "max_connections_per_minute": 100
    }
    
    # Zero Trust Settings
    zero_trust: Dict[str, Any] = {
        "enforcement_level": "high",
        "require_approval_for_new_processes": True,
        "block_unknown_network_destinations": True,
        "file_integrity_monitoring": True
    }
    
    # Logging Configuration
    logging: Dict[str, Any] = {
        "level": "INFO",
        "max_file_size": 1024 * 1024 * 10,  # 10MB
        "backup_count": 5,
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    }
    
    # Demo Settings
    demo_settings: Dict[str, Any] = {
        "simulation_delay": 30,  # seconds
        "auto_simulate_threats": True,
        "demo_mode": True
    }

    class Config:
        env_file = ".env"
        case_sensitive = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "central_system_url": self.central_system_url,
            "thresholds": self.thresholds,
            "monitoring_intervals": self.monitoring_intervals,
            "prevention_actions": self.prevention_actions,
            "backup_settings": self.backup_settings,
            "file_monitoring": self.file_monitoring,
            "process_monitoring": self.process_monitoring,
            "network_monitoring": self.network_monitoring,
            "zero_trust": self.zero_trust,
            "logging": self.logging,
            "demo_settings": self.demo_settings
        }

    def save_to_file(self, file_path: str = "agent_config.json"):
        """Save configuration to file"""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    @classmethod
    def load_from_file(cls, file_path: str = "agent_config.json"):
        """Load configuration from file"""
        try:
            with open(file_path, 'r') as f:
                config_data = json.load(f)
            return cls(**config_data)
        except Exception as e:
            print(f"Error loading config: {e}")
            return cls()

# Global config instance
config = AgentConfig()