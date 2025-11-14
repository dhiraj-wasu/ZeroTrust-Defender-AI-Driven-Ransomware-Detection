import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from utils.config import config

class AlertManager:
    """Threat alert management and formatting"""
    
    def __init__(self):
        self.alert_history: List[Dict[str, Any]] = []
        self.max_history_size = 100
        
    def create_threat_alert(self, agent_id: str, threat_type: str, threat_score: float,
                          evidence: Dict[str, Any], actions_taken: List[str],
                          threat_level: str = None) -> Dict[str, Any]:
        """Create a formatted threat alert for central system"""
        
        # Determine threat level if not provided
        if not threat_level:
            threat_level = self._calculate_threat_level(threat_score)
        
        # Generate incident ID
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create forensic data
        forensic_data = self._create_forensic_data(evidence, threat_type)
        
        alert = {
            "type": "THREAT_ALERT",
            "payload": {
                "agent_id": agent_id,
                "incident_id": incident_id,
                "status": "infected",
                "threat_level": threat_level,
                "malware_process": evidence.get('malware_process', 'unknown'),
                "detection_confidence": threat_score,
                "actions_taken": actions_taken,
                "forensic_data": forensic_data,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        # Store in history
        self._store_alert(alert)
        
        return alert

    def create_demo_alert(self, agent_id: str) -> Dict[str, Any]:
        """Create a demo threat alert for testing"""
        return {
            "type": "THREAT_ALERT",
            "payload": {
                "agent_id": agent_id,
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

    def create_system_alert(self, agent_id: str, alert_type: str, 
                          message: str, severity: str = "info") -> Dict[str, Any]:
        """Create a system status alert"""
        alert = {
            "type": "SYSTEM_ALERT",
            "payload": {
                "agent_id": agent_id,
                "alert_type": alert_type,
                "message": message,
                "severity": severity,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        self._store_alert(alert)
        return alert

    def _calculate_threat_level(self, threat_score: float) -> str:
        """Calculate threat level based on score"""
        if threat_score >= config.thresholds["critical"]:
            return "critical"
        elif threat_score >= config.thresholds["high"]:
            return "high"
        elif threat_score >= config.thresholds["suspicious"]:
            return "suspicious"
        else:
            return "low"

    def _create_forensic_data(self, evidence: Dict[str, Any], threat_type: str) -> Dict[str, Any]:
        """Create forensic data from evidence"""
        forensic_data = {
            "threat_type": threat_type,
            "process_tree": evidence.get('process_tree', []),
            "file_access_patterns": {
                "files_modified": evidence.get('files_modified', 0),
                "extensions_changed": evidence.get('extensions_changed', []),
                "encryption_detected": evidence.get('encryption_detected', False),
                "ransom_note_found": evidence.get('ransom_note_found', False),
                "ransom_extension": evidence.get('ransom_extension', '')
            },
            "network_connections": evidence.get('network_connections', []),
            "system_metrics": evidence.get('system_metrics', {})
        }
        
        return forensic_data

    def _store_alert(self, alert: Dict[str, Any]):
        """Store alert in history"""
        self.alert_history.append(alert)
        
        # Keep history size manageable
        if len(self.alert_history) > self.max_history_size:
            self.alert_history = self.alert_history[-self.max_history_size:]

    def get_recent_alerts(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return self.alert_history[-count:] if self.alert_history else []

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        if not self.alert_history:
            return {"total_alerts": 0}
        
        threat_levels = {}
        alert_types = {}
        
        for alert in self.alert_history:
            alert_type = alert.get("type", "unknown")
            threat_level = alert.get("payload", {}).get("threat_level", "unknown")
            
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
            threat_levels[threat_level] = threat_levels.get(threat_level, 0) + 1
        
        return {
            "total_alerts": len(self.alert_history),
            "alert_types": alert_types,
            "threat_levels": threat_levels,
            "last_alert": self.alert_history[-1]["payload"]["timestamp"] if self.alert_history else None
        }

    def format_central_command_ack(self, agent_id: str, command_id: str, 
                                 status: str, message: str) -> Dict[str, Any]:
        """Format command acknowledgment for central system"""
        return {
            "type": "COMMAND_ACK",
            "payload": {
                "agent_id": agent_id,
                "command_id": command_id,
                "status": status,
                "message": message,
                "timestamp": datetime.now().isoformat()
            }
        }

    def format_heartbeat(self, agent_id: str, status: Dict[str, Any]) -> Dict[str, Any]:
        """Format heartbeat message for central system"""
        return {
            "type": "HEARTBEAT",
            "payload": {
                "agent_id": agent_id,
                "status": status,
                "timestamp": datetime.now().isoformat()
            }
        }