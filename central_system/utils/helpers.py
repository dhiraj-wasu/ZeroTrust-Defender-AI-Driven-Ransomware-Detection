import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List
import hashlib

def generate_incident_id() -> str:
    """Generate unique incident ID"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:8]
    return f"INC_{timestamp}_{unique_id}"

def generate_agent_id(hostname: str, ip_address: str) -> str:
    """Generate unique agent ID"""
    unique_string = f"{hostname}_{ip_address}_{datetime.now().timestamp()}"
    return f"AGENT_{hashlib.md5(unique_string.encode()).hexdigest()[:12]}"

def validate_threat_alert(alert_data: Dict[str, Any]) -> bool:
    """Validate threat alert structure"""
    required_fields = ['agent_id', 'status', 'threat_level', 'timestamp']
    
    for field in required_fields:
        if field not in alert_data:
            return False
    
    # Validate threat level
    valid_threat_levels = ['critical', 'high', 'medium', 'low', 'info']
    if alert_data['threat_level'] not in valid_threat_levels:
        return False
    
    return True

def calculate_risk_score(threat_level: str, confidence: float, network_exposure: int) -> float:
    """Calculate comprehensive risk score"""
    threat_weights = {
        'critical': 10.0,
        'high': 8.0,
        'medium': 5.0,
        'low': 3.0,
        'info': 1.0
    }
    
    base_score = threat_weights.get(threat_level, 5.0)
    exposure_multiplier = 1.0 + (network_exposure * 0.1)
    
    return min(10.0, base_score * confidence * exposure_multiplier)

def format_timestamp(timestamp: str = None) -> str:
    """Format timestamp for consistency"""
    if timestamp is None:
        return datetime.now().isoformat()
    return timestamp

def deep_merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    
    for key, value in dict2.items():
        if (key in result and isinstance(result[key], dict) 
            and isinstance(value, dict)):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result