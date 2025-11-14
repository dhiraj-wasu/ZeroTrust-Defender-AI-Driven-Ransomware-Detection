import json
import os
from typing import Dict, Any, List
from datetime import datetime

class PolicyManager:
    """Zero Trust policy management"""
    
    def __init__(self):
        self.policies_file = "zero_trust/policies.json"
        self.policies = {}
        self.load_policies()

    def load_policies(self):
        """Load policies from file"""
        try:
            if os.path.exists(self.policies_file):
                with open(self.policies_file, 'r') as f:
                    self.policies = json.load(f)
            else:
                self.create_default_policies()
        except Exception as e:
            print(f"Error loading policies: {e}")
            self.create_default_policies()

    def create_default_policies(self):
        """Create default zero-trust policies"""
        self.policies = {
            "emergency": {
                "name": "Emergency Lockdown",
                "description": "Complete system lockdown for active threats",
                "rules": {
                    "block_all_new_processes": True,
                    "block_network_connections": True,
                    "block_file_modifications": True,
                    "allow_whitelisted_only": True,
                    "enable_process_monitoring": True,
                    "enable_file_integrity_monitoring": True,
                    "enable_network_monitoring": True
                },
                "created": datetime.now().isoformat()
            },
            "enterprise": {
                "name": "Enterprise Protection",
                "description": "Balanced security for enterprise environments",
                "rules": {
                    "block_all_new_processes": False,
                    "block_network_connections": False,
                    "block_file_modifications": False,
                    "allow_whitelisted_only": False,
                    "enable_process_monitoring": True,
                    "enable_file_integrity_monitoring": True,
                    "enable_network_monitoring": True,
                    "log_suspicious_activity": True,
                    "alert_on_high_risk": True
                },
                "created": datetime.now().isoformat()
            },
            "enhanced_monitoring": {
                "name": "Enhanced Monitoring",
                "description": "Increased monitoring without enforcement",
                "rules": {
                    "enable_process_monitoring": True,
                    "enable_file_integrity_monitoring": True,
                    "enable_network_monitoring": True,
                    "log_all_activity": True,
                    "alert_on_suspicious_behavior": True
                },
                "created": datetime.now().isoformat()
            }
        }
        self.save_policies()

    def save_policies(self):
        """Save policies to file"""
        try:
            os.makedirs(os.path.dirname(self.policies_file), exist_ok=True)
            with open(self.policies_file, 'w') as f:
                json.dump(self.policies, f, indent=2)
        except Exception as e:
            print(f"Error saving policies: {e}")

    def get_policy(self, policy_name: str) -> Dict[str, Any]:
        """Get specific policy"""
        return self.policies.get(policy_name, {})

    def update_policy(self, policy_name: str, policy_data: Dict[str, Any]) -> bool:
        """Update policy"""
        try:
            self.policies[policy_name] = policy_data
            self.policies[policy_name]["modified"] = datetime.now().isoformat()
            self.save_policies()
            return True
        except Exception as e:
            print(f"Error updating policy: {e}")
            return False

    def create_custom_policy(self, policy_name: str, policy_data: Dict[str, Any]) -> bool:
        """Create custom policy"""
        if policy_name in self.policies:
            return False  # Policy already exists
        
        policy_data["created"] = datetime.now().isoformat()
        self.policies[policy_name] = policy_data
        self.save_policies()
        return True

    def list_policies(self) -> List[str]:
        """List all available policies"""
        return list(self.policies.keys())

    def validate_policy(self, policy_data: Dict[str, Any]) -> bool:
        """Validate policy structure"""
        required_fields = ["name", "description", "rules"]
        return all(field in policy_data for field in required_fields)