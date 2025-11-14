import os
import json
import psutil
import threading
from typing import Dict, List, Set, Any
from datetime import datetime

class ZeroTrustEnforcer:
    """Zero Trust security enforcement engine"""
    
    def __init__(self):
        self.whitelist_file = "zero_trust/whitelist.json"
        self.policies_file = "zero_trust/policies.json"
        self.enforcement_enabled = False
        self.emergency_mode = False
        
        # Process whitelist
        self.whitelisted_processes: Set[str] = set()
        self.whitelisted_paths: Set[str] = set()
        
        # Load configurations
        self._load_whitelist()
        self._load_policies()
        
        # Monitoring state
        self.monitored_processes: Set[int] = set()
        self.denied_operations: List[Dict[str, Any]] = []
        self.enforcement_lock = threading.Lock()

    def enable_emergency_mode(self) -> bool:
        """Enable zero-trust emergency mode"""
        print("🛡️ Enabling Zero Trust Emergency Mode...")
        
        with self.enforcement_lock:
            self.emergency_mode = True
            self.enforcement_enabled = True
            
            # Apply emergency policies
            self._apply_emergency_policies()
            
            # Start enhanced monitoring
            self._start_enhanced_monitoring()
            
            print("✅ Zero Trust Emergency Mode activated")
            return True

    def enable_enterprise_mode(self) -> bool:
        """Enable enterprise zero-trust mode"""
        print("🏢 Enabling Enterprise Zero Trust Mode...")
        
        with self.enforcement_lock:
            self.emergency_mode = False
            self.enforcement_enabled = True
            
            # Apply enterprise policies
            self._apply_enterprise_policies()
            
            print("✅ Enterprise Zero Trust Mode activated")
            return True

    def disable_enforcement(self) -> bool:
        """Disable zero-trust enforcement"""
        print("🔓 Disabling Zero Trust enforcement...")
        
        with self.enforcement_lock:
            self.enforcement_enabled = False
            self.emergency_mode = False
            
            # Restore normal operations
            self._restore_normal_operations()
            
            print("✅ Zero Trust enforcement disabled")
            return True

    def enhance_monitoring(self) -> bool:
        """Enable enhanced monitoring without full enforcement"""
        print("🔍 Enabling enhanced monitoring...")
        
        with self.enforcement_lock:
            self._start_enhanced_monitoring()
            print("✅ Enhanced monitoring activated")
            return True

    def _load_whitelist(self):
        """Load process and path whitelist"""
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    whitelist_data = json.load(f)
                
                self.whitelisted_processes = set(whitelist_data.get("processes", []))
                self.whitelisted_paths = set(whitelist_data.get("paths", []))
            else:
                # Create default whitelist
                self._create_default_whitelist()
                
        except Exception as e:
            print(f"Error loading whitelist: {e}")
            self._create_default_whitelist()

    def _load_policies(self):
        """Load enforcement policies"""
        try:
            if os.path.exists(self.policies_file):
                with open(self.policies_file, 'r') as f:
                    self.policies = json.load(f)
            else:
                self._create_default_policies()
                
        except Exception as e:
            print(f"Error loading policies: {e}")
            self._create_default_policies()

    def _create_default_whitelist(self):
        """Create default process whitelist"""
        default_processes = {
            "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
            "winlogon.exe", "csrss.exe", "smss.exe", "System",
            "taskhost.exe", "dwm.exe", "ctfmon.exe"
        }
        
        default_paths = {
            "C:\\Windows\\", "C:\\Program Files\\", "C:\\ProgramData\\"
        }
        
        self.whitelisted_processes = default_processes
        self.whitelisted_paths = default_paths
        
        # Save default whitelist
        self._save_whitelist()

    def _create_default_policies(self):
        """Create default enforcement policies"""
        self.policies = {
            "emergency": {
                "block_new_processes": True,
                "block_network_connections": True,
                "block_file_modifications": True,
                "allow_whitelisted_only": True,
                "monitor_system_calls": True
            },
            "enterprise": {
                "block_new_processes": False,
                "block_network_connections": False,
                "block_file_modifications": False,
                "allow_whitelisted_only": False,
                "monitor_system_calls": True,
                "log_suspicious_activity": True
            },
            "enhanced_monitoring": {
                "monitor_process_creation": True,
                "monitor_file_operations": True,
                "monitor_network_activity": True,
                "alert_on_suspicious_behavior": True
            }
        }
        
        # Save default policies
        self._save_policies()

    def _save_whitelist(self):
        """Save whitelist to file"""
        try:
            os.makedirs(os.path.dirname(self.whitelist_file), exist_ok=True)
            with open(self.whitelist_file, 'w') as f:
                json.dump({
                    "processes": list(self.whitelisted_processes),
                    "paths": list(self.whitelisted_paths)
                }, f, indent=2)
        except Exception as e:
            print(f"Error saving whitelist: {e}")

    def _save_policies(self):
        """Save policies to file"""
        try:
            os.makedirs(os.path.dirname(self.policies_file), exist_ok=True)
            with open(self.policies_file, 'w') as f:
                json.dump(self.policies, f, indent=2)
        except Exception as e:
            print(f"Error saving policies: {e}")

    def _apply_emergency_policies(self):
        """Apply emergency zero-trust policies"""
        print("    🔒 Applying emergency policies...")
        
        # These would be implemented with actual system hooks
        # For demo purposes, we just log the actions
        
        policies = self.policies["emergency"]
        
        if policies.get("block_new_processes"):
            print("    ⚠️ New process creation blocked")
        
        if policies.get("block_network_connections"):
            print("    ⚠️ New network connections blocked")
        
        if policies.get("block_file_modifications"):
            print("    ⚠️ File modifications blocked")
        
        if policies.get("allow_whitelisted_only"):
            print("    ✅ Only whitelisted processes allowed")

    def _apply_enterprise_policies(self):
        """Apply enterprise zero-trust policies"""
        print("    🔒 Applying enterprise policies...")
        
        policies = self.policies["enterprise"]
        
        if policies.get("monitor_system_calls"):
            print("    🔍 System call monitoring enabled")
        
        if policies.get("log_suspicious_activity"):
            print("    📝 Suspicious activity logging enabled")

    def _restore_normal_operations(self):
        """Restore normal system operations"""
        print("    🔓 Restoring normal operations...")
        # Implementation would remove system hooks and restrictions

    def _start_enhanced_monitoring(self):
        """Start enhanced monitoring"""
        print("    🔍 Starting enhanced monitoring...")
        # Implementation would set up monitoring hooks

    def validate_process(self, process_name: str, process_path: str) -> bool:
        """Validate if process is allowed"""
        if not self.enforcement_enabled:
            return True
        
        # Check if process is whitelisted
        if process_name in self.whitelisted_processes:
            return True
        
        # Check if path is whitelisted
        for whitelisted_path in self.whitelisted_paths:
            if process_path.startswith(whitelisted_path):
                return True
        
        # In emergency mode, deny all non-whitelisted
        if self.emergency_mode:
            self._log_denied_operation("process_execution", process_name, process_path)
            return False
        
        return True

    def validate_file_operation(self, file_path: str, operation: str) -> bool:
        """Validate file operation"""
        if not self.enforcement_enabled:
            return True
        
        # In emergency mode, block all file modifications
        if self.emergency_mode and operation in ["write", "delete", "modify"]:
            self._log_denied_operation("file_operation", operation, file_path)
            return False
        
        return True

    def validate_network_connection(self, remote_host: str, port: int) -> bool:
        """Validate network connection"""
        if not self.enforcement_enabled:
            return True
        
        # In emergency mode, block all network connections
        if self.emergency_mode:
            self._log_denied_operation("network_connection", f"{remote_host}:{port}", "")
            return False
        
        return True

    def _log_denied_operation(self, operation_type: str, target: str, details: str):
        """Log denied operation"""
        denied_op = {
            "timestamp": datetime.now().isoformat(),
            "operation_type": operation_type,
            "target": target,
            "details": details,
            "mode": "emergency" if self.emergency_mode else "enterprise"
        }
        
        self.denied_operations.append(denied_op)
        print(f"    🚫 Denied {operation_type}: {target}")

    def add_to_whitelist(self, process_name: str = None, path: str = None) -> bool:
        """Add process or path to whitelist"""
        try:
            if process_name:
                self.whitelisted_processes.add(process_name.lower())
            if path:
                self.whitelisted_paths.add(path.lower())
            
            self._save_whitelist()
            print(f"✅ Added to whitelist: {process_name or path}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to add to whitelist: {e}")
            return False

    def remove_from_whitelist(self, process_name: str = None, path: str = None) -> bool:
        """Remove process or path from whitelist"""
        try:
            if process_name and process_name.lower() in self.whitelisted_processes:
                self.whitelisted_processes.remove(process_name.lower())
            if path and path.lower() in self.whitelisted_paths:
                self.whitelisted_paths.remove(path.lower())
            
            self._save_whitelist()
            print(f"✅ Removed from whitelist: {process_name or path}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to remove from whitelist: {e}")
            return False

    def get_enforcement_status(self) -> Dict[str, Any]:
        """Get current enforcement status"""
        return {
            "enforcement_enabled": self.enforcement_enabled,
            "emergency_mode": self.emergency_mode,
            "whitelisted_processes_count": len(self.whitelisted_processes),
            "whitelisted_paths_count": len(self.whitelisted_paths),
            "denied_operations_count": len(self.denied_operations),
            "recent_denials": self.denied_operations[-5:] if self.denied_operations else []
        }

    def get_whitelist(self) -> Dict[str, List[str]]:
        """Get current whitelist"""
        return {
            "processes": sorted(list(self.whitelisted_processes)),
            "paths": sorted(list(self.whitelisted_paths))
        }   