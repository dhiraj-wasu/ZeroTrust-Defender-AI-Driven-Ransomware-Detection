import re
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import asyncio
import json

class RuleEngine:
    def __init__(self):
        self.rules = {}
        self.rule_categories = {
            "file_encryption": [],
            "process_behavior": [],
            "network_communication": [],
            "system_manipulation": []
        }
        self.rule_weights = {}
        self.suspicious_patterns = [
            r'crypto', r'encrypt', r'ransom', r'locker', r'wannacry',
            r'petya', r'cerber', r'locky', r'cryptolocker', r'encrypted',
            r'decrypt', r'bitcoin', r'wallet', r'payment', r'recover'
        ]
        self.suspicious_extensions = [
            '.encrypted', '.locked', '.crypto', '.ransom', '.wncry',
            '.cryptolocker', '.cryptowall', '.cerber', '.zeppelin'
        ]

    async def load_rules(self):
        """Load and initialize detection rules"""
        print("📋 Loading rule-based detection engine...")
        
        # File encryption rules
        self._add_file_encryption_rules()
        
        # Process behavior rules  
        self._add_process_behavior_rules()
        
        # Network communication rules
        self._add_network_communication_rules()
        
        # System manipulation rules
        self._add_system_manipulation_rules()
        
        print(f"✅ Rule engine loaded with {len(self.rules)} rules")

    async def analyze_file_event(self, event_type: str, file_path: str,
                               features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze file event using rule-based heuristics"""
        
        rule_matches = []
        total_confidence = 0.0
        matched_rules = []
        
        # Check file encryption rules
        encryption_matches = await self._check_file_encryption_rules(
            event_type, file_path, features
        )
        rule_matches.extend(encryption_matches)
        
        # Calculate overall threat score
        if rule_matches:
            total_confidence = sum(match["confidence"] for match in rule_matches) / len(rule_matches)
            matched_rules = [match["rule_id"] for match in rule_matches]
        
        threat_detected = total_confidence > 0.6
        threat_level = self._calculate_threat_level(total_confidence)
        
        return {
            "threat_detected": threat_detected,
            "confidence": total_confidence,
            "threat_level": threat_level,
            "detection_type": "rule_based",
            "matched_rules": matched_rules,
            "rule_matches": rule_matches,
            "total_rules_checked": len(self.rules),
            "timestamp": datetime.now().isoformat()
        }

    async def analyze_process_event(self, process_data: Dict[str, Any],
                                  features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze process event using rule-based heuristics"""
        
        rule_matches = []
        total_confidence = 0.0
        matched_rules = []
        
        # Check process behavior rules
        process_matches = await self._check_process_behavior_rules(
            process_data, features
        )
        rule_matches.extend(process_matches)
        
        if rule_matches:
            total_confidence = sum(match["confidence"] for match in rule_matches) / len(rule_matches)
            matched_rules = [match["rule_id"] for match in rule_matches]
        
        threat_detected = total_confidence > 0.6
        threat_level = self._calculate_threat_level(total_confidence)
        
        return {
            "threat_detected": threat_detected,
            "confidence": total_confidence,
            "threat_level": threat_level,
            "detection_type": "rule_based",
            "matched_rules": matched_rules,
            "rule_matches": rule_matches,
            "total_rules_checked": len(self.rules),
            "timestamp": datetime.now().isoformat()
        }

    async def analyze_network_event(self, network_data: Dict[str, Any],
                                  features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network event using rule-based heuristics"""
        
        rule_matches = []
        total_confidence = 0.0
        matched_rules = []
        
        # Check network communication rules
        network_matches = await self._check_network_communication_rules(
            network_data, features
        )
        rule_matches.extend(network_matches)
        
        if rule_matches:
            total_confidence = sum(match["confidence"] for match in rule_matches) / len(rule_matches)
            matched_rules = [match["rule_id"] for match in rule_matches]
        
        threat_detected = total_confidence > 0.5
        threat_level = self._calculate_threat_level(total_confidence)
        
        return {
            "threat_detected": threat_detected,
            "confidence": total_confidence,
            "threat_level": threat_level,
            "detection_type": "rule_based",
            "matched_rules": matched_rules,
            "rule_matches": rule_matches,
            "total_rules_checked": len(self.rules),
            "timestamp": datetime.now().isoformat()
        }

    def _add_file_encryption_rules(self):
        """Add file encryption detection rules"""
        rules = [
            {
                "id": "FILE_ENC_001",
                "name": "Suspicious File Extension",
                "category": "file_encryption",
                "weight": 0.8,
                "condition": lambda e, p, f: self._has_suspicious_extension(p),
                "description": "File has known ransomware extension"
            },
            {
                "id": "FILE_ENC_002", 
                "name": "Mass File Modification",
                "category": "file_encryption",
                "weight": 0.7,
                "condition": lambda e, p, f: f.get("files_modified_5min", 0) > 50,
                "description": "High number of file modifications in short time"
            },
            {
                "id": "FILE_ENC_003",
                "name": "High Entropy Content",
                "category": "file_encryption", 
                "weight": 0.9,
                "condition": lambda e, p, f: f.get("entropy", 0) > 7.5,
                "description": "File content has high entropy indicating encryption"
            },
            {
                "id": "FILE_ENC_004",
                "name": "Ransom Note Creation",
                "category": "file_encryption",
                "weight": 0.95,
                "condition": lambda e, p, f: self._is_ransom_note_file(p),
                "description": "Ransom note file created"
            },
            {
                "id": "FILE_ENC_005",
                "name": "Extension Change Pattern", 
                "category": "file_encryption",
                "weight": 0.85,
                "condition": lambda e, p, f: f.get("extension_changed", False),
                "description": "File extension changed to suspicious type"
            }
        ]
        
        for rule in rules:
            self.rules[rule["id"]] = rule

    def _add_process_behavior_rules(self):
        """Add process behavior detection rules"""
        rules = [
            {
                "id": "PROC_BEH_001",
                "name": "Suspicious Process Name",
                "category": "process_behavior", 
                "weight": 0.7,
                "condition": lambda p, f: self._has_suspicious_process_name(p.get("name", "")),
                "description": "Process name matches known ransomware patterns"
            },
            {
                "id": "PROC_BEH_002",
                "name": "High CPU Usage",
                "category": "process_behavior",
                "weight": 0.6,
                "condition": lambda p, f: p.get("cpu", 0) > 90.0,
                "description": "Process consuming excessive CPU resources"
            },
            {
                "id": "PROC_BEH_003",
                "name": "File Handle Proliferation",
                "category": "process_behavior",
                "weight": 0.75,
                "condition": lambda p, f: f.get("file_handles", 0) > 1000,
                "description": "Process has unusually high number of file handles"
            },
            {
                "id": "PROC_BEH_004",
                "name": "Cryptographic API Calls",
                "category": "process_behavior",
                "weight": 0.8,
                "condition": lambda p, f: f.get("crypto_api_calls", 0) > 100,
                "description": "High number of cryptographic API calls"
            },
            {
                "id": "PROC_BEH_005",
                "name": "Process Injection",
                "category": "process_behavior",
                "weight": 0.9,
                "condition": lambda p, f: f.get("process_injection", False),
                "description": "Process attempting code injection into other processes"
            }
        ]
        
        for rule in rules:
            self.rules[rule["id"]] = rule

    def _add_network_communication_rules(self):
        """Add network communication detection rules"""
        rules = [
            {
                "id": "NET_COM_001",
                "name": "SMB Lateral Movement",
                "category": "network_communication",
                "weight": 0.8,
                "condition": lambda n, f: f.get("remote_port", 0) == 445,
                "description": "SMB connections indicating lateral movement"
            },
            {
                "id": "NET_COM_002",
                "name": "RDP Brute Force",
                "category": "network_communication",
                "weight": 0.7,
                "condition": lambda n, f: f.get("remote_port", 0) == 3389 and f.get("connection_attempts", 0) > 10,
                "description": "Multiple RDP connection attempts"
            },
            {
                "id": "NET_COM_003",
                "name": "C2 Communication",
                "category": "network_communication",
                "weight": 0.85,
                "condition": lambda n, f: f.get("is_c2_ip", False),
                "description": "Communication with known C2 server IP"
            },
            {
                "id": "NET_COM_004",
                "name": "Data Exfiltration",
                "category": "network_communication", 
                "weight": 0.75,
                "condition": lambda n, f: f.get("data_sent", 0) > 100000000,  # 100MB
                "description": "Large amount of data being sent"
            },
            {
                "id": "NET_COM_005",
                "name": "Encrypted Traffic to Unknown",
                "category": "network_communication",
                "weight": 0.6,
                "condition": lambda n, f: f.get("is_encrypted", False) and f.get("is_unknown_destination", False),
                "description": "Encrypted traffic to unknown destination"
            }
        ]
        
        for rule in rules:
            self.rules[rule["id"]] = rule

    def _add_system_manipulation_rules(self):
        """Add system manipulation detection rules"""
        rules = [
            {
                "id": "SYS_MAN_001",
                "name": "Registry Modification",
                "category": "system_manipulation",
                "weight": 0.7,
                "condition": lambda p, f: f.get("registry_modifications", 0) > 10,
                "description": "Multiple registry modifications"
            },
            {
                "id": "SYS_MAN_002",
                "name": "Service Creation",
                "category": "system_manipulation",
                "weight": 0.8,
                "condition": lambda p, f: f.get("services_created", 0) > 0,
                "description": "New services created"
            },
            {
                "id": "SYS_MAN_003",
                "name": "Shadow Copy Deletion",
                "category": "system_manipulation",
                "weight": 0.9,
                "condition": lambda p, f: f.get("shadow_copies_deleted", False),
                "description": "Volume shadow copies deleted"
            },
            {
                "id": "SYS_MAN_004",
                "name": "Boot Configuration Modified",
                "category": "system_manipulation",
                "weight": 0.85,
                "condition": lambda p, f: f.get("bcd_modified", False),
                "description": "Boot configuration data modified"
            }
        ]
        
        for rule in rules:
            self.rules[rule["id"]] = rule

    async def _check_file_encryption_rules(self, event_type: str, file_path: str,
                                         features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check file encryption rules"""
        matches = []
        for rule_id, rule in self.rules.items():
            if rule["category"] == "file_encryption":
                try:
                    if rule["condition"](event_type, file_path, features):
                        matches.append({
                            "rule_id": rule_id,
                            "rule_name": rule["name"],
                            "confidence": rule["weight"],
                            "description": rule["description"]
                        })
                except Exception as e:
                    print(f"Rule evaluation error {rule_id}: {e}")
        return matches

    async def _check_process_behavior_rules(self, process_data: Dict[str, Any],
                                          features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check process behavior rules"""
        matches = []
        for rule_id, rule in self.rules.items():
            if rule["category"] == "process_behavior":
                try:
                    if rule["condition"](process_data, features):
                        matches.append({
                            "rule_id": rule_id,
                            "rule_name": rule["name"],
                            "confidence": rule["weight"],
                            "description": rule["description"]
                        })
                except Exception as e:
                    print(f"Rule evaluation error {rule_id}: {e}")
        return matches

    async def _check_network_communication_rules(self, network_data: Dict[str, Any],
                                               features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check network communication rules"""
        matches = []
        for rule_id, rule in self.rules.items():
            if rule["category"] == "network_communication":
                try:
                    if rule["condition"](network_data, features):
                        matches.append({
                            "rule_id": rule_id,
                            "rule_name": rule["name"],
                            "confidence": rule["weight"],
                            "description": rule["description"]
                        })
                except Exception as e:
                    print(f"Rule evaluation error {rule_id}: {e}")
        return matches

    def _has_suspicious_extension(self, file_path: str) -> bool:
        """Check if file has suspicious extension"""
        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in self.suspicious_extensions

    def _has_suspicious_process_name(self, process_name: str) -> bool:
        """Check if process name is suspicious"""
        process_lower = process_name.lower()
        return any(pattern in process_lower for pattern in self.suspicious_patterns)

    def _is_ransom_note_file(self, file_path: str) -> bool:
        """Check if file is a ransom note"""
        ransom_note_patterns = [
            r'readme', r'decrypt', r'recover', r'instruction', r'help',
            r'how_to_recover', r'ransom', r'payment', r'bitcoin'
        ]
        file_name = os.path.basename(file_path).lower()
        return any(pattern in file_name for pattern in ransom_note_patterns)

    def _calculate_threat_level(self, confidence: float) -> str:
        """Calculate threat level based on confidence"""
        if confidence > 0.8:
            return "critical"
        elif confidence > 0.6:
            return "high"
        elif confidence > 0.4:
            return "suspicious"
        else:
            return "normal"

    async def add_custom_rule(self, rule_definition: Dict[str, Any]) -> bool:
        """Add a custom rule to the engine"""
        try:
            rule_id = rule_definition.get("id")
            if rule_id in self.rules:
                return False  # Rule ID already exists
            
            self.rules[rule_id] = rule_definition
            return True
            
        except Exception as e:
            print(f"Error adding custom rule: {e}")
            return False

    async def get_rule_statistics(self) -> Dict[str, Any]:
        """Get rule engine statistics"""
        category_counts = {}
        for rule in self.rules.values():
            category = rule["category"]
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            "total_rules": len(self.rules),
            "rules_by_category": category_counts,
            "rule_categories": list(self.rule_categories.keys())
        }  