import os
import math
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import asyncio
import psutil

class FeatureExtractor:
    def __init__(self):
        self.feature_cache = {}
        self.cache_size = 1000
        self.history_window = timedelta(hours=24)

    async def extract_file_features(self, event_type: str, file_path: str, 
                                  details: Dict[str, Any] = None) -> Dict[str, Any]:
        """Extract features from file events"""
        features = {
            "event_type": event_type,
            "file_path": file_path,
            "file_size": 0,
            "entropy": 0,
            "file_extension": self._get_file_extension(file_path),
            "is_system_file": self._is_system_file(file_path),
            "is_executable": self._is_executable_file(file_path),
            "is_document": self._is_document_file(file_path),
            "timestamp": datetime.now().isoformat()
        }
        
        # Add file size if available
        try:
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                features["file_size"] = file_size
                features["entropy"] = await self._calculate_file_entropy(file_path)
        except:
            pass
        
        # Add details if provided
        if details:
            features.update(details)
        
        # Calculate derived features
        features.update(await self._calculate_derived_file_features(features))
        
        return features

    async def extract_process_features(self, process_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from process events"""
        features = {
            "process_name": process_data.get("name", ""),
            "pid": process_data.get("pid", 0),
            "cpu_usage": process_data.get("cpu", 0),
            "memory_usage": process_data.get("memory", 0),
            "username": process_data.get("username", ""),
            "timestamp": datetime.now().isoformat()
        }
        
        # Calculate derived features
        features.update(await self._calculate_derived_process_features(features))
        
        return features

    async def extract_network_features(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from network events"""
        features = {
            "connection_type": network_data.get("type", ""),
            "local_address": network_data.get("local", ""),
            "remote_address": network_data.get("remote", ""),
            "protocol": network_data.get("protocol", ""),
            "status": network_data.get("status", ""),
            "timestamp": datetime.now().isoformat()
        }
        
        # Calculate derived features
        features.update(await self._calculate_derived_network_features(features))
        
        return features

    async def _calculate_derived_file_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate derived file features"""
        derived = {}
        
        # File type features
        file_ext = features.get("file_extension", "").lower()
        derived["is_suspicious_extension"] = 1.0 if self._is_suspicious_extension(file_ext) else 0.0
        derived["is_archive"] = 1.0 if file_ext in ['.zip', '.rar', '.7z'] else 0.0
        
        # Entropy-based features
        entropy = features.get("entropy", 0)
        derived["high_entropy"] = 1.0 if entropy > 7.0 else 0.0
        
        # Size-based features
        file_size = features.get("file_size", 0)
        derived["is_large_file"] = 1.0 if file_size > 1000000 else 0.0  # 1MB
        
        return derived

    async def _calculate_derived_process_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate derived process features"""
        derived = {}
        
        # Process name analysis
        process_name = features.get("process_name", "").lower()
        derived["is_suspicious_name"] = 1.0 if self._is_suspicious_process_name(process_name) else 0.0
        derived["is_system_process"] = 1.0 if self._is_system_process(process_name) else 0.0
        
        # Resource usage features
        cpu_usage = features.get("cpu_usage", 0)
        memory_usage = features.get("memory_usage", 0)
        derived["high_cpu_usage"] = 1.0 if cpu_usage > 80.0 else 0.0
        derived["high_memory_usage"] = 1.0 if memory_usage > 80.0 else 0.0
        
        return derived

    async def _calculate_derived_network_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate derived network features"""
        derived = {}
        
        # Port analysis
        remote_addr = features.get("remote_address", "")
        port = self._extract_port(remote_addr)
        derived["remote_port"] = port
        derived["is_smb_port"] = 1.0 if port == 445 else 0.0
        derived["is_rdp_port"] = 1.0 if port == 3389 else 0.0
        
        # Protocol analysis
        protocol = features.get("protocol", "").lower()
        derived["is_suspicious_protocol"] = 1.0 if protocol in ['smb', 'rdp'] else 0.0
        
        return derived

    async def _calculate_file_entropy(self, file_path: str) -> float:
        """Calculate file entropy (measure of randomness)"""
        try:
            if not os.path.exists(file_path) or os.path.isdir(file_path):
                return 0.0
            
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return 0.0
            
            # Read first 1MB for entropy calculation (for performance)
            sample_size = min(file_size, 1024 * 1024)
            
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
            
        except Exception as e:
            return 0.0

    def _get_file_extension(self, file_path: str) -> str:
        """Get file extension in lowercase"""
        return os.path.splitext(file_path)[1].lower()

    def _is_system_file(self, file_path: str) -> bool:
        """Check if file is a system file"""
        system_dirs = ['/windows/', '/system32/', '/program files/', '/programdata/']
        file_path_lower = file_path.lower()
        return any(system_dir in file_path_lower for system_dir in system_dirs)

    def _is_executable_file(self, file_path: str) -> bool:
        """Check if file is executable"""
        executable_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs']
        file_ext = self._get_file_extension(file_path)
        return file_ext in executable_extensions

    def _is_document_file(self, file_path: str) -> bool:
        """Check if file is a document"""
        document_extensions = ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx', '.txt']
        file_ext = self._get_file_extension(file_path)
        return file_ext in document_extensions

    def _is_suspicious_extension(self, file_ext: str) -> bool:
        """Check if file extension is suspicious"""
        suspicious_extensions = [
            '.encrypted', '.locked', '.crypto', '.ransom', '.wncry',
            '.cryptolocker', '.cryptowall', '.cerber'
        ]
        return file_ext in suspicious_extensions

    def _is_suspicious_process_name(self, process_name: str) -> bool:
        """Check if process name is suspicious"""
        suspicious_patterns = [
            'crypto', 'encrypt', 'ransom', 'locker', 'wannacry',
            'petya', 'cerber', 'locky', 'cryptolocker'
        ]
        return any(pattern in process_name for pattern in suspicious_patterns)

    def _is_system_process(self, process_name: str) -> bool:
        """Check if process is a system process"""
        system_processes = [
            'svchost.exe', 'services.exe', 'lsass.exe', 'winlogon.exe',
            'csrss.exe', 'smss.exe', 'system', 'system idle process'
        ]
        return process_name in system_processes

    def _extract_port(self, address: str) -> int:
        """Extract port number from address string"""
        try:
            if ':' in address:
                return int(address.split(':')[-1])
        except:
            pass
        return 0

    async def get_feature_statistics(self) -> Dict[str, Any]:
        """Get feature extraction statistics"""
        return {
            "cache_size": len(self.feature_cache),
            "max_cache_size": self.cache_size,
            "history_window": str(self.history_window)
        }