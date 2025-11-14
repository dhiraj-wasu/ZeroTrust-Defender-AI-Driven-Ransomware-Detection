import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import asyncio
from collections import deque
import statistics

class SlowRansomwareDetector:
    def __init__(self):
        self.time_windows = {
            "short": timedelta(minutes=5),
            "medium": timedelta(hours=1),
            "long": timedelta(hours=24)
        }
        
        self.behavior_profiles = {
            "stealth_encryption": {
                "description": "Slow, stealthy file encryption over time",
                "indicators": ["gradual_entropy_increase", "sparse_modifications", "time_distributed_operations"]
            },
            "low_profile_exfiltration": {
                "description": "Slow data exfiltration to avoid detection",
                "indicators": ["small_consistent_transfers", "encrypted_channels", "business_hours_activity"]
            },
            "progressive_encryption": {
                "description": "Progressive encryption of files in stages",
                "indicators": ["batch_operations", "incremental_encryption", "backup_targeting"]
            }
        }
        
        self.feature_history = deque(maxlen=10000)  # Store last 10,000 events
        self.anomaly_scores = {}
        self.detection_threshold = 0.7

    async def initialize_detector(self):
        """Initialize slow ransomware detection"""
        print("⏳ Initializing slow ransomware detection...")
        # Initialize baseline profiles
        await self._initialize_baseline_profiles()
        print("✅ Slow ransomware detection initialized")

    async def analyze_time_series(self, feature_history: List[Dict]) -> Dict[str, Any]:
        """Analyze time series data for slow ransomware patterns"""
        
        if len(feature_history) < 50:
            return {
                "threat_detected": False,
                "confidence": 0.0,
                "threat_level": "normal",
                "detection_type": "slow_ransomware",
                "timestamp": datetime.now().isoformat()
            }
        
        # Update feature history
        self.feature_history.extend(feature_history)
        
        # Analyze different behavior patterns
        stealth_score = await self._detect_stealth_encryption()
        exfiltration_score = await self._detect_low_profile_exfiltration()
        progressive_score = await self._detect_progressive_encryption()
        
        # Calculate overall score
        overall_score = max(stealth_score, exfiltration_score, progressive_score)
        
        threat_detected = overall_score > self.detection_threshold
        threat_level = "suspicious" if overall_score > 0.7 else "normal"
        
        behavior_analysis = {
            "stealth_encryption_score": stealth_score,
            "low_profile_exfiltration_score": exfiltration_score,
            "progressive_encryption_score": progressive_score,
            "primary_behavior": self._identify_primary_behavior(stealth_score, exfiltration_score, progressive_score)
        }
        
        return {
            "threat_detected": threat_detected,
            "confidence": overall_score,
            "threat_level": threat_level,
            "detection_type": "slow_ransomware",
            "behavior_analysis": behavior_analysis,
            "timestamp": datetime.now().isoformat()
        }

    async def analyze_file_patterns(self, feature_history: List[Dict], 
                                  current_features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze file patterns for slow ransomware"""
        
        file_entropy_trend = await self._analyze_entropy_trend(feature_history)
        modification_pattern = await self._analyze_modification_pattern(feature_history)
        access_sequence = await self._analyze_access_sequence(feature_history)
        
        # Calculate file-based threat score
        file_threat_score = (file_entropy_trend + modification_pattern + access_sequence) / 3.0
        
        threat_detected = file_threat_score > self.detection_threshold
        threat_level = "suspicious" if file_threat_score > 0.6 else "normal"
        
        return {
            "threat_detected": threat_detected,
            "confidence": file_threat_score,
            "threat_level": threat_level,
            "detection_type": "slow_ransomware_file",
            "analysis_components": {
                "entropy_trend": file_entropy_trend,
                "modification_pattern": modification_pattern,
                "access_sequence": access_sequence
            },
            "timestamp": datetime.now().isoformat()
        }

    async def analyze_process_patterns(self, feature_history: List[Dict],
                                     current_process: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze process patterns for slow ransomware"""
        
        resource_usage_trend = await self._analyze_resource_usage_trend(feature_history)
        execution_pattern = await self._analyze_execution_pattern(feature_history)
        network_behavior = await self._analyze_network_behavior(feature_history)
        
        process_threat_score = (resource_usage_trend + execution_pattern + network_behavior) / 3.0
        
        threat_detected = process_threat_score > self.detection_threshold
        threat_level = "suspicious" if process_threat_score > 0.6 else "normal"
        
        return {
            "threat_detected": threat_detected,
            "confidence": process_threat_score,
            "threat_level": threat_level,
            "detection_type": "slow_ransomware_process",
            "analysis_components": {
                "resource_usage_trend": resource_usage_trend,
                "execution_pattern": execution_pattern,
                "network_behavior": network_behavior
            },
            "timestamp": datetime.now().isoformat()
        }

    async def analyze_network_patterns(self, feature_history: List[Dict],
                                     current_network: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network patterns for slow ransomware"""
        
        data_transfer_trend = await self._analyze_data_transfer_trend(feature_history)
        connection_pattern = await self._analyze_connection_pattern(feature_history)
        protocol_usage = await self._analyze_protocol_usage(feature_history)
        
        network_threat_score = (data_transfer_trend + connection_pattern + protocol_usage) / 3.0
        
        threat_detected = network_threat_score > self.detection_threshold
        threat_level = "suspicious" if network_threat_score > 0.6 else "normal"
        
        return {
            "threat_detected": threat_detected,
            "confidence": network_threat_score,
            "threat_level": threat_level,
            "detection_type": "slow_ransomware_network",
            "analysis_components": {
                "data_transfer_trend": data_transfer_trend,
                "connection_pattern": connection_pattern,
                "protocol_usage": protocol_usage
            },
            "timestamp": datetime.now().isoformat()
        }

    async def _detect_stealth_encryption(self) -> float:
        """Detect stealth encryption patterns"""
        if len(self.feature_history) < 100:
            return 0.0
        
        # Analyze entropy trends over time
        entropy_values = [f.get("entropy", 0) for f in self.feature_history if "entropy" in f]
        if len(entropy_values) < 50:
            return 0.0
        
        # Calculate entropy trend
        entropy_trend = self._calculate_trend(entropy_values)
        
        # Analyze modification patterns
        modification_times = [datetime.fromisoformat(f["timestamp"]) for f in self.feature_history if "timestamp" in f]
        time_distribution = self._analyze_time_distribution(modification_times)
        
        # Combine scores
        stealth_score = (entropy_trend + time_distribution) / 2.0
        return max(0.0, min(1.0, stealth_score))

    async def _detect_low_profile_exfiltration(self) -> float:
        """Detect low-profile data exfiltration"""
        if len(self.feature_history) < 100:
            return 0.0
        
        # Analyze network transfer patterns
        transfer_sizes = [f.get("data_sent", 0) for f in self.feature_history if "data_sent" in f]
        if len(transfer_sizes) < 20:
            return 0.0
        
        # Check for consistent small transfers
        transfer_consistency = self._analyze_transfer_consistency(transfer_sizes)
        
        # Analyze timing patterns (avoiding peak hours)
        transfer_times = [datetime.fromisoformat(f["timestamp"]) for f in self.feature_history 
                         if "data_sent" in f and f.get("data_sent", 0) > 0]
        timing_analysis = self._analyze_transfer_timing(transfer_times)
        
        exfiltration_score = (transfer_consistency + timing_analysis) / 2.0
        return max(0.0, min(1.0, exfiltration_score))

    async def _detect_progressive_encryption(self) -> float:
        """Detect progressive encryption patterns"""
        if len(self.feature_history) < 200:
            return 0.0
        
        # Analyze batch operations
        batch_operations = self._detect_batch_operations()
        
        # Analyze file type targeting
        file_targeting = self._analyze_file_targeting()
        
        # Analyze backup-related activity
        backup_activity = self._analyze_backup_activity()
        
        progressive_score = (batch_operations + file_targeting + backup_activity) / 3.0
        return max(0.0, min(1.0, progressive_score))

    async def _analyze_entropy_trend(self, feature_history: List[Dict]) -> float:
        """Analyze entropy trend over time"""
        entropy_values = [f.get("entropy", 0) for f in feature_history if "entropy" in f]
        if len(entropy_values) < 10:
            return 0.0
        
        trend = self._calculate_trend(entropy_values)
        return abs(trend)  # We care about magnitude of change

    async def _analyze_modification_pattern(self, feature_history: List[Dict]) -> float:
        """Analyze file modification patterns"""
        modification_events = [f for f in feature_history if f.get("event_type") in ["modified", "created"]]
        
        if len(modification_events) < 20:
            return 0.0
        
        # Calculate modification rate variability
        timestamps = [datetime.fromisoformat(f["timestamp"]) for f in modification_events]
        time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
        
        if not time_diffs:
            return 0.0
        
        variability = statistics.stdev(time_diffs) if len(time_diffs) > 1 else 0.0
        normalized_variability = min(1.0, variability / 3600)  # Normalize to 1 hour
        
        return normalized_variability

    async def _analyze_access_sequence(self, feature_history: List[Dict]) -> float:
        """Analyze file access sequences"""
        file_events = [f for f in feature_history if "file_path" in f]
        
        if len(file_events) < 30:
            return 0.0
        
        # Analyze sequential access patterns
        file_sequences = self._extract_file_sequences(file_events)
        sequence_entropy = self._calculate_sequence_entropy(file_sequences)
        
        return sequence_entropy

    async def _analyze_resource_usage_trend(self, feature_history: List[Dict]) -> float:
        """Analyze resource usage trends"""
        cpu_usage = [f.get("cpu_usage", 0) for f in feature_history if "cpu_usage" in f]
        memory_usage = [f.get("memory_usage", 0) for f in feature_history if "memory_usage" in f]
        
        if len(cpu_usage) < 10 or len(memory_usage) < 10:
            return 0.0
        
        cpu_trend = self._calculate_trend(cpu_usage)
        memory_trend = self._calculate_trend(memory_usage)
        
        return (abs(cpu_trend) + abs(memory_trend)) / 2.0

    async def _analyze_execution_pattern(self, feature_history: List[Dict]) -> float:
        """Analyze process execution patterns"""
        process_events = [f for f in feature_history if "process_name" in f]
        
        if len(process_events) < 20:
            return 0.0
        
        # Analyze execution timing and duration patterns
        execution_times = [datetime.fromisoformat(f["timestamp"]) for f in process_events]
        time_pattern = self._analyze_temporal_pattern(execution_times)
        
        return time_pattern

    async def _analyze_network_behavior(self, feature_history: List[Dict]) -> float:
        """Analyze network behavior patterns"""
        network_events = [f for f in feature_history if "network_connection" in f]
        
        if len(network_events) < 15:
            return 0.0
        
        # Analyze connection patterns and data transfer
        connection_times = [datetime.fromisoformat(f["timestamp"]) for f in network_events]
        temporal_pattern = self._analyze_temporal_pattern(connection_times)
        
        data_volumes = [f.get("data_volume", 0) for f in network_events]
        volume_consistency = self._analyze_volume_consistency(data_volumes)
        
        return (temporal_pattern + volume_consistency) / 2.0

    async def _analyze_data_transfer_trend(self, feature_history: List[Dict]) -> float:
        """Analyze data transfer trends"""
        data_transfers = [f.get("data_sent", 0) for f in feature_history if "data_sent" in f]
        
        if len(data_transfers) < 10:
            return 0.0
        
        trend = self._calculate_trend(data_transfers)
        return abs(trend)

    async def _analyze_connection_pattern(self, feature_history: List[Dict]) -> float:
        """Analyze connection patterns"""
        connections = [f for f in feature_history if "remote_host" in f]
        
        if len(connections) < 10:
            return 0.0
        
        # Analyze connection frequency and destinations
        unique_hosts = len(set(f.get("remote_host") for f in connections))
        connection_frequency = len(connections) / max(1, len(feature_history))
        
        pattern_score = min(1.0, (unique_hosts * connection_frequency) / 10.0)
        return pattern_score

    async def _analyze_protocol_usage(self, feature_history: List[Dict]) -> float:
        """Analyze protocol usage patterns"""
        protocols = [f.get("protocol", "") for f in feature_history if "protocol" in f]
        
        if not protocols:
            return 0.0
        
        # Analyze protocol diversity and unusual combinations
        protocol_diversity = len(set(protocols)) / max(1, len(protocols))
        unusual_protocols = sum(1 for p in protocols if p in ["SMB", "RDP", "FTP"]) / max(1, len(protocols))
        
        return (protocol_diversity + unusual_protocols) / 2.0

    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend using linear regression"""
        if len(values) < 2:
            return 0.0
        
        x = np.arange(len(values))
        y = np.array(values)
        
        try:
            slope = np.polyfit(x, y, 1)[0]
            normalized_slope = slope / (max(y) - min(y)) if max(y) != min(y) else 0.0
            return normalized_slope
        except:
            return 0.0

    def _analyze_time_distribution(self, timestamps: List[datetime]) -> float:
        """Analyze time distribution of events"""
        if len(timestamps) < 10:
            return 0.0
        
        # Calculate time between events
        time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
        
        if not time_diffs:
            return 0.0
        
        # Calculate coefficient of variation
        mean_diff = statistics.mean(time_diffs)
        std_diff = statistics.stdev(time_diffs) if len(time_diffs) > 1 else 0.0
        
        cv = std_diff / mean_diff if mean_diff > 0 else 0.0
        return min(1.0, cv)

    def _analyze_transfer_consistency(self, transfer_sizes: List[float]) -> float:
        """Analyze consistency of data transfers"""
        if len(transfer_sizes) < 5:
            return 0.0
        
        # Calculate coefficient of variation
        mean_size = statistics.mean(transfer_sizes)
        std_size = statistics.stdev(transfer_sizes) if len(transfer_sizes) > 1 else 0.0
        
        cv = std_size / mean_size if mean_size > 0 else 0.0
        # Low CV indicates consistent transfers (suspicious for slow exfiltration)
        return 1.0 - min(1.0, cv)

    def _analyze_transfer_timing(self, transfer_times: List[datetime]) -> float:
        """Analyze timing of data transfers"""
        if len(transfer_times) < 5:
            return 0.0
        
        # Check if transfers avoid business hours (9 AM - 5 PM)
        off_hour_transfers = 0
        for time in transfer_times:
            hour = time.hour
            if hour < 9 or hour >= 17:  # Outside business hours
                off_hour_transfers += 1
        
        off_hour_ratio = off_hour_transfers / len(transfer_times)
        return off_hour_ratio

    def _detect_batch_operations(self) -> float:
        """Detect batch file operations"""
        file_events = [f for f in self.feature_history if "file_path" in f]
        
        if len(file_events) < 50:
            return 0.0
        
        # Analyze event clustering in time
        event_times = [datetime.fromisoformat(f["timestamp"]) for f in file_events]
        time_diffs = [(event_times[i+1] - event_times[i]).total_seconds() for i in range(len(event_times)-1)]
        
        # Count rapid successions (batch operations)
        rapid_successions = sum(1 for diff in time_diffs if diff < 1.0)  # Less than 1 second apart
        batch_ratio = rapid_successions / len(time_diffs) if time_diffs else 0.0
        
        return min(1.0, batch_ratio * 10)  # Scale to 0-1 range

    def _analyze_file_targeting(self) -> float:
        """Analyze file type targeting patterns"""
        file_events = [f for f in self.feature_history if "file_path" in f]
        
        if len(file_events) < 30:
            return 0.0
        
        # Count targeting of specific file types
        document_extensions = ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx']
        document_count = sum(1 for f in file_events 
                           if any(ext in f.get("file_path", "").lower() for ext in document_extensions))
        
        targeting_ratio = document_count / len(file_events)
        return min(1.0, targeting_ratio * 5)  # Scale to 0-1 range

    def _analyze_backup_activity(self) -> float:
        """Analyze backup-related activity"""
        backup_keywords = ['backup', 'shadow', 'vss', 'volume', 'restore']
        backup_events = sum(1 for f in self.feature_history 
                          if any(keyword in str(f).lower() for keyword in backup_keywords))
        
        backup_ratio = backup_events / len(self.feature_history) if self.feature_history else 0.0
        return min(1.0, backup_ratio * 10)  # Scale to 0-1 range

    def _extract_file_sequences(self, file_events: List[Dict]) -> List[List[str]]:
        """Extract file access sequences"""
        sequences = []
        current_sequence = []
        
        for event in file_events:
            file_path = event.get("file_path", "")
            if file_path:
                current_sequence.append(file_path)
            else:
                if current_sequence:
                    sequences.append(current_sequence)
                    current_sequence = []
        
        if current_sequence:
            sequences.append(current_sequence)
        
        return sequences

    def _calculate_sequence_entropy(self, sequences: List[List[str]]) -> float:
        """Calculate entropy of file sequences"""
        if not sequences:
            return 0.0
        
        # Flatten sequences and calculate entropy of file access patterns
        all_files = [file for sequence in sequences for file in sequence]
        
        if not all_files:
            return 0.0
        
        # Calculate frequency distribution
        file_counts = {}
        for file in all_files:
            file_counts[file] = file_counts.get(file, 0) + 1
        
        # Calculate entropy
        total_files = len(all_files)
        entropy = 0.0
        for count in file_counts.values():
            probability = count / total_files
            entropy -= probability * np.log2(probability)
        
        # Normalize entropy (max entropy is log2(n) where n is number of unique files)
        max_entropy = np.log2(len(file_counts)) if file_counts else 1.0
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
        
        return normalized_entropy

    def _analyze_temporal_pattern(self, timestamps: List[datetime]) -> float:
        """Analyze temporal patterns in events"""
        if len(timestamps) < 10:
            return 0.0
        
        # Analyze periodicity and timing patterns
        hours = [ts.hour for ts in timestamps]
        hour_entropy = self._calculate_entropy(hours)
        
        return hour_entropy

    def _analyze_volume_consistency(self, volumes: List[float]) -> float:
        """Analyze consistency of data volumes"""
        if len(volumes) < 5:
            return 0.0
        
        # Low variance indicates consistent data transfer (suspicious)
        variance = statistics.variance(volumes) if len(volumes) > 1 else 0.0
        normalized_variance = min(1.0, variance / (max(volumes) if max(volumes) > 0 else 1.0))
        
        return 1.0 - normalized_variance  # Invert so low variance = high score

    def _calculate_entropy(self, values: List[Any]) -> float:
        """Calculate entropy of a value distribution"""
        if not values:
            return 0.0
        
        value_counts = {}
        for value in values:
            value_counts[value] = value_counts.get(value, 0) + 1
        
        total = len(values)
        entropy = 0.0
        for count in value_counts.values():
            probability = count / total
            entropy -= probability * np.log2(probability)
        
        max_entropy = np.log2(len(value_counts)) if value_counts else 1.0
        return entropy / max_entropy if max_entropy > 0 else 0.0

    def _identify_primary_behavior(self, stealth_score: float, 
                                 exfiltration_score: float, 
                                 progressive_score: float) -> str:
        """Identify primary behavior pattern"""
        scores = {
            "stealth_encryption": stealth_score,
            "low_profile_exfiltration": exfiltration_score,
            "progressive_encryption": progressive_score
        }
        
        primary_behavior = max(scores, key=scores.get)
        return primary_behavior if scores[primary_behavior] > 0.3 else "normal"

    async def _initialize_baseline_profiles(self):
        """Initialize baseline behavior profiles"""
        # This would typically load historical data to establish baselines
        # For now, we'll use empty baselines that will be populated over time
        self.baseline_profiles = {
            "file_entropy": 0.0,
            "modification_frequency": 0.0,
            "network_activity": 0.0
        }

    async def get_detection_statistics(self) -> Dict[str, Any]:
        """Get slow ransomware detection statistics"""
        return {
            "feature_history_size": len(self.feature_history),
            "detection_threshold": self.detection_threshold,
            "behavior_profiles": list(self.behavior_profiles.keys()),
            "time_windows": {k: str(v) for k, v in self.time_windows.items()}
        }