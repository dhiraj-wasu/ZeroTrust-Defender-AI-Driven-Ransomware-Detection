import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import asyncio
import json
import os

class AnomalyDetector:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_means = {}
        self.feature_stds = {}
        self.history_window = 1000
        self.feature_history = {
            "file": [],
            "process": [], 
            "network": []
        }
        
        # Anomaly detection thresholds
        self.thresholds = {
            "file_anomaly": 0.65,
            "process_anomaly": 0.7,
            "network_anomaly": 0.6
        }

    async def initialize_models(self):
        """Initialize anomaly detection models"""
        print("🔍 Initializing unsupervised anomaly detection models...")
        
        # Initialize models for different data types
        self.models["file"] = IsolationForest(
            contamination=0.1, 
            random_state=42,
            n_estimators=100
        )
        
        self.models["process"] = IsolationForest(
            contamination=0.05,
            random_state=42, 
            n_estimators=100
        )
        
        self.models["network"] = IsolationForest(
            contamination=0.08,
            random_state=42,
            n_estimators=100
        )
        
        # Initialize scalers
        for data_type in ["file", "process", "network"]:
            self.scalers[data_type] = StandardScaler()
        
        print("✅ Anomaly detection models initialized")

    async def detect_file_anomaly(self, event_type: str, file_path: str,
                                features: Dict[str, Any], 
                                feature_history: List[Dict]) -> Dict[str, Any]:
        """Detect file anomalies using unsupervised learning"""
        
        # Extract anomaly features
        anomaly_features = self._extract_file_anomaly_features(
            event_type, file_path, features
        )
        
        # Update history and train model if needed
        await self._update_file_history(anomaly_features)
        
        # Detect anomaly
        anomaly_score, is_anomaly = await self._detect_anomaly(
            "file", anomaly_features
        )
        
        # Calculate confidence and threat level
        confidence = abs(anomaly_score)
        threat_detected = is_anomaly and confidence > self.thresholds["file_anomaly"]
        
        if threat_detected:
            threat_level = "critical" if confidence > 0.9 else "high"
        else:
            threat_level = "normal"
        
        return {
            "threat_detected": threat_detected,
            "confidence": confidence,
            "threat_level": threat_level,
            "detection_type": "unsupervised_anomaly",
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "features_analyzed": list(anomaly_features.keys()),
            "timestamp": datetime.now().isoformat()
        }

    async def detect_process_anomaly(self, process_data: Dict[str, Any],
                                   features: Dict[str, Any],
                                   feature_history: List[Dict]) -> Dict[str, Any]:
        """Detect process anomalies using unsupervised learning"""
        
        anomaly_features = self._extract_process_anomaly_features(
            process_data, features
        )
        
        await self._update_process_history(anomaly_features)
        
        anomaly_score, is_anomaly = await self._detect_anomaly(
            "process", anomaly_features
        )
        
        confidence = abs(anomaly_score)
        threat_detected = is_anomaly and confidence > self.thresholds["process_anomaly"]
        
        if threat_detected:
            threat_level = "critical" if confidence > 0.9 else "high"
        else:
            threat_level = "normal"
        
        return {
            "threat_detected": threat_detected,
            "confidence": confidence,
            "threat_level": threat_level,
            "detection_type": "unsupervised_anomaly", 
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "features_analyzed": list(anomaly_features.keys()),
            "timestamp": datetime.now().isoformat()
        }

    async def detect_network_anomaly(self, network_data: Dict[str, Any],
                                   features: Dict[str, Any],
                                   feature_history: List[Dict]) -> Dict[str, Any]:
        """Detect network anomalies using unsupervised learning"""
        
        anomaly_features = self._extract_network_anomaly_features(
            network_data, features
        )
        
        await self._update_network_history(anomaly_features)
        
        anomaly_score, is_anomaly = await self._detect_anomaly(
            "network", anomaly_features
        )
        
        confidence = abs(anomaly_score)
        threat_detected = is_anomaly and confidence > self.thresholds["network_anomaly"]
        
        if threat_detected:
            threat_level = "high" if confidence > 0.8 else "suspicious"
        else:
            threat_level = "normal"
        
        return {
            "threat_detected": threat_detected,
            "confidence": confidence,
            "threat_level": threat_level,
            "detection_type": "unsupervised_anomaly",
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "features_analyzed": list(anomaly_features.keys()),
            "timestamp": datetime.now().isoformat()
        }

    def _extract_file_anomaly_features(self, event_type: str, file_path: str,
                                     features: Dict[str, Any]) -> Dict[str, float]:
        """Extract features for file anomaly detection"""
        file_ext = self._get_file_extension(file_path)
        
        return {
            "event_frequency": features.get("event_frequency", 0),
            "file_entropy": features.get("entropy", 0),
            "size_change_ratio": features.get("size_change_ratio", 0),
            "modification_rate": features.get("modification_rate", 0),
            "unique_extensions": features.get("unique_extensions_count", 0),
            "suspicious_operations": features.get("suspicious_operations", 0),
            "temporal_clustering": features.get("temporal_clustering", 0),
            "access_pattern_entropy": features.get("access_pattern_entropy", 0)
        }

    def _extract_process_anomaly_features(self, process_data: Dict[str, Any],
                                        features: Dict[str, Any]) -> Dict[str, float]:
        """Extract features for process anomaly detection"""
        return {
            "cpu_usage_anomaly": features.get("cpu_usage_anomaly", 0),
            "memory_usage_anomaly": features.get("memory_usage_anomaly", 0),
            "process_lifetime": features.get("process_lifetime", 0),
            "child_process_anomaly": features.get("child_process_anomaly", 0),
            "io_activity_anomaly": features.get("io_activity_anomaly", 0),
            "network_activity_anomaly": features.get("network_activity_anomaly", 0),
            "execution_path_anomaly": features.get("execution_path_anomaly", 0),
            "user_context_anomaly": features.get("user_context_anomaly", 0)
        }

    def _extract_network_anomaly_features(self, network_data: Dict[str, Any],
                                        features: Dict[str, Any]) -> Dict[str, float]:
        """Extract features for network anomaly detection"""
        return {
            "connection_frequency": features.get("connection_frequency", 0),
            "port_entropy": features.get("port_entropy", 0),
            "data_volume_anomaly": features.get("data_volume_anomaly", 0),
            "protocol_anomaly": features.get("protocol_anomaly", 0),
            "geographic_anomaly": features.get("geographic_anomaly", 0),
            "temporal_anomaly": features.get("temporal_anomaly", 0),
            "dns_query_anomaly": features.get("dns_query_anomaly", 0),
            "session_duration_anomaly": features.get("session_duration_anomaly", 0)
        }

    async def _update_file_history(self, features: Dict[str, float]):
        """Update file feature history"""
        self.feature_history["file"].append(features)
        if len(self.feature_history["file"]) > self.history_window:
            self.feature_history["file"] = self.feature_history["file"][-self.history_window:]
        
        # Retrain model periodically
        if len(self.feature_history["file"]) % 100 == 0:
            await self._retrain_model("file")

    async def _update_process_history(self, features: Dict[str, float]):
        """Update process feature history"""
        self.feature_history["process"].append(features)
        if len(self.feature_history["process"]) > self.history_window:
            self.feature_history["process"] = self.feature_history["process"][-self.history_window:]
        
        if len(self.feature_history["process"]) % 100 == 0:
            await self._retrain_model("process")

    async def _update_network_history(self, features: Dict[str, float]):
        """Update network feature history"""
        self.feature_history["network"].append(features)
        if len(self.feature_history["network"]) > self.history_window:
            self.feature_history["network"] = self.feature_history["network"][-self.history_window:]
        
        if len(self.feature_history["network"]) % 100 == 0:
            await self._retrain_model("network")

    async def _detect_anomaly(self, data_type: str, features: Dict[str, float]) -> Tuple[float, bool]:
        """Detect anomaly using Isolation Forest"""
        try:
            model = self.models[data_type]
            scaler = self.scalers[data_type]
            
            # Convert features to array
            feature_array = np.array([list(features.values())])
            
            # Scale features
            if len(self.feature_history[data_type]) > 10:
                # Fit scaler on history
                history_array = np.array([list(f.values()) for f in self.feature_history[data_type]])
                scaler.fit(history_array)
                scaled_features = scaler.transform(feature_array)
            else:
                scaled_features = feature_array
            
            # Get anomaly score
            anomaly_score = model.decision_function(scaled_features)[0]
            is_anomaly = model.predict(scaled_features)[0] == -1
            
            return anomaly_score, is_anomaly
            
        except Exception as e:
            print(f"Anomaly detection error for {data_type}: {e}")
            return 0.0, False

    async def _retrain_model(self, data_type: str):
        """Retrain anomaly detection model with new data"""
        try:
            if len(self.feature_history[data_type]) < 50:
                return  # Not enough data
            
            # Convert history to array
            history_array = np.array([list(f.values()) for f in self.feature_history[data_type]])
            
            # Scale features
            scaler = self.scalers[data_type]
            scaled_features = scaler.fit_transform(history_array)
            
            # Retrain model
            model = self.models[data_type]
            model.fit(scaled_features)
            
            print(f"🔄 Retrained {data_type} anomaly detection model")
            
        except Exception as e:
            print(f"Model retraining error for {data_type}: {e}")

    def _get_file_extension(self, file_path: str) -> str:
        """Get file extension in lowercase"""
        import os
        return os.path.splitext(file_path)[1].lower()

    async def get_anomaly_statistics(self) -> Dict[str, Any]:
        """Get anomaly detection statistics"""
        stats = {}
        for data_type in ["file", "process", "network"]:
            history_size = len(self.feature_history[data_type])
            stats[data_type] = {
                "history_size": history_size,
                "model_trained": history_size >= 50,
                "last_retrain": datetime.now().isoformat()
            }
        return stats