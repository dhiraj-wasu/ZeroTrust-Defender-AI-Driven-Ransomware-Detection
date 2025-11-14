import numpy as np
import pandas as pd
import pickle
import os
from datetime import datetime
from typing import Dict, Any, List
import asyncio
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import SVC
import xgboost as xgb
import joblib

class SupervisedDetector:
    def __init__(self):
        self.models = {}
        self.model_versions = {}
        self.feature_scalers = {}
        self.model_directory = "data/models/supervised"
        
        # Ensure model directory exists
        os.makedirs(self.model_directory, exist_ok=True)
        
        # Default models (will be replaced with trained models)
        self.default_models = {
            "file_ransomware": self._create_default_model(),
            "process_malware": self._create_default_model(),
            "network_anomaly": self._create_default_model()
        }

    def _create_default_model(self):
        """Create a default random forest model"""
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )

    async def load_models(self):
        """Load trained ML models"""
        print("📊 Loading supervised ML models...")
        
        model_files = {
            "file_ransomware": "file_ransomware_model.pkl",
            "process_malware": "process_malware_model.pkl", 
            "network_anomaly": "network_anomaly_model.pkl"
        }
        
        for model_name, filename in model_files.items():
            model_path = os.path.join(self.model_directory, filename)
            if os.path.exists(model_path):
                try:
                    self.models[model_name] = joblib.load(model_path)
                    self.model_versions[model_name] = "1.0.0"
                    print(f"✅ Loaded {model_name} model")
                except Exception as e:
                    print(f"❌ Failed to load {model_name} model: {e}")
                    self.models[model_name] = self.default_models[model_name]
            else:
                print(f"⚠️ No trained model for {model_name}, using default")
                self.models[model_name] = self.default_models[model_name]

    async def detect_file_threat(self, event_type: str, file_path: str, 
                               features: Dict[str, Any]) -> Dict[str, Any]:
        """Detect file-based threats using supervised ML"""
        
        # Extract features for ML model
        ml_features = self._extract_file_ml_features(event_type, file_path, features)
        
        # Get prediction from model
        model = self.models.get("file_ransomware")
        if model:
            try:
                # Convert features to numpy array
                feature_array = np.array([list(ml_features.values())])
                
                # Get prediction probability
                if hasattr(model, 'predict_proba'):
                    probability = model.predict_proba(feature_array)[0][1]
                else:
                    prediction = model.predict(feature_array)[0]
                    probability = float(prediction)
                
                threat_detected = probability > 0.7
                confidence = probability
                threat_level = "critical" if probability > 0.9 else "high" if probability > 0.7 else "suspicious"
                
            except Exception as e:
                print(f"ML prediction error: {e}")
                threat_detected = False
                confidence = 0.0
                threat_level = "normal"
        else:
            threat_detected = False
            confidence = 0.0
            threat_level = "normal"
        
        return {
            "threat_detected": threat_detected,
            "confidence": confidence,
            "threat_level": threat_level,
            "detection_type": "supervised_ml",
            "model_version": self.model_versions.get("file_ransomware", "default"),
            "features_used": list(ml_features.keys()),
            "timestamp": datetime.now().isoformat()
        }

    async def detect_process_threat(self, process_data: Dict[str, Any], 
                                  features: Dict[str, Any]) -> Dict[str, Any]:
        """Detect process-based threats using supervised ML"""
        
        ml_features = self._extract_process_ml_features(process_data, features)
        
        model = self.models.get("process_malware")
        if model:
            try:
                feature_array = np.array([list(ml_features.values())])
                
                if hasattr(model, 'predict_proba'):
                    probability = model.predict_proba(feature_array)[0][1]
                else:
                    prediction = model.predict(feature_array)[0]
                    probability = float(prediction)
                
                threat_detected = probability > 0.7
                confidence = probability
                threat_level = "critical" if probability > 0.9 else "high" if probability > 0.7 else "suspicious"
                
            except Exception as e:
                print(f"Process ML prediction error: {e}")
                threat_detected = False
                confidence = 0.0
                threat_level = "normal"
        else:
            threat_detected = False
            confidence = 0.0
            threat_level = "normal"
        
        return {
            "threat_detected": threat_detected,
            "confidence": confidence,
            "threat_level": threat_level,
            "detection_type": "supervised_ml",
            "model_version": self.model_versions.get("process_malware", "default"),
            "features_used": list(ml_features.keys()),
            "timestamp": datetime.now().isoformat()
        }

    async def detect_network_threat(self, network_data: Dict[str, Any], 
                                  features: Dict[str, Any]) -> Dict[str, Any]:
        """Detect network-based threats using supervised ML"""
        
        ml_features = self._extract_network_ml_features(network_data, features)
        
        model = self.models.get("network_anomaly")
        if model:
            try:
                feature_array = np.array([list(ml_features.values())])
                
                if hasattr(model, 'predict_proba'):
                    probability = model.predict_proba(feature_array)[0][1]
                else:
                    prediction = model.predict(feature_array)[0]
                    probability = float(prediction)
                
                threat_detected = probability > 0.6
                confidence = probability
                threat_level = "high" if probability > 0.8 else "suspicious" if probability > 0.6 else "normal"
                
            except Exception as e:
                print(f"Network ML prediction error: {e}")
                threat_detected = False
                confidence = 0.0
                threat_level = "normal"
        else:
            threat_detected = False
            confidence = 0.0
            threat_level = "normal"
        
        return {
            "threat_detected": threat_detected,
            "confidence": confidence,
            "threat_level": threat_level,
            "detection_type": "supervised_ml",
            "model_version": self.model_versions.get("network_anomaly", "default"),
            "features_used": list(ml_features.keys()),
            "timestamp": datetime.now().isoformat()
        }

    def _extract_file_ml_features(self, event_type: str, file_path: str, 
                                features: Dict[str, Any]) -> Dict[str, float]:
        """Extract features for file ML model"""
        file_ext = self._get_file_extension(file_path)
        
        return {
            "event_type_encoded": self._encode_event_type(event_type),
            "file_size": features.get("file_size", 0),
            "entropy": features.get("entropy", 0),
            "is_executable": 1.0 if file_ext in ['.exe', '.dll', '.bat'] else 0.0,
            "is_document": 1.0 if file_ext in ['.doc', '.docx', '.pdf', '.xls'] else 0.0,
            "suspicious_extension": 1.0 if self._is_suspicious_extension(file_ext) else 0.0,
            "modification_frequency": features.get("modification_frequency", 0),
            "file_age_hours": features.get("file_age_hours", 0),
            "parent_process_suspicious": features.get("parent_process_suspicious", 0),
            "recent_encryption_activity": features.get("recent_encryption_activity", 0)
        }

    def _extract_process_ml_features(self, process_data: Dict[str, Any], 
                                   features: Dict[str, Any]) -> Dict[str, float]:
        """Extract features for process ML model"""
        return {
            "cpu_usage": process_data.get("cpu", 0),
            "memory_usage": process_data.get("memory", 0),
            "process_age_seconds": features.get("process_age_seconds", 0),
            "is_system_process": features.get("is_system_process", 0),
            "has_network_activity": features.get("has_network_activity", 0),
            "child_process_count": features.get("child_process_count", 0),
            "suspicious_name": features.get("suspicious_name", 0),
            "unusual_working_directory": features.get("unusual_working_directory", 0),
            "high_io_activity": features.get("high_io_activity", 0),
            "unusual_execution_time": features.get("unusual_execution_time", 0)
        }

    def _extract_network_ml_features(self, network_data: Dict[str, Any], 
                                   features: Dict[str, Any]) -> Dict[str, float]:
        """Extract features for network ML model"""
        return {
            "remote_port": features.get("remote_port", 0),
            "is_smb_port": 1.0 if features.get("remote_port", 0) == 445 else 0.0,
            "is_rdp_port": 1.0 if features.get("remote_port", 0) == 3389 else 0.0,
            "connection_duration": features.get("connection_duration", 0),
            "data_transferred": features.get("data_transferred", 0),
            "unusual_protocol": features.get("unusual_protocol", 0),
            "multiple_connections": features.get("multiple_connections", 0),
            "foreign_country": features.get("foreign_country", 0),
            "encrypted_traffic": features.get("encrypted_traffic", 0),
            "suspicious_dns": features.get("suspicious_dns", 0)
        }

    def _encode_event_type(self, event_type: str) -> float:
        """Encode event type as numerical value"""
        encoding = {
            'created': 1.0,
            'modified': 2.0, 
            'deleted': 3.0,
            'renamed': 4.0
        }
        return encoding.get(event_type, 0.0)

    def _get_file_extension(self, file_path: str) -> str:
        """Get file extension in lowercase"""
        return os.path.splitext(file_path)[1].lower()

    def _is_suspicious_extension(self, file_ext: str) -> bool:
        """Check if file extension is suspicious"""
        suspicious_extensions = [
            '.encrypted', '.locked', '.crypto', '.ransom', '.wncry',
            '.cryptolocker', '.cryptowall', '.cerber'
        ]
        return file_ext in suspicious_extensions

    async def train_model(self, training_data: List[Dict], model_type: str) -> bool:
        """Train a new supervised model (API endpoint)"""
        try:
            # Extract features and labels
            features = []
            labels = []
            
            for data_point in training_data:
                features.append(list(data_point["features"].values()))
                labels.append(data_point["is_malicious"])
            
            X = np.array(features)
            y = np.array(labels)
            
            # Train model
            model = RandomForestClassifier(n_estimators=100, random_state=42)
            model.fit(X, y)
            
            # Save model
            model_path = os.path.join(self.model_directory, f"{model_type}_model.pkl")
            joblib.dump(model, model_path)
            
            # Update loaded model
            self.models[model_type] = model
            self.model_versions[model_type] = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            print(f"✅ Trained and saved {model_type} model")
            return True
            
        except Exception as e:
            print(f"❌ Model training failed: {e}")
            return False