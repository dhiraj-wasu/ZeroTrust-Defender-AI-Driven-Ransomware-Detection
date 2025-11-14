import asyncio
import json
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Optional
import psutil

from .supervised_detector import SupervisedDetector
from .anomaly_detector import AnomalyDetector
from .rule_engine import RuleEngine
from .slow_ransomware_detector import SlowRansomwareDetector
from .ensemble_detector import EnsembleDetector

class QuadLayerDetector:
    def __init__(self):
        self.supervised_detector = SupervisedDetector()
        self.anomaly_detector = AnomalyDetector()
        self.rule_engine = RuleEngine()
        self.slow_detector = SlowRansomwareDetector()
        self.ensemble_detector = EnsembleDetector()
        
        self.detection_history = []
        self.max_history_size = 1000

    async def initialize_detectors(self):
        """Initialize all detection layers"""
        print("🔄 Initializing Quad-Layer Detection Engine...")
        
        await self.supervised_detector.load_models()
        await self.anomaly_detector.initialize_models()
        await self.rule_engine.load_rules()
        await self.slow_detector.initialize_detector()
        
        print("✅ Quad-Layer Detection Engine initialized")

    async def analyze_file_event(self, event_type: str, file_path: str, 
                               features: Dict, feature_history: List[Dict]) -> Dict[str, Any]:
        """Analyze file event through all four detection layers"""
        
        # Layer 1: Supervised ML Detection
        supervised_result = await self.supervised_detector.detect_file_threat(
            event_type, file_path, features
        )
        
        # Layer 2: Unsupervised Anomaly Detection
        anomaly_result = await self.anomaly_detector.detect_file_anomaly(
            event_type, file_path, features, feature_history
        )
        
        # Layer 3: Rule-based Heuristics
        rule_result = await self.rule_engine.analyze_file_event(
            event_type, file_path, features
        )
        
        # Layer 4: Slow Ransomware Detection
        slow_result = await self.slow_detector.analyze_file_patterns(
            feature_history, current_features=features
        )
        
        # Ensemble decision
        ensemble_result = await self.ensemble_detector.fuse_detections(
            supervised_result, anomaly_result, rule_result, slow_result
        )
        
        # Compile comprehensive result
        detection_result = {
            "threat_detected": ensemble_result["threat_detected"],
            "threat_level": ensemble_result["threat_level"],
            "confidence": ensemble_result["confidence"],
            "primary_detection_layer": ensemble_result["primary_layer"],
            "all_layer_results": {
                "supervised": supervised_result,
                "anomaly": anomaly_result,
                "rules": rule_result,
                "slow_ransomware": slow_result
            },
            "event_type": event_type,
            "file_path": file_path,
            "timestamp": datetime.now().isoformat(),
            "features": features
        }
        
        # Store in history
        self._update_detection_history(detection_result)
        
        return detection_result

    async def analyze_process_event(self, process_data: Dict, 
                                  features: Dict, feature_history: List[Dict]) -> Dict[str, Any]:
        """Analyze process event through all four detection layers"""
        
        # Layer 1: Supervised ML Detection
        supervised_result = await self.supervised_detector.detect_process_threat(
            process_data, features
        )
        
        # Layer 2: Unsupervised Anomaly Detection
        anomaly_result = await self.anomaly_detector.detect_process_anomaly(
            process_data, features, feature_history
        )
        
        # Layer 3: Rule-based Heuristics
        rule_result = await self.rule_engine.analyze_process_event(
            process_data, features
        )
        
        # Layer 4: Slow Ransomware Detection
        slow_result = await self.slow_detector.analyze_process_patterns(
            feature_history, current_process=process_data
        )
        
        # Ensemble decision
        ensemble_result = await self.ensemble_detector.fuse_detections(
            supervised_result, anomaly_result, rule_result, slow_result
        )
        
        detection_result = {
            "threat_detected": ensemble_result["threat_detected"],
            "threat_level": ensemble_result["threat_level"],
            "confidence": ensemble_result["confidence"],
            "primary_detection_layer": ensemble_result["primary_layer"],
            "all_layer_results": {
                "supervised": supervised_result,
                "anomaly": anomaly_result,
                "rules": rule_result,
                "slow_ransomware": slow_result
            },
            "process_data": process_data,
            "timestamp": datetime.now().isoformat(),
            "features": features
        }
        
        self._update_detection_history(detection_result)
        return detection_result

    async def analyze_network_event(self, network_data: Dict, 
                                  features: Dict, feature_history: List[Dict]) -> Dict[str, Any]:
        """Analyze network event through all four detection layers"""
        
        # Layer 1: Supervised ML Detection
        supervised_result = await self.supervised_detector.detect_network_threat(
            network_data, features
        )
        
        # Layer 2: Unsupervised Anomaly Detection
        anomaly_result = await self.anomaly_detector.detect_network_anomaly(
            network_data, features, feature_history
        )
        
        # Layer 3: Rule-based Heuristics
        rule_result = await self.rule_engine.analyze_network_event(
            network_data, features
        )
        
        # Layer 4: Slow Ransomware Detection
        slow_result = await self.slow_detector.analyze_network_patterns(
            feature_history, current_network=network_data
        )
        
        # Ensemble decision
        ensemble_result = await self.ensemble_detector.fuse_detections(
            supervised_result, anomaly_result, rule_result, slow_result
        )
        
        detection_result = {
            "threat_detected": ensemble_result["threat_detected"],
            "threat_level": ensemble_result["threat_level"],
            "confidence": ensemble_result["confidence"],
            "primary_detection_layer": ensemble_result["primary_layer"],
            "all_layer_results": {
                "supervised": supervised_result,
                "anomaly": anomaly_result,
                "rules": rule_result,
                "slow_ransomware": slow_result
            },
            "network_data": network_data,
            "timestamp": datetime.now().isoformat(),
            "features": features
        }
        
        self._update_detection_history(detection_result)
        return detection_result

    def _update_detection_history(self, detection_result: Dict):
        """Update detection history"""
        self.detection_history.append(detection_result)
        if len(self.detection_history) > self.max_history_size:
            self.detection_history = self.detection_history[-self.max_history_size:]

    async def get_detection_analytics(self) -> Dict[str, Any]:
        """Get detection analytics and performance metrics"""
        if not self.detection_history:
            return {"total_detections": 0, "layer_breakdown": {}}
        
        layer_counts = {}
        threat_levels = {}
        
        for detection in self.detection_history:
            layer = detection.get("primary_detection_layer", "unknown")
            threat_level = detection.get("threat_level", "unknown")
            
            layer_counts[layer] = layer_counts.get(layer, 0) + 1
            threat_levels[threat_level] = threat_levels.get(threat_level, 0) + 1
        
        return {
            "total_detections": len(self.detection_history),
            "layer_breakdown": layer_counts,
            "threat_level_breakdown": threat_levels,
            "recent_detections": self.detection_history[-10:]  # Last 10 detections
        }

    def terminate_suspicious_process(self, process_name: str) -> bool:
        """Terminate suspicious processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
                    proc.terminate()
                    return True
        except Exception as e:
            print(f"Error terminating process {process_name}: {e}")
        return False