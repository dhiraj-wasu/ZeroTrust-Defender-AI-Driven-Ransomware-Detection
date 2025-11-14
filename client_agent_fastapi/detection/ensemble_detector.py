import numpy as np
from typing import Dict, List, Any, Tuple
import asyncio
from datetime import datetime

class EnsembleDetector:
    def __init__(self):
        self.layer_weights = {
            "supervised": 0.35,    # Highest weight for ML models
            "anomaly": 0.25,       # Good for novel threats
            "rules": 0.25,         # Good for known patterns
            "slow_ransomware": 0.15 # Lower weight but important for stealth
        }
        
        self.confidence_thresholds = {
            "critical": 0.85,
            "high": 0.70,
            "suspicious": 0.55,
            "normal": 0.0
        }
        
        self.ensemble_history = []
        self.max_history_size = 1000

    async def fuse_detections(self, supervised_result: Dict[str, Any],
                            anomaly_result: Dict[str, Any],
                            rule_result: Dict[str, Any],
                            slow_result: Dict[str, Any]) -> Dict[str, Any]:
        """Fuse detections from all four layers using weighted ensemble"""
        
        # Extract confidence scores from each layer
        supervised_confidence = supervised_result.get("confidence", 0.0)
        anomaly_confidence = anomaly_result.get("confidence", 0.0)
        rule_confidence = rule_result.get("confidence", 0.0)
        slow_confidence = slow_result.get("confidence", 0.0)
        
        # Apply layer weights
        weighted_supervised = supervised_confidence * self.layer_weights["supervised"]
        weighted_anomaly = anomaly_confidence * self.layer_weights["anomaly"]
        weighted_rules = rule_confidence * self.layer_weights["rules"]
        weighted_slow = slow_confidence * self.layer_weights["slow_ransomware"]
        
        # Calculate ensemble confidence
        ensemble_confidence = weighted_supervised + weighted_anomaly + weighted_rules + weighted_slow
        
        # Determine threat detection and level
        threat_detected = ensemble_confidence > self.confidence_thresholds["suspicious"]
        threat_level = self._determine_threat_level(ensemble_confidence)
        
        # Identify primary detection layer
        primary_layer = self._identify_primary_layer(
            supervised_confidence, anomaly_confidence, rule_confidence, slow_confidence
        )
        
        # Calculate layer agreement
        layer_agreement = self._calculate_layer_agreement(
            supervised_result, anomaly_result, rule_result, slow_result
        )
        
        ensemble_result = {
            "threat_detected": threat_detected,
            "confidence": ensemble_confidence,
            "threat_level": threat_level,
            "primary_layer": primary_layer,
            "layer_agreement": layer_agreement,
            "weighted_scores": {
                "supervised": weighted_supervised,
                "anomaly": weighted_anomaly,
                "rules": weighted_rules,
                "slow_ransomware": weighted_slow
            },
            "raw_scores": {
                "supervised": supervised_confidence,
                "anomaly": anomaly_confidence,
                "rules": rule_confidence,
                "slow_ransomware": slow_confidence
            },
            "timestamp": datetime.now().isoformat()
        }
        
        # Store in history
        self._update_ensemble_history(ensemble_result)
        
        return ensemble_result

    async def analyze_ensemble(self, feature_history: List[Dict]) -> Dict[str, Any]:
        """Perform ensemble analysis on recent feature history"""
        if len(feature_history) < 10:
            return {
                "threat_detected": False,
                "confidence": 0.0,
                "threat_level": "normal",
                "primary_layer": "none",
                "timestamp": datetime.now().isoformat()
            }
        
        # Analyze trends across detection layers
        trend_analysis = await self._analyze_ensemble_trends()
        
        # Calculate ensemble confidence from trends
        ensemble_confidence = trend_analysis.get("overall_trend", 0.0)
        
        threat_detected = ensemble_confidence > self.confidence_thresholds["suspicious"]
        threat_level = self._determine_threat_level(ensemble_confidence)
        
        return {
            "threat_detected": threat_detected,
            "confidence": ensemble_confidence,
            "threat_level": threat_level,
            "primary_layer": "ensemble_trend",
            "trend_analysis": trend_analysis,
            "timestamp": datetime.now().isoformat()
        }

    def _determine_threat_level(self, confidence: float) -> str:
        """Determine threat level based on confidence score"""
        if confidence >= self.confidence_thresholds["critical"]:
            return "critical"
        elif confidence >= self.confidence_thresholds["high"]:
            return "high"
        elif confidence >= self.confidence_thresholds["suspicious"]:
            return "suspicious"
        else:
            return "normal"

    def _identify_primary_layer(self, supervised_conf: float, anomaly_conf: float,
                              rules_conf: float, slow_conf: float) -> str:
        """Identify which detection layer contributed most"""
        scores = {
            "supervised": supervised_conf,
            "anomaly": anomaly_conf,
            "rules": rules_conf,
            "slow_ransomware": slow_conf
        }
        
        primary_layer = max(scores, key=scores.get)
        return primary_layer if scores[primary_layer] > 0.1 else "none"

    def _calculate_layer_agreement(self, supervised_result: Dict[str, Any],
                                 anomaly_result: Dict[str, Any],
                                 rule_result: Dict[str, Any],
                                 slow_result: Dict[str, Any]) -> float:
        """Calculate agreement between detection layers"""
        layer_results = [
            supervised_result.get("threat_detected", False),
            anomaly_result.get("threat_detected", False),
            rule_result.get("threat_detected", False),
            slow_result.get("threat_detected", False)
        ]
        
        # Count agreements
        true_count = sum(layer_results)
        false_count = len(layer_results) - true_count
        
        # Calculate agreement ratio
        max_agreement = max(true_count, false_count)
        agreement_ratio = max_agreement / len(layer_results)
        
        return agreement_ratio

    async def _analyze_ensemble_trends(self) -> Dict[str, Any]:
        """Analyze trends across ensemble detection history"""
        if len(self.ensemble_history) < 20:
            return {"overall_trend": 0.0, "trend_strength": 0.0}
        
        # Extract recent confidence scores
        recent_scores = [result["confidence"] for result in self.ensemble_history[-20:]]
        
        # Calculate trend
        trend = self._calculate_confidence_trend(recent_scores)
        trend_strength = abs(trend)
        
        # Analyze threat level distribution
        threat_levels = [result["threat_level"] for result in self.ensemble_history[-20:]]
        threat_distribution = self._analyze_threat_distribution(threat_levels)
        
        return {
            "overall_trend": trend,
            "trend_strength": trend_strength,
            "threat_distribution": threat_distribution,
            "recent_detections": len(recent_scores)
        }

    def _calculate_confidence_trend(self, confidence_scores: List[float]) -> float:
        """Calculate trend in confidence scores"""
        if len(confidence_scores) < 2:
            return 0.0
        
        x = np.arange(len(confidence_scores))
        y = np.array(confidence_scores)
        
        try:
            slope = np.polyfit(x, y, 1)[0]
            # Normalize slope to [-1, 1] range
            normalized_slope = slope / (max(y) - min(y)) if max(y) != min(y) else 0.0
            return normalized_slope
        except:
            return 0.0

    def _analyze_threat_distribution(self, threat_levels: List[str]) -> Dict[str, float]:
        """Analyze distribution of threat levels"""
        level_counts = {
            "critical": 0,
            "high": 0,
            "suspicious": 0,
            "normal": 0
        }
        
        for level in threat_levels:
            if level in level_counts:
                level_counts[level] += 1
        
        total = len(threat_levels)
        distribution = {}
        for level, count in level_counts.items():
            distribution[level] = count / total if total > 0 else 0.0
        
        return distribution

    def _update_ensemble_history(self, ensemble_result: Dict[str, Any]):
        """Update ensemble detection history"""
        self.ensemble_history.append(ensemble_result)
        if len(self.ensemble_history) > self.max_history_size:
            self.ensemble_history = self.ensemble_history[-self.max_history_size:]

    async def adjust_layer_weights(self, performance_metrics: Dict[str, float]):
        """Adjust layer weights based on performance metrics"""
        # This method would adjust weights based on historical performance
        # For now, we use fixed weights
        pass

    async def get_ensemble_statistics(self) -> Dict[str, Any]:
        """Get ensemble detection statistics"""
        if not self.ensemble_history:
            return {"total_detections": 0, "average_confidence": 0.0}
        
        total_detections = len(self.ensemble_history)
        average_confidence = sum(r["confidence"] for r in self.ensemble_history) / total_detections
        
        # Count detections by primary layer
        layer_counts = {}
        for result in self.ensemble_history:
            layer = result.get("primary_layer", "unknown")
            layer_counts[layer] = layer_counts.get(layer, 0) + 1
        
        return {
            "total_detections": total_detections,
            "average_confidence": average_confidence,
            "detections_by_layer": layer_counts,
            "confidence_thresholds": self.confidence_thresholds,
            "layer_weights": self.layer_weights
        }