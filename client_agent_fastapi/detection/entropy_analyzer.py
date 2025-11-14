import math
import os
import numpy as np
from typing import Dict, Any, Optional
from collections import deque
import asyncio

class EntropyAnalyzer:
    """Advanced entropy analysis for encryption detection"""
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.entropy_history = deque(maxlen=window_size)
        self.baseline_entropy = 0.0
        self.baseline_calculated = False
        
        # Entropy thresholds for different file types
        self.entropy_thresholds = {
            'text': 4.5,      # Low entropy for text files
            'executable': 6.0, # Medium entropy for executables
            'encrypted': 7.5,  # High entropy for encrypted files
            'compressed': 7.0  # High entropy for compressed files
        }
        
        # File type patterns
        self.file_patterns = {
            'text': ['.txt', '.log', '.csv', '.json', '.xml', '.html', '.css', '.js'],
            'executable': ['.exe', '.dll', '.so', '.bin', '.app'],
            'document': ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx'],
            'media': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp4', '.avi', '.mp3'],
            'compressed': ['.zip', '.rar', '.7z', '.tar', '.gz']
        }

    async def calculate_file_entropy(self, file_path: str, sample_size: int = 1048576) -> Optional[float]:
        """Calculate file entropy with efficient sampling"""
        try:
            if not os.path.exists(file_path) or os.path.isdir(file_path):
                return None
            
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return 0.0
            
            # Use smaller sample for large files
            actual_sample_size = min(file_size, sample_size)
            
            with open(file_path, 'rb') as f:
                data = f.read(actual_sample_size)
            
            if not data:
                return 0.0
            
            return self._calculate_data_entropy(data)
            
        except Exception as e:
            print(f"Entropy calculation error for {file_path}: {e}")
            return None

    def _calculate_data_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Calculate byte frequency
        byte_counts = np.zeros(256, dtype=np.int64)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate probabilities and entropy
        probabilities = byte_counts / len(data)
        entropy = 0.0
        
        for prob in probabilities:
            if prob > 0:
                entropy -= prob * math.log2(prob)
        
        return entropy

    async def analyze_entropy_pattern(self, file_path: str, current_entropy: float) -> Dict[str, Any]:
        """Analyze entropy patterns for ransomware detection"""
        
        file_type = self._classify_file_type(file_path)
        expected_entropy = self.entropy_thresholds.get(file_type, 5.0)
        
        # Update entropy history
        self.entropy_history.append(current_entropy)
        
        # Calculate baseline if we have enough data
        if len(self.entropy_history) >= 100 and not self.baseline_calculated:
            self.baseline_entropy = np.mean(list(self.entropy_history))
            self.baseline_calculated = True
        
        # Analyze entropy anomalies
        analysis = {
            'current_entropy': current_entropy,
            'file_type': file_type,
            'expected_entropy': expected_entropy,
            'entropy_ratio': current_entropy / expected_entropy if expected_entropy > 0 else 0,
            'is_suspicious': False,
            'confidence': 0.0,
            'anomaly_type': 'normal'
        }
        
        # Check for suspicious entropy levels
        if current_entropy > self.entropy_thresholds['encrypted']:
            analysis.update({
                'is_suspicious': True,
                'confidence': min(1.0, (current_entropy - expected_entropy) / 3.0),
                'anomaly_type': 'high_entropy'
            })
        
        # Check for entropy spikes compared to baseline
        elif self.baseline_calculated and current_entropy > self.baseline_entropy * 1.5:
            analysis.update({
                'is_suspicious': True,
                'confidence': 0.7,
                'anomaly_type': 'entropy_spike'
            })
        
        # Check for inconsistent entropy (text files with high entropy)
        elif file_type == 'text' and current_entropy > self.entropy_thresholds['text']:
            analysis.update({
                'is_suspicious': True,
                'confidence': 0.6,
                'anomaly_type': 'inconsistent_entropy'
            })
        
        return analysis

    def _classify_file_type(self, file_path: str) -> str:
        """Classify file type based on extension"""
        file_ext = os.path.splitext(file_path)[1].lower()
        
        for file_type, extensions in self.file_patterns.items():
            if file_ext in extensions:
                return file_type
        
        return 'unknown'

    async def detect_mass_entropy_changes(self, file_entropies: Dict[str, float]) -> Dict[str, Any]:
        """Detect mass entropy changes indicative of ransomware"""
        if len(file_entropies) < 5:
            return {'is_mass_change': False, 'confidence': 0.0}
        
        high_entropy_files = 0
        total_files = len(file_entropies)
        
        for file_path, entropy in file_entropies.items():
            file_type = self._classify_file_type(file_path)
            expected_entropy = self.entropy_thresholds.get(file_type, 5.0)
            
            if entropy > expected_entropy * 1.3:  # 30% higher than expected
                high_entropy_files += 1
        
        high_entropy_ratio = high_entropy_files / total_files
        
        analysis = {
            'is_mass_change': high_entropy_ratio > 0.3,  # 30% of files have high entropy
            'confidence': min(1.0, high_entropy_ratio * 2),  # Scale to 0-1
            'high_entropy_files': high_entropy_files,
            'total_files': total_files,
            'high_entropy_ratio': high_entropy_ratio
        }
        
        return analysis

    async def calculate_rolling_entropy(self, new_entropy: float) -> Dict[str, Any]:
        """Calculate rolling entropy statistics"""
        self.entropy_history.append(new_entropy)
        
        if len(self.entropy_history) < 10:
            return {
                'mean': new_entropy,
                'std_dev': 0.0,
                'trend': 0.0,
                'volatility': 0.0
            }
        
        entropy_array = np.array(list(self.entropy_history))
        
        # Calculate basic statistics
        mean_entropy = np.mean(entropy_array)
        std_dev = np.std(entropy_array)
        
        # Calculate trend (slope of last 20 points)
        if len(entropy_array) >= 20:
            x = np.arange(len(entropy_array[-20:]))
            y = entropy_array[-20:]
            trend = np.polyfit(x, y, 1)[0]
        else:
            trend = 0.0
        
        # Calculate volatility (rate of change)
        volatility = np.std(np.diff(entropy_array)) if len(entropy_array) > 1 else 0.0
        
        return {
            'mean': mean_entropy,
            'std_dev': std_dev,
            'trend': trend,
            'volatility': volatility,
            'history_size': len(self.entropy_history)
        }

    def get_entropy_statistics(self) -> Dict[str, Any]:
        """Get current entropy analysis statistics"""
        if not self.entropy_history:
            return {'history_size': 0, 'baseline_calculated': False}
        
        entropy_array = np.array(list(self.entropy_history))
        
        return {
            'history_size': len(self.entropy_history),
            'current_entropy': self.entropy_history[-1] if self.entropy_history else 0.0,
            'mean_entropy': np.mean(entropy_array),
            'max_entropy': np.max(entropy_array),
            'min_entropy': np.min(entropy_array),
            'baseline_entropy': self.baseline_entropy,
            'baseline_calculated': self.baseline_calculated
        }

    async def reset_baseline(self):
        """Reset entropy baseline"""
        self.baseline_calculated = False
        self.baseline_entropy = 0.0
        self.entropy_history.clear()
        print("🔄 Entropy baseline reset")

# Global entropy analyzer instance
entropy_analyzer = EntropyAnalyzer() 