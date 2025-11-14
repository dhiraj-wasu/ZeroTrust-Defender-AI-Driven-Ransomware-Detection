from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    SUSPICIOUS = "suspicious"
    LOW = "low"
    NORMAL = "normal"

class DetectionLayer(str, Enum):
    SUPERVISED = "supervised"
    ANOMALY = "anomaly"
    RULES = "rules"
    SLOW_RANSOMWARE = "slow_ransomware"
    ENSEMBLE = "ensemble"

class DemoConfig(BaseModel):
    """Configuration for demo setup"""
    monitor_directory: str = Field(..., description="Directory to monitor for threats")
    backup_directory: str = Field(..., description="Directory for storing backups")
    important_folders: List[str] = Field(default=[], description="Important subfolders for priority protection")

class ThreatSimulation(BaseModel):
    """Threat simulation request"""
    threat_type: str = Field(..., description="Type of threat to simulate")
    threat_level: ThreatLevel = Field(default=ThreatLevel.CRITICAL, description="Threat level for simulation")
    confidence: float = Field(default=0.95, ge=0.0, le=1.0, description="Detection confidence")
    malware_process: str = Field(default="crypto_locker.exe", description="Malware process name")
    files_modified: int = Field(default=50, description="Number of files modified in simulation")

class CommandExecution(BaseModel):
    """Command execution request"""
    commands: List[str] = Field(..., description="Commands to execute")
    incident_id: Optional[str] = Field(default=None, description="Associated incident ID")

class AgentStatus(BaseModel):
    """Agent status response"""
    agent_id: str
    status: str
    monitoring_active: bool
    monitor_directory: Optional[str]
    backup_directory: Optional[str]
    stats: Dict[str, Any]
    timestamp: datetime

class ThreatAlert(BaseModel):
    """Threat alert model"""
    agent_id: str
    incident_id: str
    threat_level: ThreatLevel
    malware_process: str
    detection_confidence: float
    detection_layer: DetectionLayer
    actions_taken: List[str]
    forensic_data: Dict[str, Any]
    timestamp: datetime

class DetectionAnalytics(BaseModel):
    """Detection analytics response"""
    detection_stats: Dict[str, int]
    feature_history_size: int
    model_versions: Dict[str, str]
    performance_metrics: Dict[str, str]
    recent_detections: List[Dict[str, Any]]

class BackupInfo(BaseModel):
    """Backup information"""
    name: str
    path: str
    type: str
    file_count: int
    timestamp: datetime
    size: int

class SystemInfo(BaseModel):
    """System information"""
    hostname: str
    local_ip: str
    os_type: str
    os_version: str
    architecture: str
    processor: str
    cpu_count: int
    total_memory: int
    boot_time: datetime

class ZeroTrustStatus(BaseModel):
    """Zero Trust enforcement status"""
    enforcement_enabled: bool
    emergency_mode: bool
    whitelisted_processes_count: int
    whitelisted_paths_count: int
    denied_operations_count: int
    recent_denials: List[Dict[str, Any]]

class NetworkStatus(BaseModel):
    """Network isolation status"""
    is_isolated: bool
    blocked_ips_count: int
    os_type: str

class ProcessInfo(BaseModel):
    """Process information"""
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    username: str
    create_time: float

class FileEvent(BaseModel):
    """File system event"""
    event_type: str
    file_path: str
    timestamp: datetime
    entropy: Optional[float]
    file_size: Optional[int]

class EntropyAnalysis(BaseModel):
    """Entropy analysis results"""
    current_entropy: float
    file_type: str
    expected_entropy: float
    entropy_ratio: float
    is_suspicious: bool
    confidence: float
    anomaly_type: str

class PatternAnalysis(BaseModel):
    """Pattern analysis results"""
    suspicious_patterns: List[str]
    confidence: float
    threat_level: ThreatLevel
    matched_rules: List[str]
    file_type_verification: Optional[Dict[str, Any]]

class EnsembleResult(BaseModel):
    """Ensemble detection result"""
    threat_detected: bool
    confidence: float
    threat_level: ThreatLevel
    primary_layer: DetectionLayer
    layer_agreement: float
    weighted_scores: Dict[str, float]
    raw_scores: Dict[str, float]

class APIResponse(BaseModel):
    """Standard API response"""
    status: str
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.now)

class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    details: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)

# WebSocket message models
class WebSocketMessage(BaseModel):
    """Base WebSocket message"""
    type: str
    timestamp: datetime = Field(default_factory=datetime.now)

class ThreatDetectedMessage(WebSocketMessage):
    """Threat detected WebSocket message"""
    data: Dict[str, Any]
    detection_stats: Dict[str, int]

class StatusUpdateMessage(WebSocketMessage):
    """Status update WebSocket message"""
    agent_status: str
    monitoring_active: bool
    stats: Dict[str, Any]

class EmergencyResponseMessage(WebSocketMessage):
    """Emergency response WebSocket message"""
    actions: List[str]
    detection_result: Dict[str, Any]

class CommandExecutedMessage(WebSocketMessage):
    """Command executed WebSocket message"""
    commands: List[str]

# Configuration models
class AgentConfiguration(BaseModel):
    """Complete agent configuration"""
    agent_id: str
    central_system_url: str
    thresholds: Dict[str, float]
    monitoring_intervals: Dict[str, int]
    prevention_actions: Dict[str, bool]
    backup_settings: Dict[str, Any]
    file_monitoring: Dict[str, Any]
    process_monitoring: Dict[str, Any]
    network_monitoring: Dict[str, Any]
    zero_trust: Dict[str, Any]
    logging: Dict[str, Any]
    demo_settings: Dict[str, Any]

class UpdateConfiguration(BaseModel):
    """Configuration update request"""
    thresholds: Optional[Dict[str, float]] = None
    monitoring_intervals: Optional[Dict[str, int]] = None
    prevention_actions: Optional[Dict[str, bool]] = None
    backup_settings: Optional[Dict[str, Any]] = None  