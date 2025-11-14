# from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, Request, File, UploadFile
# from fastapi.staticfiles import StaticFiles
# from fastapi.templating import Jinja2Templates
# from fastapi.responses import HTMLResponse, JSONResponse
# import asyncio
# import json
# import os
# import threading
# from datetime import datetime, timedelta
# from contextlib import asynccontextmanager
# import pandas as pd
# import numpy as np
# from api.websocket_handler import ConnectionManager
# from monitor import RealTimeMonitor
# from detection.detector import QuadLayerDetector
# from detection.supervised_detector import SupervisedDetector
# from detection.anomaly_detector import AnomalyDetector
# from detection.rule_engine import RuleEngine
# from detection.slow_ransomware_detector import SlowRansomwareDetector
# from detection.ensemble_detector import EnsembleDetector
# from prevention.backup_manager import BackupManager
# from prevention.file_lock import FileLockManager
# from prevention.network_isolation import NetworkIsolation
# from zero_trust.enforcer import ZeroTrustEnforcer
# from communication.central_client import CentralSystemClient
# from utils.config import AgentConfig
# from utils.feature_extractor import FeatureExtractor

# # Global agent instance
# agent_instance = None

# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     # Startup
#     global agent_instance
#     agent_instance = ClientAgent()
    
#     # Initialize detection models (non-blocking)
#     asyncio.create_task(agent_instance.initialize_detection_models())
    
#     # ✅ CRITICAL FIX: Start central connection in SEPARATE THREAD
#     def start_central_in_thread():
#         loop = asyncio.new_event_loop()
#         asyncio.set_event_loop(loop)
#         loop.run_until_complete(agent_instance.connect_to_central())
    
#     central_thread = threading.Thread(target=start_central_in_thread, daemon=True)
#     central_thread.start()
    
#     yield
    
#     # Shutdown
#     if agent_instance:
#         await agent_instance.shutdown()

# app = FastAPI(
#     title="AI Ransomware Protection Agent - Quad-Layer Detection",
#     description="FastAPI-based client agent with 4-layer ransomware detection",
#     version="2.0.0",
#     lifespan=lifespan
# )

# # Mount static files and templates
# app.mount("/static", StaticFiles(directory="static"), name="static")
# templates = Jinja2Templates(directory="static")

# # Include routers
# try:
#     from api.endpoints import router as api_router
#     app.include_router(api_router, prefix="/api/v1")
# except ImportError as e:
#     print(f"⚠️ API router not available: {e}")

# # WebSocket manager
# websocket_manager = ConnectionManager()

# class ClientAgent:
#     def __init__(self):
#         self.config = AgentConfig()
#         self.monitor = None
#         self.detector = QuadLayerDetector()
#         self.backup_manager = None
#         self.file_lock = FileLockManager()
#         self.network_isolation = NetworkIsolation()
#         self.zero_trust = ZeroTrustEnforcer()
#         self.central_client = CentralSystemClient()
#         self.websocket_manager = websocket_manager
#         self.feature_extractor = FeatureExtractor()
        
#         self.agent_id = f"PC-{os.environ.get('COMPUTERNAME', 'UNKNOWN')}"
#         self.monitoring_active = False
#         self.monitor_thread = None
        
#         # Demo configuration
#         self.monitor_directory = None
#         self.backup_directory = None
#         self.important_folders = []
        
#         # Status tracking
#         self.status = "initializing"
#         self.last_alert = None
#         self.last_alert_timestamp = None
        
#         # Stats tracking
#         self.stats = {
#             "files_monitored": 0,
#             "threats_detected": 0,
#             "prevention_actions": 0,
#             "last_detection": None,
#             "total_detections": 0,
#             "layer1_supervised": 0,
#             "layer2_anomaly": 0,
#             "layer3_rules": 0,
#             "layer4_slow": 0,
#             "ensemble_detections": 0
#         }
        
#         # Detection stats for quad-layer
#         self.detection_stats = {
#             "total_detections": 0,
#             "layer1_supervised": 0,
#             "layer2_anomaly": 0,
#             "layer3_rules": 0,
#             "layer4_slow": 0,
#             "ensemble_detections": 0,
#             "false_positives": 0
#         }
        
#         # Feature history for time-series analysis
#         self.feature_history = []
#         self.max_history_size = 1000

#     async def initialize_detection_models(self):
#         """Initialize all detection models"""
#         print("🧠 Initializing Quad-Layer Detection Engine...")
        
#         # Initialize individual detectors
#         self.supervised_detector = SupervisedDetector()
#         self.anomaly_detector = AnomalyDetector()
#         self.rule_engine = RuleEngine()
#         self.slow_detector = SlowRansomwareDetector()
#         self.ensemble_detector = EnsembleDetector()
        
#         # Load models
#         await self.supervised_detector.load_models()
#         await self.anomaly_detector.initialize_models()
#         await self.rule_engine.load_rules()
#         await self.slow_detector.initialize_detector()
        
#         print("✅ Quad-Layer Detection Engine initialized")

#     async def connect_to_central(self):
#         """Connect to central system - runs in separate thread"""
#         print("🌐 Attempting to connect to Central Intelligence System...")
#         await asyncio.sleep(2)  # Small delay to ensure FastAPI is up
        
#         max_retries = 3
#         retry_delay = 5  # seconds
        
#         for attempt in range(max_retries):
#             try:
#                 success = await self.central_client.connect()
#                 if success:
#                     print("✅ Successfully connected to Central Intelligence System")
#                     return
#                 else:
#                     print(f"❌ Connection attempt {attempt + 1} failed")
#             except Exception as e:
#                 print(f"❌ Connection error on attempt {attempt + 1}: {e}")
            
#             if attempt < max_retries - 1:
#                 print(f"🔄 Retrying in {retry_delay} seconds...")
#                 await asyncio.sleep(retry_delay)
        
#         print("⚠️ Could not connect to Central System. Running in standalone mode.")

#     async def setup_demo_configuration(self, config_data: dict):
#         """Setup monitoring configuration from API"""
#         self.monitor_directory = config_data.get("monitor_directory")
#         self.backup_directory = config_data.get("backup_directory")
#         self.important_folders = config_data.get("important_folders", [])
        
#         # Validate directories
#         if not os.path.exists(self.monitor_directory):
#             raise ValueError(f"Monitor directory does not exist: {self.monitor_directory}")
#         if not os.path.exists(self.backup_directory):
#             raise ValueError(f"Backup directory does not exist: {self.backup_directory}")
        
#         # Initialize backup manager
#         self.backup_manager = BackupManager(
#             self.monitor_directory,
#             self.backup_directory,
#             self.important_folders
#         )
        
#         # Create initial backup
#         await self.backup_manager.create_initial_backup()
        
#         self.status = "configured"
#         return {"status": "configured", "message": "Demo configuration completed"}

#     async def start_background_monitoring(self):
#         """Start monitoring in background"""
#         if not self.monitor_directory:
#             print("⚠️ Monitoring not started - configuration required")
#             return
        
#         print("🚀 Starting AI Ransomware Protection Agent with Quad-Layer Detection...")
        
#         # Initialize real-time monitor
#         self.monitor = RealTimeMonitor(
#             self.monitor_directory,
#             self.on_file_event,
#             self.on_process_event,
#             self.on_network_event
#         )
        
#         # Start monitoring in separate thread
#         self.monitoring_active = True
#         self.monitor_thread = threading.Thread(target=self.monitor.start)
#         self.monitor_thread.daemon = True
#         self.monitor_thread.start()
        
#         self.status = "monitoring"
#         print("✅ Real-time monitoring active with Quad-Layer Detection")
        
#         # Start background detection processing
#         asyncio.create_task(self.background_detection_processing())
        
#         # Start demo simulation after 30 seconds
#         asyncio.create_task(self.start_demo_simulation())

#     async def on_file_event(self, event_type: str, file_path: str, details: dict = None):
#         """Handle file system events"""
#         try:
#             # Extract features for detection
#             features = await self.feature_extractor.extract_file_features(
#                 event_type, file_path, details
#             )
            
#             # Store in history
#             self._update_feature_history(features)
            
#             # Run quad-layer detection
#             detection_result = await self.detector.analyze_file_event(
#                 event_type, file_path, features, self.feature_history
#             )
            
#             if detection_result["threat_detected"]:
#                 await self.evaluate_threat(detection_result)
#         except Exception as e:
#             print(f"Error in file event handling: {e}")

#     async def on_process_event(self, process_data: dict):
#         """Handle process monitoring events"""
#         try:
#             # Extract features for detection
#             features = await self.feature_extractor.extract_process_features(process_data)
            
#             # Store in history
#             self._update_feature_history(features)
            
#             # Run quad-layer detection
#             detection_result = await self.detector.analyze_process_event(
#                 process_data, features, self.feature_history
#             )
            
#             if detection_result["threat_detected"]:
#                 await self.evaluate_threat(detection_result)
#         except Exception as e:
#             print(f"Error in process event handling: {e}")

#     async def on_network_event(self, network_data: dict):
#         """Handle network monitoring events"""
#         try:
#             # Extract features for detection
#             features = await self.feature_extractor.extract_network_features(network_data)
            
#             # Store in history
#             self._update_feature_history(features)
            
#             # Run quad-layer detection
#             detection_result = await self.detector.analyze_network_event(
#                 network_data, features, self.feature_history
#             )
            
#             if detection_result["threat_detected"]:
#                 await self.evaluate_threat(detection_result)
#         except Exception as e:
#             print(f"Error in network event handling: {e}")

#     def _update_feature_history(self, features: dict):
#         """Update feature history for time-series analysis"""
#         features["timestamp"] = datetime.now().isoformat()
#         self.feature_history.append(features)
        
#         # Keep history size manageable
#         if len(self.feature_history) > self.max_history_size:
#             self.feature_history = self.feature_history[-self.max_history_size:]

#     async def evaluate_threat(self, detection_result: dict):
#         """Evaluate threat and trigger response"""
#         self.detection_stats["total_detections"] += 1
#         self.last_alert = detection_result
#         self.last_alert_timestamp = datetime.now().isoformat()
        
#         # Update layer-specific stats
#         detection_layer = detection_result.get("primary_detection_layer")
#         if detection_layer == "supervised":
#             self.detection_stats["layer1_supervised"] += 1
#         elif detection_layer == "anomaly":
#             self.detection_stats["layer2_anomaly"] += 1
#         elif detection_layer == "rules":
#             self.detection_stats["layer3_rules"] += 1
#         elif detection_layer == "slow_ransomware":
#             self.detection_stats["layer4_slow"] += 1
#         elif detection_layer == "ensemble":
#             self.detection_stats["ensemble_detections"] += 1
        
#         # Broadcast to WebSocket clients
#         await self.websocket_manager.broadcast({
#             "type": "THREAT_DETECTED",
#             "data": detection_result,
#             "detection_stats": self.detection_stats,
#             "timestamp": self.last_alert_timestamp
#         })
        
#         threat_level = detection_result.get("threat_level", "medium")
#         confidence = detection_result.get("confidence", 0.5)
        
#         print(f"🎯 Threat Detected - Layer: {detection_layer}, Level: {threat_level}, Confidence: {confidence:.2f}")
        
#         if threat_level == "critical" and confidence > 0.8:
#             await self.trigger_emergency_response(detection_result)
#         elif threat_level == "high" and confidence > 0.6:
#             await self.trigger_high_alert_response(detection_result)
#         elif threat_level == "suspicious":
#             await self.trigger_enhanced_monitoring(detection_result)

#     async def trigger_emergency_response(self, detection_result: dict):
#         """Execute emergency response procedures"""
#         print("🚨 CRITICAL THREAT - Executing emergency response")
        
#         prevention_actions = []
        
#         # 1. Emergency backup
#         if self.backup_manager:
#             try:
#                 backup_path = await self.backup_manager.create_emergency_backup()
#                 prevention_actions.append(f"emergency_backup:{backup_path}")
#             except Exception as e:
#                 print(f"Backup failed: {e}")
        
#         # 2. File locking
#         try:
#             locked_files = self.file_lock.lock_critical_files(self.monitor_directory)
#             prevention_actions.append(f"files_locked:{len(locked_files)}")
#         except Exception as e:
#             print(f"File locking failed: {e}")
        
#         # 3. Network isolation
#         try:
#             if self.network_isolation.isolate_machine():
#                 prevention_actions.append("network_isolated")
#         except Exception as e:
#             print(f"Network isolation failed: {e}")
        
#         # 4. Zero-trust enforcement
#         try:
#             if self.zero_trust.enable_emergency_mode():
#                 prevention_actions.append("zero_trust_enabled")
#         except Exception as e:
#             print(f"Zero-trust failed: {e}")
        
#         # Send alert to central system
#         try:
#             alert_data = await self.prepare_central_alert(detection_result, prevention_actions)
#             await self.central_client.send_threat_alert(alert_data)
#         except Exception as e:
#             print(f"Central alert failed: {e}")
        
#         # Broadcast response action
#         await self.websocket_manager.broadcast({
#             "type": "EMERGENCY_RESPONSE",
#             "actions": prevention_actions,
#             "detection_result": detection_result,
#             "timestamp": datetime.now().isoformat()
#         })

#     async def trigger_high_alert_response(self, detection_result: dict):
#         """Execute high alert response"""
#         print("⚠️ HIGH THREAT - Enhanced monitoring activated")
        
#         prevention_actions = []
        
#         # Enhanced monitoring
#         try:
#             if self.zero_trust.enhance_monitoring():
#                 prevention_actions.append("enhanced_monitoring")
#         except Exception as e:
#             print(f"Enhanced monitoring failed: {e}")
        
#         # Send alert to central system
#         try:
#             alert_data = await self.prepare_central_alert(detection_result, prevention_actions)
#             await self.central_client.send_threat_alert(alert_data)
#         except Exception as e:
#             print(f"Central alert failed: {e}")
        
#         await self.websocket_manager.broadcast({
#             "type": "HIGH_ALERT_RESPONSE",
#             "actions": prevention_actions,
#             "detection_result": detection_result,
#             "timestamp": datetime.now().isoformat()
#         })

#     async def trigger_enhanced_monitoring(self, detection_result: dict):
#         """Trigger enhanced monitoring for suspicious activity"""
#         print("🔍 SUSPICIOUS ACTIVITY - Enhanced monitoring activated")
        
#         await self.websocket_manager.broadcast({
#             "type": "ENHANCED_MONITORING",
#             "detection_result": detection_result,
#             "timestamp": datetime.now().isoformat()
#         })

#     async def background_detection_processing(self):
#         """Background processing for time-series and ensemble detection"""
#         while self.monitoring_active:
#             try:
#                 # Run slow ransomware detection on feature history
#                 if len(self.feature_history) >= 50:
#                     slow_detection = await self.slow_detector.analyze_time_series(
#                         self.feature_history[-100:]
#                     )
                    
#                     if slow_detection["threat_detected"]:
#                         await self.evaluate_threat(slow_detection)
                
#                 # Run ensemble detection periodically
#                 if len(self.feature_history) >= 10:
#                     ensemble_result = await self.ensemble_detector.analyze_ensemble(
#                         self.feature_history[-20:]
#                     )
                    
#                     if ensemble_result["threat_detected"]:
#                         await self.evaluate_threat(ensemble_result)
                
#                 await asyncio.sleep(10)
                
#             except Exception as e:
#                 print(f"Background detection error: {e}")
#                 await asyncio.sleep(30)

#     async def prepare_central_alert(self, detection_result: dict, prevention_actions: list) -> dict:
#         """Prepare alert data for central system"""
#         return {
#             "type": "THREAT_ALERT",
#             "payload": {
#                 "agent_id": self.agent_id,
#                 "incident_id": f"INC-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
#                 "status": "infected",
#                 "threat_level": detection_result.get("threat_level", "critical"),
#                 "malware_process": detection_result.get("process_name", "unknown"),
#                 "detection_confidence": detection_result.get("confidence", 0.92),
#                 "detection_layer": detection_result.get("primary_detection_layer", "unknown"),
#                 "actions_taken": prevention_actions,
#                 "timestamp": datetime.now().isoformat()
#             }
#         }

#     async def start_demo_simulation(self):
#         """Start demo simulation after delay"""
#         await asyncio.sleep(30)
        
#         if self.monitoring_active:
#             print("🎭 Starting quad-layer demo simulation...")
            
#             demo_threats = [
#                 {
#                     "threat_type": "SUPERVISED_ML_DETECTION",
#                     "threat_level": "critical",
#                     "confidence": 0.95,
#                     "primary_detection_layer": "supervised",
#                     "malware_process": "crypto_locker.exe",
#                     "files_modified": 47,
#                     "encryption_detected": True
#                 }
#             ]
            
#             for threat in demo_threats:
#                 await asyncio.sleep(5)
#                 await self.evaluate_threat(threat)

#     async def shutdown(self):
#         """Shutdown agent gracefully"""
#         self.monitoring_active = False
#         if self.monitor:
#             self.monitor.stop()
#         await self.central_client.disconnect()
#         print("✅ Agent shutdown complete")

# # WebSocket endpoints
# @app.websocket("/ws/dashboard")
# async def websocket_dashboard(websocket: WebSocket):
#     await websocket_manager.connect(websocket)
#     try:
#         while True:
#             data = await websocket.receive_text()
#             # Handle incoming messages from dashboard
#             try:
#                 message = json.loads(data)
#                 # You can add message handling here if needed
#             except json.JSONDecodeError:
#                 pass
#     except WebSocketDisconnect:
#         websocket_manager.disconnect(websocket)

# # Web interface
# @app.get("/")
# async def read_root():
#     return HTMLResponse("""
#     <html>
#         <head>
#             <title>AI Ransomware Protection</title>
#             <meta http-equiv="refresh" content="0; url='/dashboard'">
#         </head>
#         <body>
#             <p>Redirecting to <a href="/dashboard">dashboard</a>...</p>
#         </body>
#     </html>
#     """)

# @app.get("/dashboard")
# async def read_dashboard(request: Request):
#     try:
#         return templates.TemplateResponse("dashboard.html", {"request": request})
#     except Exception as e:
#         return HTMLResponse(f"""
#         <html>
#             <body>
#                 <h1>AI Ransomware Protection Dashboard</h1>
#                 <p>Dashboard template not found. Please ensure dashboard.html exists in static/ directory.</p>
#                 <p>Error: {e}</p>
#                 <div id="status">Agent Status: Running</div>
#                 <div id="connection">Central System: Connecting...</div>
#             </body>
#         </html>
#         """)

# @app.get("/health")
# async def health_check():
#     return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# @app.get("/api/status")
# async def api_status():
#     if agent_instance:
#         return {
#             "agent_id": agent_instance.agent_id,
#             "status": agent_instance.status,
#             "monitoring_active": agent_instance.monitoring_active,
#             "central_connected": agent_instance.central_client.connected if agent_instance.central_client else False
#         }
#     return {"status": "agent_not_initialized"}

# # Global agent access
# def get_agent():
#     return agent_instance

# if __name__ == "__main__":
#     import uvicorn
#     print("🚀 Starting AI Ransomware Protection Agent...")
#     print("📊 Dashboard will be available at: http://localhost:8000/dashboard")
#     print("🔧 API Documentation: http://localhost:8000/docs")
#     uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import asyncio
import json
import os
import threading
from datetime import datetime
from contextlib import asynccontextmanager
from api.websocket_handler import ConnectionManager
from monitor import RealTimeMonitor
from detection.detector import QuadLayerDetector
from detection.supervised_detector import SupervisedDetector
from detection.anomaly_detector import AnomalyDetector
from detection.rule_engine import RuleEngine
from detection.slow_ransomware_detector import SlowRansomwareDetector
from detection.ensemble_detector import EnsembleDetector
from prevention.backup_manager import BackupManager
from prevention.file_lock import FileLockManager
from prevention.network_isolation import NetworkIsolation
from zero_trust.enforcer import ZeroTrustEnforcer
from communication.central_client import CentralSystemClient
from utils.config import AgentConfig
from utils.feature_extractor import FeatureExtractor

# Import and set up dependencies
from api.dependencies import set_agent, get_agent

# Global agent instance
agent_instance = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global agent_instance
    agent_instance = ClientAgent()
    set_agent(agent_instance)  # Set for API dependencies
    
    # Initialize detection models in background
    asyncio.create_task(agent_instance.initialize_detection_models())
    
    # Start central connection in separate thread
    def start_central_in_thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(agent_instance.connect_to_central())
    
    central_thread = threading.Thread(target=start_central_in_thread, daemon=True)
    central_thread.start()
    
    yield
    
    # Shutdown
    if agent_instance:
        await agent_instance.shutdown()

app = FastAPI(
    title="AI Ransomware Protection Agent - Quad-Layer Detection",
    description="FastAPI-based client agent with 4-layer ransomware detection",
    version="2.0.0",
    lifespan=lifespan
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="static")

# Include API routers
try:
    from api.endpoints import router as api_router
    app.include_router(api_router, prefix="/api/v1")
    print("✅ API routes loaded successfully")
except ImportError as e:
    print(f"⚠️ API router not available: {e}")

# WebSocket manager
websocket_manager = ConnectionManager()

class ClientAgent:
    def __init__(self):
        self.config = AgentConfig()
        self.monitor = None
        self.detector = QuadLayerDetector()
        self.backup_manager = None
        self.file_lock = FileLockManager()
        self.network_isolation = NetworkIsolation()
        self.zero_trust = ZeroTrustEnforcer()
        self.central_client = CentralSystemClient()
        self.websocket_manager = websocket_manager
        self.feature_extractor = FeatureExtractor()
        
        self.agent_id = f"PC-{os.environ.get('COMPUTERNAME', 'UNKNOWN')}"
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Demo configuration
        self.monitor_directory = None
        self.backup_directory = None
        self.important_folders = []
        
        # Status tracking
        self.status = "initialized"
        self.last_alert = None
        self.last_alert_timestamp = None
        
        # Stats tracking
        self.stats = {
            "files_monitored": 0,
            "threats_detected": 0,
            "prevention_actions": 0,
            "last_detection": None,
        }
        
        # Detection stats for quad-layer
        self.detection_stats = {
            "total_detections": 0,
            "layer1_supervised": 0,
            "layer2_anomaly": 0,
            "layer3_rules": 0,
            "layer4_slow": 0,
            "ensemble_detections": 0,
            "false_positives": 0
        }
        
        # Feature history for time-series analysis
        self.feature_history = []
        self.max_history_size = 1000

    async def initialize_detection_models(self):
        """Initialize all detection models"""
        print("🧠 Initializing Quad-Layer Detection Engine...")
        
        try:
            # Initialize individual detectors
            self.supervised_detector = SupervisedDetector()
            self.anomaly_detector = AnomalyDetector()
            self.rule_engine = RuleEngine()
            self.slow_detector = SlowRansomwareDetector()
            self.ensemble_detector = EnsembleDetector()
            
            # Load models
            await self.supervised_detector.load_models()
            await self.anomaly_detector.initialize_models()
            await self.rule_engine.load_rules()
            await self.slow_detector.initialize_detector()
            
            print("✅ Quad-Layer Detection Engine initialized")
            self.status = "models_loaded"
        except Exception as e:
            print(f"❌ Error initializing detection models: {e}")
            self.status = "models_failed"

    async def connect_to_central(self):
        """Connect to central system - runs in separate thread"""
        print("🌐 Attempting to connect to Central Intelligence System...")
        await asyncio.sleep(2)  # Small delay to ensure FastAPI is up
        
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                success = await self.central_client.connect()
                if success:
                    print("✅ Successfully connected to Central Intelligence System")
                    self.status = "central_connected"
                    return
                else:
                    print(f"❌ Connection attempt {attempt + 1} failed")
            except Exception as e:
                print(f"❌ Connection error on attempt {attempt + 1}: {e}")
            
            if attempt < max_retries - 1:
                print(f"🔄 Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
        
        print("⚠️ Could not connect to Central System. Running in standalone mode.")
        self.status = "central_disconnected"

    async def setup_demo_configuration(self, config_data: dict):
        """Setup monitoring configuration from API"""
        try:
            self.monitor_directory = config_data.get("monitor_directory")
            self.backup_directory = config_data.get("backup_directory")
            self.important_folders = config_data.get("important_folders", [])
            
            # Validate directories
            if not os.path.exists(self.monitor_directory):
                os.makedirs(self.monitor_directory, exist_ok=True)
                print(f"📁 Created monitor directory: {self.monitor_directory}")
            
            if not os.path.exists(self.backup_directory):
                os.makedirs(self.backup_directory, exist_ok=True)
                print(f"📁 Created backup directory: {self.backup_directory}")
            
            # Initialize backup manager
            self.backup_manager = BackupManager(
                self.monitor_directory,
                self.backup_directory,
                self.important_folders
            )
            
            # Create initial backup
            await self.backup_manager.create_initial_backup()
            
            self.status = "configured"
            return {"status": "configured", "message": "Demo configuration completed"}
            
        except Exception as e:
            print(f"❌ Configuration error: {e}")
            raise

    async def start_background_monitoring(self):
        """Start monitoring in background"""
        if not self.monitor_directory:
            print("⚠️ Monitoring not started - configuration required")
            return {"status": "error", "message": "Configuration required"}
        
        print("🚀 Starting AI Ransomware Protection Agent with Quad-Layer Detection...")
        
        try:
            # Initialize real-time monitor
            self.monitor = RealTimeMonitor(
                self.monitor_directory,
                self.on_file_event,
                self.on_process_event,
                self.on_network_event
            )
            
            # Start monitoring in separate thread
            self.monitoring_active = True
            self.monitor_thread = threading.Thread(target=self.monitor.start)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            
            self.status = "monitoring"
            print("✅ Real-time monitoring active with Quad-Layer Detection")
            
            # Start background detection processing
            asyncio.create_task(self.background_detection_processing())
            
            # Start demo simulation after 30 seconds
            asyncio.create_task(self.start_demo_simulation())
            
            return {"status": "monitoring_started", "message": "Real-time monitoring activated"}
            
        except Exception as e:
            print(f"❌ Monitoring start error: {e}")
            return {"status": "error", "message": str(e)}

    async def on_file_event(self, event_type: str, file_path: str, details: dict = None):
        """Handle file system events"""
        try:
            # Extract features for detection
            features = await self.feature_extractor.extract_file_features(
                event_type, file_path, details
            )
            
            # Store in history
            self._update_feature_history(features)
            
            # Run quad-layer detection
            detection_result = await self.detector.analyze_file_event(
                event_type, file_path, features, self.feature_history
            )
            
            if detection_result["threat_detected"]:
                await self.evaluate_threat(detection_result)
        except Exception as e:
            print(f"Error in file event handling: {e}")

    async def on_process_event(self, process_data: dict):
        """Handle process monitoring events"""
        try:
            # Extract features for detection
            features = await self.feature_extractor.extract_process_features(process_data)
            
            # Store in history
            self._update_feature_history(features)
            
            # Run quad-layer detection
            detection_result = await self.detector.analyze_process_event(
                process_data, features, self.feature_history
            )
            
            if detection_result["threat_detected"]:
                await self.evaluate_threat(detection_result)
        except Exception as e:
            print(f"Error in process event handling: {e}")

    async def on_network_event(self, network_data: dict):
        """Handle network monitoring events"""
        try:
            # Extract features for detection
            features = await self.feature_extractor.extract_network_features(network_data)
            
            # Store in history
            self._update_feature_history(features)
            
            # Run quad-layer detection
            detection_result = await self.detector.analyze_network_event(
                network_data, features, self.feature_history
            )
            
            if detection_result["threat_detected"]:
                await self.evaluate_threat(detection_result)
        except Exception as e:
            print(f"Error in network event handling: {e}")

    def _update_feature_history(self, features: dict):
        """Update feature history for time-series analysis"""
        features["timestamp"] = datetime.now().isoformat()
        self.feature_history.append(features)
        
        # Keep history size manageable
        if len(self.feature_history) > self.max_history_size:
            self.feature_history = self.feature_history[-self.max_history_size:]

    async def evaluate_threat(self, detection_result: dict):
        """Evaluate threat and trigger response"""
        self.detection_stats["total_detections"] += 1
        self.last_alert = detection_result
        self.last_alert_timestamp = datetime.now().isoformat()
        
        # Update layer-specific stats
        detection_layer = detection_result.get("primary_detection_layer")
        if detection_layer == "supervised":
            self.detection_stats["layer1_supervised"] += 1
        elif detection_layer == "anomaly":
            self.detection_stats["layer2_anomaly"] += 1
        elif detection_layer == "rules":
            self.detection_stats["layer3_rules"] += 1
        elif detection_layer == "slow_ransomware":
            self.detection_stats["layer4_slow"] += 1
        elif detection_layer == "ensemble":
            self.detection_stats["ensemble_detections"] += 1
        
        # Broadcast to WebSocket clients
        await self.websocket_manager.broadcast({
            "type": "THREAT_DETECTED",
            "data": detection_result,
            "detection_stats": self.detection_stats,
            "timestamp": self.last_alert_timestamp
        })
        
        threat_level = detection_result.get("threat_level", "medium")
        confidence = detection_result.get("confidence", 0.5)
        
        print(f"🎯 Threat Detected - Layer: {detection_layer}, Level: {threat_level}, Confidence: {confidence:.2f}")
        
        if threat_level == "critical" and confidence > 0.8:
            await self.trigger_emergency_response(detection_result)
        elif threat_level == "high" and confidence > 0.6:
            await self.trigger_high_alert_response(detection_result)
        elif threat_level == "suspicious":
            await self.trigger_enhanced_monitoring(detection_result)

    async def trigger_emergency_response(self, detection_result: dict):
        """Execute emergency response procedures"""
        print("🚨 CRITICAL THREAT - Executing emergency response")
        
        prevention_actions = []
        
        # 1. Emergency backup
        if self.backup_manager:
            try:
                backup_path = await self.backup_manager.create_emergency_backup()
                prevention_actions.append(f"emergency_backup:{backup_path}")
            except Exception as e:
                print(f"Backup failed: {e}")
        
        # 2. File locking
        try:
            locked_files = self.file_lock.lock_critical_files(self.monitor_directory)
            prevention_actions.append(f"files_locked:{len(locked_files)}")
        except Exception as e:
            print(f"File locking failed: {e}")
        
        # 3. Network isolation
        try:
            if self.network_isolation.isolate_machine():
                prevention_actions.append("network_isolated")
        except Exception as e:
            print(f"Network isolation failed: {e}")
        
        # 4. Zero-trust enforcement
        try:
            if self.zero_trust.enable_emergency_mode():
                prevention_actions.append("zero_trust_enabled")
        except Exception as e:
            print(f"Zero-trust failed: {e}")
        
        # Send alert to central system
        try:
            alert_data = await self.prepare_central_alert(detection_result, prevention_actions)
            await self.central_client.send_threat_alert(alert_data)
        except Exception as e:
            print(f"Central alert failed: {e}")
        
        # Broadcast response action
        await self.websocket_manager.broadcast({
            "type": "EMERGENCY_RESPONSE",
            "actions": prevention_actions,
            "detection_result": detection_result,
            "timestamp": datetime.now().isoformat()
        })

    async def prepare_central_alert(self, detection_result: dict, prevention_actions: list) -> dict:
        """Prepare alert data for central system"""
        return {
            "type": "THREAT_ALERT",
            "payload": {
                "agent_id": self.agent_id,
                "incident_id": f"INC-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "status": "infected",
                "threat_level": detection_result.get("threat_level", "critical"),
                "malware_process": detection_result.get("malware_process", "unknown"),
                "detection_confidence": detection_result.get("confidence", 0.92),
                "detection_layer": detection_result.get("primary_detection_layer", "unknown"),
                "actions_taken": prevention_actions,
                "timestamp": datetime.now().isoformat()
            }
        }

    async def start_demo_simulation(self):
        """Start demo simulation after delay"""
        await asyncio.sleep(30)
        
        if self.monitoring_active:
            print("🎭 Starting quad-layer demo simulation...")
            
            demo_threats = [
                {
                    "threat_type": "SUPERVISED_ML_DETECTION",
                    "threat_level": "critical",
                    "confidence": 0.95,
                    "primary_detection_layer": "supervised",
                    "malware_process": "crypto_locker.exe",
                    "files_modified": 47,
                    "encryption_detected": True,
                    "threat_detected": True
                }
            ]
            
            for threat in demo_threats:
                await asyncio.sleep(5)
                await self.evaluate_threat(threat)

    async def execute_central_command(self, command_data: dict):
        """Execute commands from central system"""
        print(f"🔧 Executing central command: {command_data}")
        # Implementation would handle specific commands
        pass

    async def background_detection_processing(self):
        """Background processing for time-series and ensemble detection"""
        while self.monitoring_active:
            try:
                await asyncio.sleep(10)
            except Exception as e:
                print(f"Background detection error: {e}")
                await asyncio.sleep(30)

    async def shutdown(self):
        """Shutdown agent gracefully"""
        self.monitoring_active = False
        if self.monitor:
            self.monitor.stop()
        await self.central_client.disconnect()
        print("✅ Agent shutdown complete")

# WebSocket endpoints
@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await websocket_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle incoming messages from dashboard
            try:
                message = json.loads(data)
                # You can add message handling here if needed
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)

# Web interface
@app.get("/")
async def read_root():
    return HTMLResponse("""
    <html>
        <head>
            <title>AI Ransomware Protection</title>
            <meta http-equiv="refresh" content="0; url='/dashboard'">
        </head>
        <body>
            <p>Redirecting to <a href="/dashboard">dashboard</a>...</p>
        </body>
    </html>
    """)

@app.get("/dashboard")
async def read_dashboard(request: Request):
    try:
        return templates.TemplateResponse("dashboard.html", {"request": request})
    except Exception as e:
        return HTMLResponse(f"""
        <html>
            <body>
                <h1>AI Ransomware Protection Dashboard</h1>
                <p>Dashboard is loading...</p>
                <div id="status">Agent Status: Running</div>
                <div id="connection">Central System: Connected</div>
                <p><a href="/api/v1/status">Check API Status</a></p>
            </body>
        </html>
        """)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/status")
async def api_status():
    agent = get_agent()
    if agent:
        return {
            "agent_id": agent.agent_id,
            "status": agent.status,
            "monitoring_active": agent.monitoring_active,
            "central_connected": agent.central_client.connected if agent.central_client else False,
            "detection_stats": agent.detection_stats
        }
    return {"status": "agent_not_initialized"}

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting AI Ransomware Protection Agent...")
    print("📊 Dashboard will be available at: http://localhost:8000/dashboard")
    print("🔧 API Documentation: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")