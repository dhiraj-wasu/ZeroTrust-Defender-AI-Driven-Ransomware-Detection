#!/usr/bin/env python3
"""
Central Intelligence System - FastAPI Main Entry Point
Complete theoretical framework implementation with FastAPI
"""

import asyncio
import logging
import signal
import sys
import uuid
import uvicorn
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from utils.logger import setup_logger
from config.settings import settings
from models.database import DatabaseManager
from agents.agent_manager import AgentManager
from agents.command_dispatcher import CommandDispatcher
from core.llm_intelligence import LLMIntelligence
from core.forensic_correlator import ForensicCorrelator
from core.coordination_engine import CoordinationEngine
from core.adaptive_learner import AdaptiveLearner
from api.websocket_manager import WebSocketManager
from api.endpoints import router as api_router
from admin.routes import router as admin_router
from api.dependencies import (
    get_database, get_agent_manager, get_command_dispatcher,
    get_llm_intelligence, get_forensic_correlator,
    get_adaptive_learner, get_coordination_engine
)

# Global central system instance
central_system = None

def generate_incident_id():
    """Generate unique incident ID"""
    return f"INC-{uuid.uuid4().hex[:8].upper()}"

class CentralIntelligenceSystem:
    """Main Central Intelligence System Class with FastAPI"""
    
    def __init__(self):
        self.logger = setup_logger("central_system")
        self.running = False
        
        # Initialize components
        self.db = DatabaseManager()
        self.agent_manager = AgentManager(self.db)
        self.command_dispatcher = CommandDispatcher(self.agent_manager)
        self.llm_intelligence = LLMIntelligence()
        self.forensic_correlator = ForensicCorrelator(self.db)
        self.adaptive_learner = AdaptiveLearner(self.db)
        self.coordination_engine = CoordinationEngine(
            self.agent_manager, 
            self.command_dispatcher
        )
        
        # Initialize WebSocket manager
        self.websocket_manager = WebSocketManager(self)
        
        self.logger.info("Central Intelligence System components initialized")

    async def initialize(self):
        """Initialize the complete system"""
        try:
            # Initialize database
            await self.db.initialize()
            
            self.running = True
            self.logger.info("Central Intelligence System initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize system: {e}")
            return False

    async def process_threat_alert(self, threat_alert):
        """Main threat processing pipeline with detailed logging"""
        self.logger.info(f"THREAT ALERT received from {threat_alert.agent_id}: {threat_alert.threat_level.value}")
        
        # Generate incident ID
        threat_alert.incident_id = generate_incident_id()
        
        try:
            # Step 1: Save initial alert
            await self.db.save_threat_alert(threat_alert)
            await self.db.save_processing_step(
                threat_alert.incident_id, 
                "ALERT_RECEIVED",
                {
                    "agent_id": threat_alert.agent_id,
                    "threat_level": threat_alert.threat_level.value,
                    "malware_process": threat_alert.malware_process,
                    "confidence": threat_alert.detection_confidence
                }
            )
            
            # Step 2: Forensic correlation
            self.logger.info(f"FORENSIC correlation for {threat_alert.agent_id}")
            correlation_data = await self.forensic_correlator.correlate_threat(threat_alert)
            await self.db.save_processing_step(
                threat_alert.incident_id,
                "FORENSIC_CORRELATION",
                {
                    "related_alerts_count": len(correlation_data.get('related_alerts', [])),
                    "correlation_confidence": correlation_data.get('correlation_confidence', 0),
                    "propagation_paths": correlation_data.get('propagation_graph', {}).get('propagation_paths', [])
                }
            )
            
            # Step 3: LLM intelligence analysis
            self.logger.info(f"LLM ANALYSIS for {threat_alert.agent_id}")
            llm_analysis = await self.llm_intelligence.analyze_threat(threat_alert, correlation_data)
            await self.db.save_processing_step(
                threat_alert.incident_id,
                "LLM_ANALYSIS",
                {
                    "attack_classification": llm_analysis.attack_classification,
                    "confidence_score": llm_analysis.confidence_score,
                    "business_impact": llm_analysis.business_impact,
                    "recommended_response": llm_analysis.recommended_network_response
                }
            )
            
            # Step 4: Coordination and response planning
            self.logger.info(f"RESPONSE COORDINATION for {threat_alert.agent_id}")
            coordination_result = await self.coordination_engine.coordinate_response(
                threat_alert, llm_analysis, correlation_data
            )
            await self.db.save_processing_step(
                threat_alert.incident_id,
                "RESPONSE_COORDINATION",
                {
                    "risk_level": coordination_result.get('risk_assessment', {}).get('risk_level', 'UNKNOWN'),
                    "risk_score": coordination_result.get('risk_assessment', {}).get('risk_score', 0),
                    "agent_commands_count": len(coordination_result.get('response_plan', {}).get('infected_agent_commands', [])),
                    "network_commands_count": len(coordination_result.get('response_plan', {}).get('network_wide_commands', []))
                }
            )
            
            # Step 5: Adaptive learning
            self.logger.info(f"ADAPTIVE LEARNING from incident {threat_alert.incident_id}")
            incident_data = {
                'incident_id': threat_alert.incident_id,
                'alert': threat_alert.dict(),
                'llm_analysis': llm_analysis.dict(),
                'correlation_data': correlation_data,
                'coordination_result': coordination_result,
                'response_timestamp': datetime.now().isoformat()
            }
            
            await self.adaptive_learner.learn_from_incident(incident_data)
            await self.db.save_processing_step(
                threat_alert.incident_id,
                "ADAPTIVE_LEARNING",
                {
                    "learning_completed": True,
                    "knowledge_updates": "Threat patterns and response optimizations updated"
                }
            )
            
            # Return comprehensive incident response
            response = {
                'incident_id': threat_alert.incident_id,
                'agent_commands': coordination_result.get('response_plan', {}).get('infected_agent_commands', []),
                'network_commands': coordination_result.get('response_plan', {}).get('network_wide_commands', []),
                'risk_assessment': coordination_result.get('risk_assessment', {}),
                'llm_analysis': llm_analysis.dict(),
                'correlation_data': correlation_data,
                'response_plan': coordination_result.get('response_plan', {})
            }
            
            self.logger.info(f"INCIDENT {threat_alert.incident_id} processing completed")
            return response
            
        except Exception as e:
            self.logger.error(f"Threat processing pipeline error: {e}")
            await self.db.save_processing_step(
                threat_alert.incident_id,
                "PROCESSING_ERROR",
                {"error": str(e)}
            )
            # Return fallback response
            return {
                'incident_id': threat_alert.incident_id,
                'agent_commands': ['maintain_isolation', 'increase_monitoring'],
                'network_commands': [],
                'risk_assessment': {'risk_level': 'UNKNOWN', 'risk_score': 5.0},
                'error': str(e)
            }

    async def get_recent_incidents(self, hours: int = 24, severity: str = None):
        """Get recent incidents for admin console"""
        try:
            incidents = await self.db.get_recent_alerts(hours=hours)
            if severity:
                incidents = [inc for inc in incidents if inc.get('threat_level') == severity]
            return incidents
        except Exception as e:
            self.logger.error(f"Error getting recent incidents: {e}")
            return []

    async def get_incident_details(self, incident_id: str):
        """Get detailed incident information for admin console"""
        try:
            # This would query the database for specific incident
            # For now, return a mock response
            return {
                "incident_id": incident_id,
                "agent_id": "PC-A",
                "threat_level": "critical",
                "malware_process": "crypto_stealth.exe",
                "detection_confidence": 0.92,
                "timestamp": datetime.now().isoformat(),
                "actions_taken": ["process_killed", "backup_created", "files_locked"]
            }
        except Exception as e:
            self.logger.error(f"Error getting incident details: {e}")
            return None

    async def activate_emergency_protocol(self, incident_id: str):
        """Activate emergency protocol manually"""
        self.logger.warning(f"Manual emergency activation for incident: {incident_id}")
        # Implementation would activate emergency mode

    async def deactivate_emergency_protocol(self, incident_id: str):
        """Deactivate emergency protocol"""
        self.logger.info(f"Manual emergency deactivation for incident: {incident_id}")
        # Implementation would deactivate emergency mode

    async def shutdown(self):
        """Graceful shutdown of the system"""
        self.logger.info("Initiating system shutdown...")
        self.running = False
        self.logger.info("Central Intelligence System shutdown complete")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI application"""
    global central_system
    
    # Startup
    central_system = CentralIntelligenceSystem()
    success = await central_system.initialize()
    
    if not success:
        sys.exit(1)
    
    print("\n" + "="*60)
    print("🚀 CENTRAL INTELLIGENCE SYSTEM - FASTAPI - OPERATIONAL")
    print("="*60)
    print(f"Server: {settings.SERVER_HOST}:{settings.SERVER_PORT}")
    print("WebSocket: /ws/{client_id}")
    print("REST API: /api/v1/*")
    print("Admin Console: /admin/")
    print("API Documentation: /docs")
    print("System ready to receive agent connections and threat alerts")
    print("="*60 + "\n")
    
    yield  # Application runs here
    
    # Shutdown
    await central_system.shutdown()

# Create FastAPI application
app = FastAPI(
    title="Central Intelligence System",
    description="Cybersecurity threat intelligence and response coordination system",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency override to provide central_system instance
def get_central_system() -> CentralIntelligenceSystem:
    return central_system

# Override dependencies to use our central system instance
app.dependency_overrides[get_database] = lambda: central_system.db
app.dependency_overrides[get_agent_manager] = lambda: central_system.agent_manager
app.dependency_overrides[get_command_dispatcher] = lambda: central_system.command_dispatcher
app.dependency_overrides[get_llm_intelligence] = lambda: central_system.llm_intelligence
app.dependency_overrides[get_forensic_correlator] = lambda: central_system.forensic_correlator
app.dependency_overrides[get_adaptive_learner] = lambda: central_system.adaptive_learner
app.dependency_overrides[get_coordination_engine] = lambda: central_system.coordination_engine

# Include API routes
app.include_router(api_router)

# Include Admin routes
app.include_router(admin_router)

# Serve static files for admin console
app.mount("/admin/static", StaticFiles(directory="admin/static"), name="static")

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Central Intelligence System API",
        "version": "1.0.0",
        "docs": "/docs",
        "admin_console": "/admin/",
        "websocket": "/ws/{client_id}",
        "api_endpoints": "/api/v1/*"
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "service": "Central Intelligence System"
    }

# WebSocket endpoint with central_system dependency
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for agent communication"""
    global central_system
    if central_system:
        await central_system.websocket_manager.connect_client(websocket, client_id)
        try:
            while True:
                message = await websocket.receive_text()
                await central_system.websocket_manager.process_client_message(websocket, client_id, message)
        except WebSocketDisconnect:
            await central_system.websocket_manager.disconnect_client(client_id)
        except Exception as e:
            logging.getLogger("central_system").error(f"WebSocket error for {client_id}: {e}")
            await central_system.websocket_manager.disconnect_client(client_id)
    else:
        await websocket.close(code=1008, reason="System not initialized")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"\nReceived signal {signum}, shutting down...")
    sys.exit(0)

if __name__ == "__main__":
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run FastAPI application with uvicorn
    uvicorn.run(
        "main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=True,  # Enable auto-reload in development
        log_level="info"
    )