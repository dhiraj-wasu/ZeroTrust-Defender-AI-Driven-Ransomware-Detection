import logging
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime

from models.schemas import ThreatAlert
from utils.helpers import generate_incident_id
from api.dependencies import (
    get_agent_manager,
    get_coordination_engine,
    get_adaptive_learner,
    get_forensic_correlator,
    get_llm_intelligence
)
from agents.agent_manager import AgentManager
from core.coordination_engine import CoordinationEngine
from core.adaptive_learner import AdaptiveLearner
from core.forensic_correlator import ForensicCorrelator
from core.llm_intelligence import LLMIntelligence

# Create FastAPI router
router = APIRouter(prefix="/api/v1", tags=["central-intelligence"])
logger = logging.getLogger(__name__)

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "service": "Central Intelligence System"
    }

@router.get("/agents")
async def get_agents(
    agent_manager: AgentManager = Depends(get_agent_manager)
):
    """Get all registered agents"""
    agents = await agent_manager.get_all_agents()
    return {
        "agents": agents,
        "total_count": len(agents),
        "timestamp": datetime.now().isoformat()
    }

@router.get("/agents/{agent_id}")
async def get_agent(
    agent_id: str,
    agent_manager: AgentManager = Depends(get_agent_manager)
):
    """Get specific agent details"""
    agent = await agent_manager.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent

@router.get("/topology")
async def get_network_topology(
    agent_manager: AgentManager = Depends(get_agent_manager)
):
    """Get network topology"""
    topology = await agent_manager.get_network_topology()
    return topology

@router.get("/metrics")
async def get_system_metrics(
    adaptive_learner: AdaptiveLearner = Depends(get_adaptive_learner)
):
    """Get system performance metrics"""
    metrics = await adaptive_learner.get_performance_report()
    return metrics

@router.post("/alerts")
async def create_threat_alert(
    alert_data: ThreatAlert,
    agent_manager: AgentManager = Depends(get_agent_manager),
    coordination_engine: CoordinationEngine = Depends(get_coordination_engine),
    llm_intelligence: LLMIntelligence = Depends(get_llm_intelligence),
    forensic_correlator: ForensicCorrelator = Depends(get_forensic_correlator)
):
    """Submit a threat alert (HTTP endpoint)"""
    try:
        # Generate incident ID
        alert_data.incident_id = generate_incident_id()
        
        # Process through central system pipeline
        correlation_data = await forensic_correlator.correlate_threat(alert_data)
        llm_analysis = await llm_intelligence.analyze_threat(alert_data, correlation_data)
        coordination_result = await coordination_engine.coordinate_response(
            alert_data, llm_analysis, correlation_data
        )
        
        return {
            "incident_id": alert_data.incident_id,
            "status": "processed",
            "actions_taken": coordination_result.get('response_plan', {}).get('infected_agent_commands', []),
            "risk_assessment": coordination_result.get('risk_assessment', {}),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"API alert creation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/agents/{agent_id}/commands")
async def send_agent_commands(
    agent_id: str,
    commands: List[str],
    agent_manager: AgentManager = Depends(get_agent_manager),
    coordination_engine: CoordinationEngine = Depends(get_coordination_engine)
):
    """Send commands to a specific agent"""
    try:
        if not commands:
            raise HTTPException(status_code=400, detail="No commands provided")
        
        # Send commands to agent via coordination engine
        await coordination_engine.command_dispatcher.dispatch_agent_command(
            agent_id, commands
        )
        
        return {
            "status": "commands_sent",
            "agent_id": agent_id,
            "command_count": len(commands),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"API command error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/emergency/activate")
async def activate_emergency_protocol(
    incident_id: str,
    coordination_engine: CoordinationEngine = Depends(get_coordination_engine)
):
    """Activate emergency protocol manually"""
    try:
        # This would trigger emergency protocol in coordination engine
        # For now, we'll log and return success
        logger.warning(f"Manual emergency activation for incident: {incident_id}")
        
        return {
            "status": "emergency_activated",
            "incident_id": incident_id,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Emergency activation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/emergency/deactivate")
async def deactivate_emergency_protocol(
    incident_id: str,
    coordination_engine: CoordinationEngine = Depends(get_coordination_engine)
):
    """Deactivate emergency protocol"""
    try:
        logger.info(f"Manual emergency deactivation for incident: {incident_id}")
        
        return {
            "status": "emergency_deactivated",
            "incident_id": incident_id,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Emergency deactivation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

# REMOVED: WebSocket endpoint from here - it's now only in main.py