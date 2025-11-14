# api/endpoints.py
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import os
from datetime import datetime

# Use dependency injection instead of direct import
from api.dependencies import get_agent

router = APIRouter()

# Pydantic models
class DemoConfig(BaseModel):
    monitor_directory: str
    backup_directory: str
    important_folders: List[str] = []

class ThreatSimulation(BaseModel):
    threat_type: str
    threat_level: str = "critical"
    confidence: float = 0.95
    malware_process: str = "crypto_locker.exe"

class CommandExecution(BaseModel):
    commands: List[str]

@router.get("/status")
async def get_agent_status(agent = Depends(get_agent)):
    """Get agent status"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    return {
        "agent_id": agent.agent_id,
        "status": agent.status,
        "monitoring_active": agent.monitoring_active,
        "monitor_directory": agent.monitor_directory,
        "detection_stats": agent.detection_stats,  # Fixed: was agent.stats
        "last_alert": agent.last_alert,
        "last_alert_timestamp": agent.last_alert_timestamp,
        "timestamp": datetime.now().isoformat()
    }
@router.get("/alerts/recent")
async def get_recent_alerts(agent = Depends(get_agent)):
    """Get recent alerts"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    return {
        "last_alert": agent.last_alert,
        "last_alert_timestamp": agent.last_alert_timestamp,
        "total_threats": agent.detection_stats["total_detections"]  # Fixed: was agent.stats
    }

@router.post("/configure")
async def configure_agent(config: DemoConfig, agent = Depends(get_agent)):
    """Configure agent for demo"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    try:
        result = await agent.setup_demo_configuration(config.dict())
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Configuration failed: {str(e)}")

@router.post("/start-monitoring")
async def start_monitoring(background_tasks: BackgroundTasks, agent = Depends(get_agent)):
    """Start monitoring"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    if not agent.monitor_directory:
        raise HTTPException(status_code=400, detail="Agent not configured")
    
    background_tasks.add_task(agent.start_background_monitoring)
    return {"status": "started", "message": "Monitoring started"}

@router.post("/stop-monitoring")
async def stop_monitoring(agent = Depends(get_agent)):
    """Stop monitoring"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    agent.monitoring_active = False
    if agent.monitor:
        agent.monitor.stop()
    return {"status": "stopped", "message": "Monitoring stopped"}

@router.post("/simulate-threat")
async def simulate_threat(simulation: ThreatSimulation, agent = Depends(get_agent)):
    """Simulate a threat for demo purposes"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    threat_data = {
        "threat_type": simulation.threat_type,
        "threat_level": simulation.threat_level,
        "confidence": simulation.confidence,
        "malware_process": simulation.malware_process,
        "files_modified": 47,
        "encryption_detected": True,
        "ransom_note_found": True
    }
    
    await agent.evaluate_threat(threat_data)
    return {"status": "simulated", "threat_data": threat_data}

@router.post("/execute-commands")
async def execute_commands(command: CommandExecution, agent = Depends(get_agent)):
    """Execute commands (simulating central system commands)"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    command_data = {
        "type": "AGENT_COMMANDS",
        "commands": command.commands,
        "timestamp": datetime.now().isoformat()
    }
    
    await agent.execute_central_command(command_data)
    return {"status": "executed", "commands": command.commands}

@router.get("/backup/list")
async def list_backups(agent = Depends(get_agent)):
    """List available backups"""
    if not agent or not agent.backup_manager:
        raise HTTPException(status_code=400, detail="Backup manager not initialized")
    
    backups = await agent.backup_manager.list_backups()
    return {"backups": backups}

@router.post("/backup/create")
async def create_backup(agent = Depends(get_agent)):
    """Create manual backup"""
    if not agent or not agent.backup_manager:
        raise HTTPException(status_code=400, detail="Backup manager not initialized")
    
    backup_path = await agent.backup_manager.create_emergency_backup()
    return {"status": "created", "backup_path": backup_path}

@router.get("/system/info")
async def get_system_info(agent = Depends(get_agent)):
    """Get system information"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    return await agent.central_client.get_system_info()

@router.get("/alerts/recent")
async def get_recent_alerts(agent = Depends(get_agent)):
    """Get recent alerts"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    return {
        "last_alert": agent.last_alert,
        "total_threats": agent.detection_stats["total_detections"]  # Fixed: was agent.stats
    }

@router.post("/zero-trust/enable")
async def enable_zero_trust(agent = Depends(get_agent)):
    """Enable zero-trust mode"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    if agent.zero_trust.enable_emergency_mode():
        return {"status": "enabled", "message": "Zero-trust mode enabled"}
    else:
        raise HTTPException(status_code=500, detail="Failed to enable zero-trust mode")

@router.post("/network/isolation")
async def toggle_network_isolation(agent = Depends(get_agent)):
    """Toggle network isolation"""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    if agent.network_isolation.is_isolated:
        agent.network_isolation.restore_network()
        return {"status": "restored", "message": "Network connectivity restored"}
    else:
        if agent.network_isolation.isolate_machine():
            return {"status": "isolated", "message": "Network isolation enabled"}
        else:
            raise HTTPException(status_code=500, detail="Failed to isolate network")