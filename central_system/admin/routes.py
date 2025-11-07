import logging
import json
from typing import List, Dict, Any
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from datetime import datetime, timedelta

from models.database import DatabaseManager
from agents.agent_manager import AgentManager
from core.adaptive_learner import AdaptiveLearner
from api.dependencies import (
    get_database,
    get_agent_manager,
    get_adaptive_learner
)

# Create admin router
router = APIRouter(prefix="/admin", tags=["admin"])
logger = logging.getLogger(__name__)

# Setup templates
templates = Jinja2Templates(directory="admin/templates")

@router.get("/", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: DatabaseManager = Depends(get_database),
    agent_manager: AgentManager = Depends(get_agent_manager)
):
    """Admin dashboard main page"""
    try:
        # Get system statistics
        agents = await db.get_all_agents()  # Use db directly since agent_manager method is missing
        recent_alerts = await db.get_recent_alerts(hours=24)
        
        # Calculate stats
        stats = {
            'total_agents': len(agents),
            'online_agents': len([a for a in agents if a.get('status') == 'online']),
            'total_incidents': len(recent_alerts),
            'critical_incidents': len([a for a in recent_alerts if a.get('threat_level') == 'critical']),
            'emergency_active': len([a for a in recent_alerts if a.get('threat_level') in ['critical', 'high']])
        }
        
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "stats": stats,
                "recent_incidents": recent_alerts[:5],
                "agents": agents[:10]
            }
        )
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)}
        )

@router.get("/agents", response_class=HTMLResponse)
async def admin_agents(
    request: Request,
    db: DatabaseManager = Depends(get_database),
    agent_manager: AgentManager = Depends(get_agent_manager)
):
    """Agents management page"""
    try:
        agents = await db.get_all_agents()  # Use db directly
        
        # Create simple topology since agent_manager.get_network_topology might not exist
        topology = {
            'total_agents': len(agents),
            'online_agents': len([a for a in agents if a.get('status') == 'online']),
            'agents_by_department': {},
            'critical_assets': [],
            'connected_agents': []
        }
        
        # Group by department
        for agent in agents:
            dept = agent.get('department', 'unknown')
            if dept not in topology['agents_by_department']:
                topology['agents_by_department'][dept] = []
            topology['agents_by_department'][dept].append(agent['agent_id'])
            
            # Collect critical assets
            topology['critical_assets'].extend(agent.get('critical_assets', []))
        
        return templates.TemplateResponse(
            "agents.html",
            {
                "request": request,
                "agents": agents,
                "topology": topology
            }
        )
    except Exception as e:
        logger.error(f"Admin agents error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)}
        )

@router.get("/incidents", response_class=HTMLResponse)
async def admin_incidents(
    request: Request,
    db: DatabaseManager = Depends(get_database)
):
    """Incidents management page"""
    try:
        incidents = await db.get_recent_alerts(hours=168)  # 1 week
        
        # Group by severity
        incidents_by_severity = {
            'critical': [i for i in incidents if i.get('threat_level') == 'critical'],
            'high': [i for i in incidents if i.get('threat_level') == 'high'],
            'medium': [i for i in incidents if i.get('threat_level') == 'medium'],
            'low': [i for i in incidents if i.get('threat_level') == 'low']
        }
        
        return templates.TemplateResponse(
            "incidents.html",
            {
                "request": request,
                "incidents": incidents,
                "incidents_by_severity": incidents_by_severity,
                "total_count": len(incidents)
            }
        )
    except Exception as e:
        logger.error(f"Admin incidents error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)}
        )

@router.get("/forensic", response_class=HTMLResponse)
async def admin_forensic(
    request: Request,
    db: DatabaseManager = Depends(get_database)
):
    """Forensic analysis page"""
    try:
        incidents = await db.get_recent_alerts(hours=168)
        
        # Extract forensic data
        forensic_data = []
        for incident in incidents:
            forensic = incident.get('forensic_data', {})
            if forensic:
                forensic_data.append({
                    'incident_id': incident.get('incident_id'),
                    'agent_id': incident.get('agent_id'),
                    'timestamp': incident.get('timestamp'),
                    'malware_process': incident.get('malware_process'),
                    'file_patterns': forensic.get('file_access_patterns', {}),
                    'network_connections': forensic.get('network_connections', []),
                    'process_tree': forensic.get('process_tree', [])
                })
        
        return templates.TemplateResponse(
            "forensic.html",
            {
                "request": request,
                "forensic_data": forensic_data,
                "total_forensic_cases": len(forensic_data)
            }
        )
    except Exception as e:
        logger.error(f"Admin forensic error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)}
        )

@router.get("/settings", response_class=HTMLResponse)
async def admin_settings(
    request: Request,
    adaptive_learner: AdaptiveLearner = Depends(get_adaptive_learner)
):
    """System settings page"""
    try:
        performance_report = await adaptive_learner.get_performance_report()
        
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "performance": performance_report,
                "system_info": {
                    "version": "1.0.0",
                    "started": datetime.now().isoformat(),
                    "llm_provider": "OpenAI"
                }
            }
        )
    except Exception as e:
        logger.error(f"Admin settings error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)}
        )

# API endpoints for real-time data
@router.get("/api/stats")
async def get_system_stats(
    db: DatabaseManager = Depends(get_database)
):
    """Get real-time system statistics"""
    try:
        agents = await db.get_all_agents()
        recent_alerts = await db.get_recent_alerts(hours=24)
        
        return {
            "total_agents": len(agents),
            "online_agents": len([a for a in agents if a.get('status') == 'online']),
            "total_incidents": len(recent_alerts),
            "critical_incidents": len([a for a in recent_alerts if a.get('threat_level') == 'critical']),
            "emergency_active": len([a for a in recent_alerts if a.get('threat_level') in ['critical', 'high']]),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return {
            "total_agents": 0,
            "online_agents": 0,
            "total_incidents": 0,
            "critical_incidents": 0,
            "emergency_active": 0,
            "timestamp": datetime.now().isoformat()
        }

@router.get("/api/incidents/recent")
async def get_recent_incidents(
    db: DatabaseManager = Depends(get_database)
):
    """Get recent incidents for dashboard"""
    try:
        incidents = await db.get_recent_alerts(hours=24)
        return {
            "incidents": incidents[:10],
            "total": len(incidents),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting recent incidents: {e}")
        return {
            "incidents": [],
            "total": 0,
            "timestamp": datetime.now().isoformat()
        }

@router.get("/api/agents/status")
async def get_agents_status(
    db: DatabaseManager = Depends(get_database)
):
    """Get agents status for dashboard"""
    try:
        agents = await db.get_all_agents()
        return {
            "agents": agents,
            "online_count": len([a for a in agents if a.get('status') == 'online']),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting agents status: {e}")
        return {
            "agents": [],
            "online_count": 0,
            "timestamp": datetime.now().isoformat()
        }
@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
async def incident_details(
    request: Request,
    incident_id: str,
    db: DatabaseManager = Depends(get_database)
):
    """Incident details page with processing steps"""
    try:
        # Get incident details
        incidents = await db.get_recent_alerts(hours=168)
        incident = next((inc for inc in incidents if inc.get('incident_id') == incident_id), None)
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Get processing logs
        processing_logs = await db.get_processing_logs(incident_id)
        
        return templates.TemplateResponse(
            "incident_details.html",
            {
                "request": request,
                "incident": incident,
                "processing_logs": processing_logs,
                "incident_id": incident_id
            }
        )
    except Exception as e:
        logger.error(f"Incident details error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)}
        )