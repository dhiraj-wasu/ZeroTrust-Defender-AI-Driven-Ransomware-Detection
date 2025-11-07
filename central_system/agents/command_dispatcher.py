import logging
import json
from typing import Dict, List, Any
from datetime import datetime
from models.schemas import BroadcastMessage, ThreatLevel

class CommandDispatcher:
    def __init__(self, agent_manager):
        self.agent_manager = agent_manager
        self.logger = logging.getLogger(__name__)

    async def dispatch_agent_command(self, agent_id: str, commands: List[str], incident_id: str = None):
        """Dispatch commands to a specific agent"""
        message = {
            'type': 'AGENT_COMMANDS',
            'incident_id': incident_id,
            'commands': commands,
            'timestamp': datetime.now().isoformat()
        }
        
        await self.agent_manager.broadcast_to_agents(
            json.dumps(message), 
            [agent_id]
        )
        
        self.logger.info(f"Dispatched {len(commands)} commands to agent {agent_id}")

    async def broadcast_network_incident(self, incident_data: Dict[str, Any]):
        """Broadcast network-wide incident notification"""
        broadcast_msg = BroadcastMessage(
            message_type="NETWORK_SECURITY_INCIDENT",
            incident_id=incident_data['incident_id'],
            threat_level=ThreatLevel(incident_data['threat_level']),
            affected_agent=incident_data['affected_agent'],
            # affected_agent_ip=incident_data['affected_agent_ip'],
            required_actions=incident_data['required_actions'],
            duration=incident_data.get('duration', 'emergency_1hour'),
            updates_every=incident_data.get('updates_every', '5_minutes')
        )
        
        message = {
            'type': 'NETWORK_INCIDENT_BROADCAST',
            'payload': broadcast_msg.dict(),
            'timestamp': datetime.now().isoformat()
        }
        
        await self.agent_manager.broadcast_to_agents(json.dumps(message))
        self.logger.info(f"Broadcast network incident: {incident_data['incident_id']}")

    async def execute_emergency_protocol(self, incident_response: Dict[str, Any]):
        """Execute emergency defense protocol"""
        risk_score = incident_response['risk_assessment'].get('risk_score', 0)
        
        if risk_score >= 8.0:
            # Critical threat - aggressive containment
            network_commands = [
                'block_p2p_communications',
                'enable_enhanced_zero_trust',
                'activate_preemptive_file_protection',
                'isolate_critical_infrastructure',
                'trigger_emergency_backups'
            ]
        elif risk_score >= 5.0:
            # High threat - targeted containment
            network_commands = [
                'restrict_lateral_movement',
                'enable_process_whitelisting',
                'lock_sensitive_directories',
                'increase_monitoring_sensitivity'
            ]
        else:
            # Medium/Low threat - enhanced monitoring
            network_commands = [
                'enable_preventive_protection',
                'monitor_similar_patterns',
                'ready_isolation_protocols'
            ]
        
        # Dispatch to affected agents
        affected_agents = incident_response['risk_assessment'].get('exposed_agents', [])
        for agent_id in affected_agents:
            await self.dispatch_agent_command(
                agent_id, 
                network_commands,
                incident_response['incident_id']
            )