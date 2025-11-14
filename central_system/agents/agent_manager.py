# import logging
# import json  # ✅ ADD THIS IMPORT
# from typing import Dict, List, Any, Optional
# from datetime import datetime, timedelta
# from models.schemas import AgentRegistration
# from models.database import DatabaseManager

# class AgentManager:
#     def __init__(self, db: DatabaseManager):
#         self.db = db
#         self.logger = logging.getLogger(__name__)
#         self.connected_agents: Dict[str, Any] = {}  # agent_id -> websocket

#     async def register_agent(self, agent_data: AgentRegistration, websocket: Any = None) -> bool:
#         """Register a new agent with the central system"""
#         try:
#             # Register in database
#             success = await self.db.register_agent(agent_data)
#             if success and websocket:
#                 self.connected_agents[agent_data.agent_id] = websocket
                
#             return success
#         except Exception as e:
#             self.logger.error(f"Error in agent registration: {e}")
#             return False

#     async def unregister_agent(self, agent_id: str):
#         """Unregister an agent (on disconnect)"""
#         if agent_id in self.connected_agents:
#             del self.connected_agents[agent_id]
#             self.logger.info(f"Agent unregistered: {agent_id}")

#     async def get_agent_websocket(self, agent_id: str) -> Optional[Any]:
#         """Get websocket for a connected agent"""
#         return self.connected_agents.get(agent_id)

#     async def get_all_agents(self) -> List[Dict[str, Any]]:
#         """Get all registered agents from database"""
#         try:
#             return await self.db.get_all_agents()
#         except Exception as e:
#             self.logger.error(f"Error getting all agents: {e}")
#             return []

#     async def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
#         """Get agent by ID"""
#         try:
#             return await self.db.get_agent(agent_id)
#         except Exception as e:
#             self.logger.error(f"Error getting agent: {e}")
#             return None

#     async def get_network_topology(self) -> Dict[str, Any]:
#         """Get current network topology and agent relationships"""
#         agents = await self.get_all_agents()
        
#         topology = {
#             'total_agents': len(agents),
#             'online_agents': len([a for a in agents if a.get('status') == 'online']),
#             'agents_by_department': {},
#             'critical_assets': [],
#             'connected_agents': list(self.connected_agents.keys())
#         }
        
#         # Group by department
#         for agent in agents:
#             dept = agent.get('department', 'unknown')
#             if dept not in topology['agents_by_department']:
#                 topology['agents_by_department'][dept] = []
#             topology['agents_by_department'][dept].append(agent['agent_id'])
            
#             # Collect critical assets
#             topology['critical_assets'].extend(agent.get('critical_assets', []))
        
#         return topology

#     async def get_related_agents(self, agent_id: str) -> List[str]:
#         """Get agents that are related to the given agent"""
#         topology = await self.get_network_topology()
#         agent = await self.get_agent(agent_id)
        
#         if not agent:
#             return []
        
#         # Return agents in same department
#         department = agent.get('department')
#         return topology['agents_by_department'].get(department, [])

#     async def update_agent_status(self, agent_id: str, status: str, threat_level: str = None):
#         """Update agent status and threat level"""
#         # This would update the agent in the database
#         # Implementation depends on database structure
#         pass

#     async def update_agent_heartbeat(self, agent_id: str):
#         """Update agent heartbeat timestamp"""
#         # This would update the last_seen timestamp in database
#         pass

#     # 
#     async def broadcast_to_agents(self, message: Dict[str, Any], target_agents: List[str] = None):
#         """Broadcast message to specified agents or all agents"""
#         if target_agents is None:
#             target_agents = list(self.connected_agents.keys())
        
#         disconnected_agents = []
        
#         for agent_id in target_agents:
#             websocket = self.connected_agents.get(agent_id)
#             if websocket:
#                 try:
#                     await websocket.send_text(json.dumps(message))  # ✅ Now json is defined
#                 except Exception as e:
#                     self.logger.error(f"Error sending to agent {agent_id}: {e}")
#                     disconnected_agents.append(agent_id)
        
#         # Clean up disconnected agents
#         for agent_id in disconnected_agents:
#             await self.unregister_agent(agent_id)

import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from models.schemas import AgentRegistration
from models.database import DatabaseManager

class AgentManager:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.logger = logging.getLogger(__name__)
        self.connected_agents: Dict[str, Any] = {}  # agent_id -> websocket
        self.agent_registrations: Dict[str, AgentRegistration] = {}  # ✅ ADD THIS to store registration data

    async def register_agent(self, agent_data: AgentRegistration, websocket: Any = None) -> bool:
        """Register a new agent with the central system"""
        try:
            # Register in database
            success = await self.db.register_agent(agent_data)
            if success and websocket:
                self.connected_agents[agent_data.agent_id] = websocket
                self.agent_registrations[agent_data.agent_id] = agent_data  # ✅ STORE REGISTRATION DATA
                
            return success
        except Exception as e:
            self.logger.error(f"Error in agent registration: {e}")
            return False

    # ✅ ADD THIS MISSING METHOD
    async def get_agent_details(self, agent_id: str) -> Dict[str, Any]:
        """Get detailed information about an agent including IP address"""
        try:
            # Check if we have registration data for this agent
            if agent_id in self.agent_registrations:
                agent_data = self.agent_registrations[agent_id]
                return {
                    'agent_id': agent_id,
                    'ip_address': agent_data.ip_address,
                    'hostname': agent_data.hostname,
                    'os_type': agent_data.os_type,
                    'department': agent_data.department,
                    'critical_assets': agent_data.critical_assets,
                    'capabilities': agent_data.capabilities,
                    'status': 'registered',
                    'last_seen': datetime.now().isoformat()
                }
            
            # Fallback: try to get from database
            db_agent = await self.db.get_agent(agent_id)
            if db_agent:
                return {
                    'agent_id': agent_id,
                    'ip_address': db_agent.get('ip_address', 'unknown'),
                    'hostname': db_agent.get('hostname', 'unknown'),
                    'os_type': db_agent.get('os_type', 'unknown'),
                    'department': db_agent.get('department', 'unknown'),
                    'critical_assets': db_agent.get('critical_assets', []),
                    'capabilities': db_agent.get('capabilities', []),
                    'status': db_agent.get('status', 'unknown'),
                    'last_seen': db_agent.get('last_seen', 'unknown')
                }
            
            # Final fallback
            return {
                'agent_id': agent_id,
                'ip_address': 'unknown',
                'hostname': 'unknown',
                'os_type': 'unknown',
                'department': 'unknown',
                'critical_assets': [],
                'capabilities': [],
                'status': 'unknown',
                'last_seen': 'unknown'
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agent details for {agent_id}: {e}")
            return {
                'agent_id': agent_id,
                'ip_address': 'unknown',
                'hostname': 'unknown', 
                'os_type': 'unknown',
                'department': 'unknown',
                'critical_assets': [],
                'capabilities': [],
                'status': 'error',
                'last_seen': 'unknown'
            }

    async def unregister_agent(self, agent_id: str):
        """Unregister an agent (on disconnect)"""
        if agent_id in self.connected_agents:
            del self.connected_agents[agent_id]
        if agent_id in self.agent_registrations:  # ✅ ALSO CLEAN UP REGISTRATION
            del self.agent_registrations[agent_id]
        self.logger.info(f"Agent unregistered: {agent_id}")

    # ... rest of your existing methods remain the same ...
    async def get_agent_websocket(self, agent_id: str) -> Optional[Any]:
        """Get websocket for a connected agent"""
        return self.connected_agents.get(agent_id)

    async def get_all_agents(self) -> List[Dict[str, Any]]:
        """Get all registered agents from database"""
        try:
            return await self.db.get_all_agents()
        except Exception as e:
            self.logger.error(f"Error getting all agents: {e}")
            return []

    async def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get agent by ID"""
        try:
            return await self.db.get_agent(agent_id)
        except Exception as e:
            self.logger.error(f"Error getting agent: {e}")
            return None

    async def get_network_topology(self) -> Dict[str, Any]:
        """Get current network topology and agent relationships"""
        agents = await self.get_all_agents()
        
        topology = {
            'total_agents': len(agents),
            'online_agents': len([a for a in agents if a.get('status') == 'online']),
            'agents_by_department': {},
            'critical_assets': [],
            'connected_agents': list(self.connected_agents.keys())
        }
        
        # Group by department
        for agent in agents:
            dept = agent.get('department', 'unknown')
            if dept not in topology['agents_by_department']:
                topology['agents_by_department'][dept] = []
            topology['agents_by_department'][dept].append(agent['agent_id'])
            
            # Collect critical assets
            topology['critical_assets'].extend(agent.get('critical_assets', []))
        
        return topology

    async def get_related_agents(self, agent_id: str) -> List[str]:
        """Get agents that are related to the given agent"""
        topology = await self.get_network_topology()
        agent = await self.get_agent(agent_id)
        
        if not agent:
            return []
        
        # Return agents in same department
        department = agent.get('department')
        return topology['agents_by_department'].get(department, [])

    async def update_agent_status(self, agent_id: str, status: str, threat_level: str = None):
        """Update agent status and threat level"""
        # This would update the agent in the database
        # Implementation depends on database structure
        pass

    async def update_agent_heartbeat(self, agent_id: str):
        """Update agent heartbeat timestamp"""
        # This would update the last_seen timestamp in database
        pass

    async def broadcast_to_agents(self, message: Dict[str, Any], target_agents: List[str] = None):
        """Broadcast message to specified agents or all agents"""
        if target_agents is None:
            target_agents = list(self.connected_agents.keys())
        
        disconnected_agents = []
        
        for agent_id in target_agents:
            websocket = self.connected_agents.get(agent_id)
            if websocket:
                try:
                    await websocket.send_text(json.dumps(message))
                except Exception as e:
                    self.logger.error(f"Error sending to agent {agent_id}: {e}")
                    disconnected_agents.append(agent_id)
        
        # Clean up disconnected agents
        for agent_id in disconnected_agents:
            await self.unregister_agent(agent_id)