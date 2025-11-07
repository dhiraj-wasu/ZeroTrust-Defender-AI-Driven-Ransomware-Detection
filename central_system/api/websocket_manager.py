import json
import logging
from typing import Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime

from models.schemas import AgentRegistration, ThreatAlert
from utils.helpers import validate_threat_alert, generate_incident_id

class WebSocketManager:
    def __init__(self, central_system):
        self.central_system = central_system
        self.logger = logging.getLogger(__name__)
        self.connected_clients: Dict[str, WebSocket] = {}
        self.message_handlers = {
            'REGISTER': self._handle_register,
            'THREAT_ALERT': self._handle_threat_alert,
            'STATUS_UPDATE': self._handle_status_update,
            'HEARTBEAT': self._handle_heartbeat,
            'COMMAND_ACK': self._handle_command_ack
        }

    async def connect_client(self, websocket: WebSocket, client_id: str):
        """Accept WebSocket connection and add to connected clients"""
        await websocket.accept()
        self.connected_clients[client_id] = websocket
        self.logger.info(f"Client connected: {client_id}")

    async def disconnect_client(self, client_id: str):
        """Remove client from connected clients"""
        if client_id in self.connected_clients:
            del self.connected_clients[client_id]
            await self.central_system.agent_manager.unregister_agent(client_id)
            self.logger.info(f"Client disconnected: {client_id}")

    async def process_client_message(self, websocket: WebSocket, client_id: str, message: str):
        """Process message from client"""
        try:
            data = json.loads(message)
            message_type = data.get('type')
            
            if message_type in self.message_handlers:
                await self.message_handlers[message_type](websocket, client_id, data)
            else:
                await self._send_error(websocket, f"Unknown message type: {message_type}")
                
        except json.JSONDecodeError:
            await self._send_error(websocket, "Invalid JSON format")
        except Exception as e:
            self.logger.error(f"Error processing message from {client_id}: {e}")
            await self._send_error(websocket, "Internal server error")

    async def _handle_register(self, websocket: WebSocket, client_id: str, data: Dict[str, Any]):
        """Handle agent registration"""
        try:
            agent_data = AgentRegistration(**data['payload'])
            
            # Validate client_id matches agent_id
            if agent_data.agent_id != client_id:
                await self._send_error(websocket, "Client ID does not match agent ID")
                return
            
            # Register agent with central system
            success = await self.central_system.agent_manager.register_agent(agent_data, websocket)
            
            if success:
                response = {
                    'type': 'REGISTRATION_ACK',
                    'status': 'success',
                    'message': f'Agent {agent_data.agent_id} registered successfully',
                    'timestamp': datetime.now().isoformat()
                }
                await websocket.send_text(json.dumps(response))
                self.logger.info(f"Agent registered: {agent_data.agent_id}")
            else:
                await self._send_error(websocket, "Registration failed")
                
        except Exception as e:
            self.logger.error(f"Registration error for {client_id}: {e}")
            await self._send_error(websocket, f"Registration failed: {str(e)}")

    async def _handle_threat_alert(self, websocket: WebSocket, client_id: str, data: Dict[str, Any]):
        """Handle threat alert from agent"""
        try:
            alert_payload = data['payload']
            
            # Validate alert structure
            if not validate_threat_alert(alert_payload):
                await self._send_error(websocket, "Invalid threat alert format")
                return
            
            # Convert to ThreatAlert schema
            threat_alert = ThreatAlert(**alert_payload)
            threat_alert.incident_id = generate_incident_id()
            
            # Process through central system
            incident_response = await self.central_system.process_threat_alert(threat_alert)
            
            # Send response back to agent - PROPERLY FORMATTED
            response = {
                'type': 'INCIDENT_RESPONSE',
                'incident_id': incident_response.get('incident_id'),
                'agent_commands': incident_response.get('agent_commands', []),
                'network_commands': incident_response.get('network_commands', []),
                'risk_assessment': incident_response.get('risk_assessment', {}),
                'llm_analysis': incident_response.get('llm_analysis', {}),
                'correlation_data': incident_response.get('correlation_data', {}),
                'timestamp': datetime.now().isoformat()
            }
            
            await websocket.send_text(json.dumps(response))
            
            self.logger.info(f"Processed threat alert from {threat_alert.agent_id}")
            
        except Exception as e:
            self.logger.error(f"Threat alert processing error for {client_id}: {e}")
            await self._send_error(websocket, f"Alert processing failed: {str(e)}")

    async def _handle_status_update(self, websocket: WebSocket, client_id: str, data: Dict[str, Any]):
        """Handle status update from agent"""
        try:
            update_data = data['payload']
            
            # Update agent status in central system
            await self.central_system.agent_manager.update_agent_status(
                client_id, 
                update_data
            )
            
            response = {
                'type': 'STATUS_ACK',
                'status': 'success',
                'timestamp': datetime.now().isoformat()
            }
            await websocket.send_text(json.dumps(response))
            
        except Exception as e:
            self.logger.error(f"Status update error for {client_id}: {e}")

    async def _handle_heartbeat(self, websocket: WebSocket, client_id: str, data: Dict[str, Any]):
        """Handle heartbeat from agent"""
        try:
            await self.central_system.agent_manager.update_agent_heartbeat(client_id)
            
            response = {
                'type': 'HEARTBEAT_ACK',
                'timestamp': datetime.now().isoformat()
            }
            await websocket.send_text(json.dumps(response))
            
        except Exception as e:
            self.logger.error(f"Heartbeat error for {client_id}: {e}")

    async def _handle_command_ack(self, websocket: WebSocket, client_id: str, data: Dict[str, Any]):
        """Handle command acknowledgment from agent"""
        try:
            ack_data = data['payload']
            command_id = ack_data.get('command_id')
            status = ack_data.get('status')
            
            self.logger.info(f"Command {command_id} acknowledged by {client_id}: {status}")
            
        except Exception as e:
            self.logger.error(f"Command ACK error for {client_id}: {e}")

    async def _send_error(self, websocket: WebSocket, error_message: str):
        """Send error message to client"""
        error_response = {
            'type': 'ERROR',
            'message': error_message,
            'timestamp': datetime.now().isoformat()
        }
        await websocket.send_text(json.dumps(error_response))

    async def send_to_agent(self, agent_id: str, message: Dict[str, Any]):
        """Send message to specific agent"""
        if agent_id in self.connected_clients:
            try:
                await self.connected_clients[agent_id].send_text(json.dumps(message))
            except Exception as e:
                self.logger.error(f"Error sending to agent {agent_id}: {e}")
                await self.disconnect_client(agent_id)

    async def broadcast_to_agents(self, message: Dict[str, Any], agent_ids: list = None):
        """Broadcast message to multiple agents"""
        targets = agent_ids if agent_ids else list(self.connected_clients.keys())
        
        for agent_id in targets:
            await self.send_to_agent(agent_id, message)