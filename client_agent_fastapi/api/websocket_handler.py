# api/websocket_handler.py
import json
from fastapi import WebSocket
from typing import Dict, List
from api.dependencies import get_agent

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"✅ WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"❌ WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            print(f"Error sending message: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                print(f"Error broadcasting message: {e}")
                disconnected.append(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)

    async def handle_message(self, message: dict, websocket: WebSocket):
        """Handle incoming WebSocket messages"""
        try:
            message_type = message.get("type")
            agent = get_agent()
            
            if not agent:
                await self.send_personal_message(json.dumps({
                    "type": "ERROR",
                    "message": "Agent not initialized"
                }), websocket)
                return

            if message_type == "GET_STATUS":
                # Send current agent status
                status_data = {
                    "type": "AGENT_STATUS",
                    "data": {
                        "agent_id": agent.agent_id,
                        "status": agent.status,
                        "monitoring_active": agent.monitoring_active,
                        "monitor_directory": agent.monitor_directory,
                        "detection_stats": agent.detection_stats,  # Fixed: was agent.stats
                        "last_alert": agent.last_alert,
                        "timestamp": agent.last_alert_timestamp if hasattr(agent, 'last_alert_timestamp') else None
                    }
                }
                await self.send_personal_message(json.dumps(status_data), websocket)
            
            elif message_type == "GET_ANALYTICS":
                # Send detection analytics
                analytics = await agent.get_detection_analytics()
                analytics_data = {
                    "type": "DETECTION_ANALYTICS",
                    "data": analytics
                }
                await self.send_personal_message(json.dumps(analytics_data), websocket)
            
            elif message_type == "START_MONITORING":
                if not agent.monitor_directory:
                    await self.send_personal_message(json.dumps({
                        "type": "ERROR",
                        "message": "Agent not configured. Please configure first."
                    }), websocket)
                else:
                    await agent.start_background_monitoring()
                    await self.broadcast({
                        "type": "MONITORING_STARTED",
                        "message": "Real-time monitoring started"
                    })
            
            elif message_type == "STOP_MONITORING":
                agent.monitoring_active = False
                if agent.monitor:
                    agent.monitor.stop()
                await self.broadcast({
                    "type": "MONITORING_STOPPED",
                    "message": "Monitoring stopped"
                })
            
            elif message_type == "SIMULATE_THREAT":
                # Simulate a demo threat
                threat_data = {
                    "threat_type": "DEMO_SUPERVISED_DETECTION",
                    "threat_level": "critical",
                    "confidence": 0.95,
                    "primary_detection_layer": "supervised",
                    "malware_process": "demo_crypto_locker.exe",
                    "files_modified": 25,
                    "encryption_detected": True,
                    "ransom_note_found": True
                }
                await agent.evaluate_threat(threat_data)
            
            else:
                await self.send_personal_message(json.dumps({
                    "type": "ERROR",
                    "message": f"Unknown message type: {message_type}"
                }), websocket)
                
        except Exception as e:
            print(f"WebSocket message handling error: {e}")
            await self.send_personal_message(json.dumps({
                "type": "ERROR",
                "message": f"Internal server error: {str(e)}"
            }), websocket)

# Global WebSocket manager instance
websocket_manager = ConnectionManager()