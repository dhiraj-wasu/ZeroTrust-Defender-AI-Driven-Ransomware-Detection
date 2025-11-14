import websockets
import json
import asyncio
from datetime import datetime
import os
import aiohttp
from typing import Dict, Any, Optional, List
from utils.config import config
from utils.helpers import SystemHelpers


class CentralSystemClient:
    """Client for communicating with Central Intelligence System"""
    
    def __init__(self):
        self.websocket = None
        self.connected = False
        self.central_ws_url = f"{config.central_system_url}/ws/{config.agent_id}"
        self.central_rest_url = config.central_rest_url
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
        self.heartbeat_interval = 30  # seconds
        
        # Message handlers
        self.message_handlers = {
            "REGISTRATION_ACK": self._handle_registration_ack,
            "NETWORK_INCIDENT_BROADCAST": self._handle_network_broadcast,
            "AGENT_COMMANDS": self._handle_agent_commands,
            "INCIDENT_RESPONSE": self._handle_incident_response,
            "HEARTBEAT_ACK": self._handle_heartbeat_ack
        }
        
        # Command handlers
        self.command_handlers = {
            "maintain_full_isolation": self._handle_full_isolation,
            "begin_forensic_collection": self._handle_forensic_collection,
            "prepare_deep_scan_recovery": self._handle_deep_scan_recovery,
            "do_not_reconnect_network": self._handle_network_isolation,
            "enable_enterprise_protection_mode": self._handle_enterprise_protection,
            "update_detection_models": self._handle_update_models,
            "block_specific_ip": self._handle_block_ip
        }

    async def connect(self) -> bool:
        """Connect to central system with timeout and error handling"""
        try:
            print(f"🔄 Connecting to {self.central_ws_url}")
            
            # Add connection timeout and better error handling
            self.websocket = await asyncio.wait_for(
                websockets.connect(self.central_ws_url),
                timeout=10.0  # 10 second timeout
            )
            
            self.connected = True
            self.reconnect_attempts = 0
            
            # Register with central system
            await self._register_agent()
            
            # Start message listener
            asyncio.create_task(self._listen_for_messages())
            
            # Start heartbeat
            asyncio.create_task(self._start_heartbeat())
            
            print("✅ Connected to Central Intelligence System")
            return True
            
        except asyncio.TimeoutError:
            print("❌ Connection timeout - central system not responding")
            self.connected = False
            return False
        except ConnectionRefusedError:
            print("❌ Connection refused - is central system running?")
            self.connected = False
            return False
        except Exception as e:
            print(f"❌ Failed to connect to central system: {e}")
            self.connected = False
            return False

    async def _register_agent(self):
        """Register agent with central system"""
        registration_data = {
            "type": "REGISTER",
            "payload": self.get_system_info()
        }
        
        await self.websocket.send(json.dumps(registration_data))
        print("📝 Agent registration sent to central system")

    async def send_threat_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send threat alert to central system"""
        if not self.connected:
            print("⚠️ Not connected to central system, cannot send alert")
            return False
        
        try:
            await self.websocket.send(json.dumps(alert_data))
            print("📡 Threat alert sent to central system")
            return True
        except Exception as e:
            print(f"❌ Failed to send threat alert: {e}")
            await self._handle_connection_failure()
            return False

    async def send_heartbeat(self) -> bool:
        """Send heartbeat to central system"""
        if not self.connected:
            return False
        
        try:
            heartbeat_data = {
                "type": "HEARTBEAT",
                "payload": {
                    "agent_id": config.agent_id,
                    "status": "healthy",
                    "timestamp": datetime.now().isoformat(),
                    "system_metrics": self._get_system_metrics()
                }
            }
            
            await self.websocket.send(json.dumps(heartbeat_data))
            return True
        except Exception as e:
            print(f"❌ Failed to send heartbeat: {e}")
            await self._handle_connection_failure()
            return False

    async def _listen_for_messages(self):
        """Listen for messages from central system"""
        while self.connected:
            try:
                message = await asyncio.wait_for(
                    self.websocket.recv(), 
                    timeout=1.0
                )
                await self._handle_message(message)
            except asyncio.TimeoutError:
                continue  # No message, continue listening
            except Exception as e:
                print(f"❌ Error in message listener: {e}")
                await self._handle_connection_failure()
                break

    async def _handle_message(self, message: str):
        """Handle incoming message from central system"""
        try:
            message_data = json.loads(message)
            message_type = message_data.get("type")
            
            print(f"📨 Received message: {message_type}")
            
            # Call appropriate handler
            handler = self.message_handlers.get(message_type)
            if handler:
                await handler(message_data)
            else:
                print(f"🤔 No handler for message type: {message_type}")
                
        except json.JSONDecodeError:
            print("❌ Failed to parse JSON message from central system")
        except Exception as e:
            print(f"❌ Error handling message: {e}")

    async def _handle_registration_ack(self, message_data: Dict[str, Any]):
        """Handle registration acknowledgment"""
        payload = message_data.get("payload", {})
        status = payload.get("status", "")
        message = payload.get("message", "")
        print(f"📨 Registration ACK: status={status}, message={message}")
        if status == "success":
            print("✅ Agent registered successfully with central system")
        else:
            print(f"❌ Agent registration failed: {message}")

    async def _handle_network_broadcast(self, message_data: Dict[str, Any]):
        """Handle network incident broadcast"""
        payload = message_data.get("payload", {})
        
        print("\n" + "="*60)
        print("🎯 CENTRAL SYSTEM - NETWORK BROADCAST")
        print("="*60)
        print(f"🆔 Incident: {payload.get('incident_id', 'Unknown')}")
        print(f"🔴 Threat Level: {payload.get('threat_level', 'unknown')}")
        print(f"🖥️  Affected Agent: {payload.get('affected_agent', 'Unknown')}")
        print(f"🌐 Agent IP: {payload.get('affected_agent_ip', 'Unknown')}")
        print(f"🦠 Malware: {payload.get('malware_process', 'Unknown')}")
        print(f"📊 Confidence: {payload.get('detection_confidence', 0) * 100}%")
        
        required_actions = payload.get('required_actions', [])
        if required_actions:
            print("🚨 Required Actions:")
            for action in required_actions:
                print(f"   • {action}")
        
        print(f"⏰ Duration: {payload.get('duration', 'Unknown')}")
        print(f"📡 Updates: {payload.get('updates_every', 'Unknown')}")
        print("="*60)

    async def _handle_agent_commands(self, message_data: Dict[str, Any]):
        """Handle agent-specific commands"""
        commands = message_data.get("commands", [])
        incident_id = message_data.get("incident_id", "Unknown")
        
        print(f"\n🔧 Received {len(commands)} commands for incident {incident_id}:")
        
        for command in commands:
            print(f"   • {command}")
            handler = self.command_handlers.get(command)
            if handler:
                await handler(incident_id)
            else:
                print(f"   ⚠️ No handler for command: {command}")

    async def _handle_incident_response(self, message_data: Dict[str, Any]):
        """Handle comprehensive incident response"""
        print("\n" + "="*60)
        print("🎯 CENTRAL SYSTEM - INCIDENT RESPONSE")
        print("="*60)
        print(f"🆔 Incident ID: {message_data.get('incident_id', 'Unknown')}")
        
        # Agent commands
        agent_cmds = message_data.get('agent_commands', [])
        if agent_cmds:
            print(f"🖥️  Agent Commands ({len(agent_cmds)}):")
            for cmd in agent_cmds:
                print(f"   • {cmd}")
        
        # Network commands
        network_cmds = message_data.get('network_commands', [])
        if network_cmds:
            print(f"🌐 Network Commands ({len(network_cmds)}):")
            for cmd in network_cmds:
                print(f"   • {cmd}")
        
        # Risk assessment
        risk_data = message_data.get('risk_assessment', {})
        if risk_data:
            print("📊 Risk Assessment:")
            print(f"   • Level: {risk_data.get('level', 'Unknown')}")
            print(f"   • Score: {risk_data.get('score', 'Unknown')}")
            print(f"   • Urgency: {risk_data.get('urgency', 'Unknown')}")
        
        # LLM Analysis
        llm_analysis = message_data.get('llm_analysis', {})
        if llm_analysis:
            print("🧠 LLM Analysis:")
            print(f"   • Attack: {llm_analysis.get('attack_classification', 'Unknown')}")
            print(f"   • Confidence: {llm_analysis.get('confidence_score', 0) * 100}%")
            print(f"   • Impact: {llm_analysis.get('business_impact', 'Unknown')}")
        
        print("="*60)

    async def _handle_heartbeat_ack(self, message_data: Dict[str, Any]):
        """Handle heartbeat acknowledgment"""
        # Update last heartbeat time
        pass

    async def _handle_full_isolation(self, incident_id: str):
        """Handle full isolation command"""
        print(f"🔒 Executing full isolation for incident {incident_id}")
        # Implementation would call network isolation and zero-trust

    async def _handle_forensic_collection(self, incident_id: str):
        """Handle forensic collection command"""
        print(f"🔍 Starting forensic collection for incident {incident_id}")
        # Implementation would collect system forensics

    async def _handle_deep_scan_recovery(self, incident_id: str):
        """Handle deep scan recovery command"""
        print(f"🔄 Preparing deep scan recovery for incident {incident_id}")
        # Implementation would prepare recovery procedures

    async def _handle_network_isolation(self, incident_id: str):
        """Handle network isolation command"""
        print(f"🌐 Maintaining network isolation for incident {incident_id}")
        # Implementation would ensure network remains isolated

    async def _handle_enterprise_protection(self, incident_id: str):
        """Handle enterprise protection mode command"""
        print(f"🏢 Enabling enterprise protection mode for incident {incident_id}")
        # Implementation would enable enterprise zero-trust

    async def _handle_update_models(self, incident_id: str):
        """Handle update detection models command"""
        print(f"🔄 Updating detection models for incident {incident_id}")
        # Implementation would update ML models

    async def _handle_block_ip(self, incident_id: str):
        """Handle block IP command"""
        print(f"🚫 Blocking specific IP for incident {incident_id}")
        # Implementation would block specified IP

    async def _start_heartbeat(self):
        """Start periodic heartbeat"""
        while self.connected:
            await self.send_heartbeat()
            await asyncio.sleep(self.heartbeat_interval)

    async def _handle_connection_failure(self):
        """Handle connection failure"""
        self.connected = False
        self.reconnect_attempts += 1
        
        if self.reconnect_attempts <= self.max_reconnect_attempts:
            print(f"🔄 Attempting reconnect ({self.reconnect_attempts}/{self.max_reconnect_attempts})...")
            await asyncio.sleep(5)  # Wait before reconnect
            await self.connect()
        else:
            print("❌ Max reconnection attempts reached")

    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get system metrics for heartbeat"""
        import psutil
        
        return {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "active_processes": len(psutil.pids()),
            "boot_time": psutil.boot_time()
        }

    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for registration"""
        system_info = SystemHelpers.get_system_info()
        
        return {
            "agent_id": config.agent_id,
            "hostname": system_info.get("hostname", "UNKNOWN"),
            "ip_address": system_info.get("local_ip", "127.0.0.1"),
            "os_type": system_info.get("os_type", "Unknown"),
            "department": "Finance",
            "critical_assets": ["financial_data", "customer_records", "transaction_database"],
            "capabilities": [
                "file_monitoring", "process_analysis", "network_monitoring", 
                "memory_scanning", "quad_layer_detection", "automated_response"
            ],
            "last_seen": datetime.now().isoformat(),
            "agent_version": config.agent_version
        }

    async def disconnect(self):
        """Disconnect from central system"""
        self.connected = False
        if self.websocket:
            await self.websocket.close()
        print("🔌 Disconnected from central system")

    async def send_command_ack(self, command_id: str, status: str, message: str):
        """Send command acknowledgment to central system"""
        if not self.connected:
            return False
        
        try:
            ack_data = {
                "type": "COMMAND_ACK",
                "payload": {
                    "command_id": command_id,
                    "agent_id": config.agent_id,
                    "status": status,
                    "message": message,
                    "timestamp": datetime.now().isoformat()
                }
            }
            
            await self.websocket.send(json.dumps(ack_data))
            return True
        except Exception as e:
            print(f"❌ Failed to send command ACK: {e}")
            return False

    def get_connection_status(self) -> Dict[str, Any]:
        """Get connection status"""
        return {
            "connected": self.connected,
            "reconnect_attempts": self.reconnect_attempts,
            "max_reconnect_attempts": self.max_reconnect_attempts,
            "central_system_url": self.central_ws_url
        }