#!/usr/bin/env python3
"""
Test Agent for Central Intelligence System - Fixed Double JSON Encoding
"""

import asyncio
import websockets
import json
import uuid
from datetime import datetime

class TestAgent:
    def __init__(self, agent_id="PC-TEST-001", central_server="ws://localhost:8765"):
        self.agent_id = agent_id
        self.central_server = central_server
        self.websocket = None
    
    def generate_incident_id(self):
        """Generate unique incident ID matching central system format"""
        return f"INC-{uuid.uuid4().hex[:8].upper()}"
        
    async def run_test(self):
        """Run comprehensive test with better error handling"""
        try:
            # Connect to central system
            print(f"🔄 Connecting to {self.central_server}/ws/{self.agent_id}")
            websocket = await websockets.connect(f"{self.central_server}/ws/{self.agent_id}")
            self.websocket = websocket
            print(f"✅ CONNECTED to central system as {self.agent_id}")
            
            # Step 1: Register agent
            await self._register_agent(websocket)
            
            # Step 2: Send threat alert
            await self._send_threat_alert(websocket)
            
            # Step 3: Listen for additional messages
            await self._listen_for_messages(websocket)
            
            await websocket.close()
            print("\n🎉 Test completed successfully!")
            
        except asyncio.TimeoutError:
            print("⏰ Timeout waiting for response from central system")
        except websockets.exceptions.ConnectionClosed:
            print("🔌 Connection closed by central system")
        except Exception as e:
            print(f"💥 Test failed: {e}")
            import traceback
            traceback.print_exc()

    async def _register_agent(self, websocket):
        """Register agent with central system"""
        registration_data = {
            "type": "REGISTER",
            "payload": {
                "agent_id": self.agent_id,
                "hostname": "TEST-PC-001",
                "ip_address": "192.168.1.100",
                "os_type": "Windows 10",
                "department": "Finance",
                "critical_assets": ["financial_data", "customer_records", "transaction_database"],
                "capabilities": ["file_monitoring", "process_analysis", "network_monitoring", "memory_scanning"],
                "last_seen": datetime.now().isoformat()
            }
        }
        
        print("\n📝 REGISTERING AGENT...")
        await websocket.send(json.dumps(registration_data))
        
        # Wait for registration response
        response = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        await self._parse_response(response, "REGISTRATION")

    async def _send_threat_alert(self, websocket):
        """Send threat alert to central system"""
        incident_id = self.generate_incident_id()
        
        threat_alert = {
            "type": "THREAT_ALERT", 
            "payload": {
                "agent_id": self.agent_id,
                "incident_id": incident_id,  # ✅ Added incident_id
                "status": "infected",
                "threat_level": "critical",
                "malware_process": "crypto_locker.exe",
                "detection_confidence": 0.92,
                "actions_taken": ["process_killed", "network_isolated", "backup_triggered"],
                "forensic_data": {
                    "process_tree": ["explorer.exe", "crypto_locker.exe", "powershell.exe"],
                    "file_access_patterns": {
                        "files_modified": 47,
                        "encryption_detected": True,
                        "ransom_note_found": True,
                        "extensions_changed": [".encrypted", ".locked"],
                        "suspicious_operations": ["mass_encryption", "file_deletion"]
                    },
                    "network_connections": [
                        {
                            "remote_host": "SERVER-01", 
                            "port": 445, 
                            "protocol": "SMB", 
                            "direction": "outbound",
                            "suspicious": True,
                            "timestamp": datetime.now().isoformat()
                        },
                        {
                            "remote_host": "BACKUP-SRV", 
                            "port": 3389, 
                            "protocol": "RDP", 
                            "direction": "outbound",
                            "suspicious": True,
                            "timestamp": datetime.now().isoformat()
                        }
                    ],
                    "system_metrics": {
                        "cpu_usage": 95,
                        "memory_usage": 87,
                        "disk_activity": "high",
                        "process_count": 142
                    }
                },
                "timestamp": datetime.now().isoformat()
            }
        }
        
        print("\n🚨 SENDING THREAT ALERT...")
        print(f"📋 Agent: {self.agent_id}")
        print(f"🔴 Threat Level: CRITICAL")
        print(f"🦠 Malware: {threat_alert['payload']['malware_process']}")
        print(f"📊 Files Modified: {threat_alert['payload']['forensic_data']['file_access_patterns']['files_modified']}")
        print(f"🔐 Encryption Detected: {threat_alert['payload']['forensic_data']['file_access_patterns']['encryption_detected']}")
        print(f"🌐 Network Connections: {len(threat_alert['payload']['forensic_data']['network_connections'])}")
        
        await websocket.send(json.dumps(threat_alert))
        
        # Wait for response
        print("\n⏳ Waiting for central system response...")
        response = await asyncio.wait_for(websocket.recv(), timeout=30.0)
        
        print(f"\n📨 RAW RESPONSE: {response}")
        await self._parse_response(response, "THREAT_RESPONSE")

    async def _parse_response(self, response, response_source="UNKNOWN"):
        """Parse and display the central system response - FIXED for double JSON encoding"""
        try:
            print(f"\n🔍 Parsing {response_source} response...")
            
            # First, try to parse the response as JSON
            response_data = json.loads(response)
            
            # Check if we got a string that contains JSON (double encoding)
            if isinstance(response_data, str):
                print("🔄 Detected double JSON encoding, parsing inner JSON...")
                try:
                    response_data = json.loads(response_data)  # Parse the inner JSON
                except json.JSONDecodeError:
                    print("❌ Inner content is not valid JSON either")
                    response_data = {"type": "RAW_TEXT", "content": response_data}
            
            print("\n" + "="*60)
            print("🎯 CENTRAL SYSTEM RESPONSE")
            print("="*60)
            
            response_type = response_data.get('type', 'Unknown')
            print(f"📨 Response Type: {response_type}")
            
            if response_type == 'INCIDENT_RESPONSE':
                self._parse_incident_response(response_data)
            elif response_type == 'NETWORK_INCIDENT_BROADCAST':
                self._parse_broadcast_message(response_data)
            elif response_type == 'REGISTRATION_ACK':
                self._parse_registration_response(response_data)
            elif response_type == 'ERROR':
                self._parse_error_response(response_data)
            else:
                print(f"🤔 Unexpected response type:")
                print(json.dumps(response_data, indent=2))
                
        except json.JSONDecodeError as e:
            print(f"❌ Response is not valid JSON: {e}")
            print(f"📄 Raw response was: {response}")

    def _parse_registration_response(self, response_data):
        """Parse registration response"""
        if response_data.get('status') == 'success':
            print("✅ Agent registered successfully")
            print(f"📝 Message: {response_data.get('message')}")
        else:
            print(f"❌ Registration failed: {response_data.get('message')}")

    def _parse_incident_response(self, response_data):
        """Parse incident response from central system"""
        print(f"🆔 Incident ID: {response_data.get('incident_id')}")
        
        # Agent commands
        agent_commands = response_data.get('agent_commands', [])
        print(f"🖥️  Agent Commands ({len(agent_commands)}):")
        for cmd in agent_commands:
            print(f"   • {cmd}")
        
        # Network commands
        network_commands = response_data.get('network_commands', [])
        if network_commands:
            print(f"🌐 Network Commands ({len(network_commands)}):")
            for cmd in network_commands:
                print(f"   • {cmd}")
        
        # Risk assessment
        risk_assessment = response_data.get('risk_assessment', {})
        if risk_assessment:
            print(f"📊 Risk Assessment:")
            print(f"   • Level: {risk_assessment.get('risk_level', 'Unknown')}")
            print(f"   • Score: {risk_assessment.get('risk_score', 0)}/10")
            print(f"   • Urgency: {risk_assessment.get('containment_urgency', 'Unknown')}")
        
        # LLM analysis
        llm_analysis = response_data.get('llm_analysis', {})
        if llm_analysis:
            print(f"🧠 LLM Analysis:")
            print(f"   • Attack: {llm_analysis.get('attack_classification', 'Unknown')}")
            print(f"   • Confidence: {llm_analysis.get('confidence_score', 0) * 100:.1f}%")
            print(f"   • Impact: {llm_analysis.get('business_impact', 'Unknown')}")
            print(f"   • Propagation: {llm_analysis.get('propagation_method', 'Unknown')}")
            print(f"   • Response: {llm_analysis.get('recommended_network_response', 'Unknown')}")
        
        # Correlation data
        correlation_data = response_data.get('correlation_data', {})
        if correlation_data:
            related_alerts = correlation_data.get('related_alerts', [])
            print(f"🔗 Correlation Data: {len(related_alerts)} related alerts")
        
        print("="*60)

    def _parse_broadcast_message(self, msg_data):
        """Parse network broadcast message"""
        payload = msg_data.get('payload', {})
        if not payload:  # Handle case where data is directly in root
            payload = msg_data
        
        print("🔄 NETWORK BROADCAST:")
        print(f"   🆔 Incident: {payload.get('incident_id')}")
        print(f"   🔴 Threat Level: {payload.get('threat_level')}")
        print(f"   🖥️  Affected Agent: {payload.get('affected_agent')}")
        print(f"   🚨 Response Level: {payload.get('response_level', 'AGGRESSIVE_CONTAINMENT')}")
        print(f"   ⏰ Duration: {payload.get('duration', 'emergency_1hour')}")
        print(f"   📡 Updates: {payload.get('updates_every', '5_minutes')}")
        
        required_actions = payload.get('required_actions', [])
        if required_actions:
            print(f"   📋 Required Actions:")
            for action in required_actions:
                print(f"      • {action}")
        
        print("="*60)

    def _parse_error_response(self, response_data):
        """Parse error response from central system"""
        print(f"❌ ERROR: {response_data.get('message')}")
        print(f"⏰ Timestamp: {response_data.get('timestamp')}")

    async def _listen_for_messages(self, websocket):
        """Listen for additional messages like network broadcasts"""
        print("\n👂 Listening for additional messages (15 seconds)...")
        try:
            start_time = asyncio.get_event_loop().time()
            while (asyncio.get_event_loop().time() - start_time) < 15:
                try:
                    additional_msg = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    print(f"\n📢 ADDITIONAL MESSAGE RECEIVED:")
                    await self._parse_response(additional_msg, "BROADCAST")
                        
                except asyncio.TimeoutError:
                    continue  # Continue listening
                    
        except asyncio.TimeoutError:
            print("⏰ No additional messages received within timeout period")

async def main():
    print("🔬 CENTRAL INTELLIGENCE SYSTEM - FIXED TEST AGENT")
    print("=" * 60)
    
    agent = TestAgent(agent_id="PC-TEST-001")
    await agent.run_test()

if __name__ == "__main__":
    asyncio.run(main())