#!/usr/bin/env python3
"""
Local Test Agent for Central Intelligence System
Run this on the SAME PC as the central system
"""

import asyncio
import websockets
import json
import uuid
import platform
import socket
from datetime import datetime
import random

class LocalTestAgent:
    def __init__(self):
        self.central_host = "localhost"  # Connect to localhost
        self.central_port = 8765
        self.agent_id = f"LOCAL-AGENT-{platform.node()}-{uuid.uuid4().hex[:8]}"
        self.websocket = None
        self.is_connected = False
        
    async def connect(self):
        """Connect to central system"""
        try:
            uri = f"ws://{self.central_host}:{self.central_port}"
            print(f"🔗 Connecting to {uri}...")
            
            self.websocket = await websockets.connect(uri, ping_interval=20, ping_timeout=10)
            self.is_connected = True
            print("✅ Connected to central system!")
            
            # Register agent
            await self.register()
            
            return True
            
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
            
    async def register(self):
        """Register agent with central system"""
        registration_data = {
            "type": "REGISTER",
            "payload": {
                "agent_id": self.agent_id,
                "hostname": platform.node(),
                "ip_address": self._get_ip_address(),
                "os_type": platform.system(),
                "department": "IT",
                "critical_assets": ["documents", "financial_data", "databases"],
                "capabilities": [
                    "kill_process", 
                    "lock_files", 
                    "isolate_network", 
                    "backup_files",
                    "enable_zerotrust",
                    "block_network"
                ]
            }
        }
        
        await self.websocket.send(json.dumps(registration_data))
        print(f"📝 Registered as: {self.agent_id}")
        print(f"   Hostname: {platform.node()}")
        print(f"   IP: {self._get_ip_address()}")
        print(f"   OS: {platform.system()}")
        
    async def listen(self):
        """Listen for commands from central system"""
        try:
            print("👂 Listening for commands from central system...")
            async for message in self.websocket:
                await self.handle_message(message)
                
        except websockets.exceptions.ConnectionClosed:
            print("❌ Connection closed by server")
            self.is_connected = False
        except Exception as e:
            print(f"❌ Error in listener: {e}")
            self.is_connected = False
            
    async def handle_message(self, message):
        """Handle incoming messages"""
        try:
            data = json.loads(message)
            message_type = data.get('type')
            
            print(f"\n📨 Received message type: {message_type}")
            
            if message_type == 'REGISTRATION_ACK':
                print("   ✅ Registration confirmed by central system")
                print(f"   Message: {data.get('message')}")
                
            elif message_type == 'INCIDENT_RESPONSE':
                print("   🚨 INCIDENT RESPONSE RECEIVED!")
                print(f"   Incident ID: {data.get('incident_id')}")
                print(f"   Commands: {data.get('commands', [])}")
                print(f"   Risk Assessment: {data.get('risk_assessment', {})}")
                
                # Simulate executing commands
                commands = data.get('commands', [])
                if commands:
                    print("   ⚡ Executing commands:")
                    for i, command in enumerate(commands, 1):
                        print(f"     {i}. {command}")
                        await asyncio.sleep(0.5)  # Simulate command execution
                    print("   ✅ All commands executed successfully")
                
            elif message_type == 'NETWORK_INCIDENT_BROADCAST':
                print("   🔊 NETWORK-WIDE ALERT!")
                payload = data.get('payload', {})
                print(f"   Incident: {payload.get('incident_id')}")
                print(f"   Threat Level: {payload.get('threat_level')}")
                print(f"   Required Actions: {payload.get('required_actions', [])}")
                print(f"   Duration: {payload.get('duration')}")
                
            elif message_type == 'AGENT_COMMANDS':
                print("   ⚡ DIRECT COMMANDS RECEIVED!")
                commands = data.get('commands', [])
                incident_id = data.get('incident_id', 'N/A')
                print(f"   Incident: {incident_id}")
                print(f"   Commands: {commands}")
                
                # Simulate command execution
                for command in commands:
                    print(f"     Executing: {command}")
                    await asyncio.sleep(0.3)
                print("   ✅ Commands executed")
                
            elif message_type == 'ERROR':
                print(f"   ❌ Error from central: {data.get('message')}")
                
            else:
                print(f"   📦 Unknown message type: {message_type}")
                print(f"   Full data: {json.dumps(data, indent=2)}")
                
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON received: {e}")
            print(f"   Raw message: {message}")
            
    async def send_test_alert(self, alert_type="ransomware"):
        """Send a test threat alert to central system"""
        if not self.is_connected or not self.websocket:
            print("❌ Not connected to central system")
            return False
            
        alert_data = self._create_alert_data(alert_type)
        
        print(f"\n🚨 SENDING {alert_type.upper()} ALERT...")
        print(f"   Threat Level: {alert_data['payload']['threat_level']}")
        print(f"   Malware: {alert_data['payload']['malware_process']}")
        
        try:
            await self.websocket.send(json.dumps(alert_data))
            print("✅ Test alert sent to central system!")
            return True
        except Exception as e:
            print(f"❌ Failed to send alert: {e}")
            return False
            
    def _create_alert_data(self, alert_type):
        """Create different types of test alerts"""
        base_alert = {
            "type": "THREAT_ALERT",
            "payload": {
                "agent_id": self.agent_id,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        if alert_type == "ransomware":
            base_alert["payload"].update({
                "status": "infected_contained",
                "threat_level": "critical",
                "malware_process": "crypto_stealth.exe",
                "detection_confidence": 0.92,
                "actions_taken": ["process_killed", "backup_created", "files_locked", "network_isolated"],
                "forensic_data": {
                    "process_tree": ["explorer.exe", "crypto_stealth.exe", "cmd.exe"],
                    "file_access_patterns": {
                        "files_modified": 50,
                        "extensions_changed": [".docx", ".pdf", ".xlsx"],
                        "encryption_detected": True,
                        "ransom_note_found": True,
                        "ransom_extension": ".encrypted_crypto"
                    },
                    "network_connections": [
                        {
                            "remote_host": "192.168.1.101", 
                            "port": 445, 
                            "protocol": "SMB", 
                            "direction": "outbound"
                        },
                        {
                            "remote_host": "192.168.1.102",
                            "port": 3389,
                            "protocol": "RDP", 
                            "direction": "outbound"
                        }
                    ],
                    "system_metrics": {
                        "cpu_usage": 95.2,
                        "memory_usage": 87.5,
                        "disk_activity": "high"
                    }
                }
            })
            
        elif alert_type == "trojan":
            base_alert["payload"].update({
                "status": "suspicious",
                "threat_level": "high", 
                "malware_process": "stealth_trojan.exe",
                "detection_confidence": 0.78,
                "actions_taken": ["process_terminated", "network_blocked"],
                "forensic_data": {
                    "process_tree": ["svchost.exe", "stealth_trojan.exe"],
                    "file_access_patterns": {
                        "files_modified": 12,
                        "extensions_changed": [".exe", ".dll"],
                        "encryption_detected": False
                    },
                    "network_connections": [
                        {
                            "remote_host": "45.33.32.156",
                            "port": 443,
                            "protocol": "HTTPS",
                            "direction": "outbound"
                        }
                    ],
                    "system_metrics": {
                        "cpu_usage": 45.2,
                        "memory_usage": 67.8,
                        "disk_activity": "medium"
                    }
                }
            })
            
        elif alert_type == "suspicious":
            base_alert["payload"].update({
                "status": "suspicious",
                "threat_level": "medium",
                "malware_process": "unknown_script.js",
                "detection_confidence": 0.65,
                "actions_taken": ["increased_monitoring"],
                "forensic_data": {
                    "process_tree": ["chrome.exe", "unknown_script.js"],
                    "file_access_patterns": {
                        "files_modified": 5,
                        "extensions_changed": [".tmp"],
                        "encryption_detected": False
                    },
                    "network_connections": [
                        {
                            "remote_host": "93.184.216.34",
                            "port": 443,
                            "protocol": "HTTPS",
                            "direction": "outbound"
                        }
                    ],
                    "system_metrics": {
                        "cpu_usage": 25.1,
                        "memory_usage": 45.3,
                        "disk_activity": "low"
                    }
                }
            })
            
        elif alert_type == "miner":
            base_alert["payload"].update({
                "status": "infected",
                "threat_level": "high",
                "malware_process": "xmrig.exe", 
                "detection_confidence": 0.85,
                "actions_taken": ["process_killed", "cpu_throttled"],
                "forensic_data": {
                    "process_tree": ["xmrig.exe", "miner_helper.exe"],
                    "file_access_patterns": {
                        "files_modified": 3,
                        "extensions_changed": [],
                        "encryption_detected": False
                    },
                    "network_connections": [
                        {
                            "remote_host": "pool.minexmr.com",
                            "port": 4444,
                            "protocol": "TCP",
                            "direction": "outbound"
                        }
                    ],
                    "system_metrics": {
                        "cpu_usage": 98.7,
                        "memory_usage": 23.4, 
                        "disk_activity": "low"
                    }
                }
            })
            
        return base_alert
        
    async def send_heartbeat(self):
        """Send periodic heartbeat"""
        while self.is_connected:
            try:
                if self.websocket:
                    heartbeat = {
                        "type": "HEARTBEAT",
                        "payload": {
                            "agent_id": self.agent_id,
                            "timestamp": datetime.now().isoformat(),
                            "system_health": "normal"
                        }
                    }
                    await self.websocket.send(json.dumps(heartbeat))
                    print("💓 Heartbeat sent")
            except Exception as e:
                print(f"❌ Heartbeat failed: {e}")
                self.is_connected = False
                break
            await asyncio.sleep(30)  # Every 30 seconds
            
    async def send_status_update(self):
        """Send status update"""
        if not self.is_connected:
            return
            
        status_update = {
            "type": "STATUS_UPDATE",
            "payload": {
                "agent_id": self.agent_id,
                "status": "normal",
                "timestamp": datetime.now().isoformat(),
                "resources": {
                    "cpu_usage": random.randint(5, 40),
                    "memory_usage": random.randint(30, 70),
                    "disk_free": random.randint(20, 80)
                }
            }
        }
        
        await self.websocket.send(json.dumps(status_update))
        print("📊 Status update sent")
        
    def _get_ip_address(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

async def interactive_local_test():
    """Interactive local test agent"""
    agent = LocalTestAgent()
    
    print("🛡️ LOCAL TEST AGENT STARTING")
    print("="*50)
    
    # Connect to central system
    connected = await agent.connect()
    if not connected:
        print("❌ Failed to connect to central system. Make sure it's running!")
        return
        
    # Start background tasks
    listen_task = asyncio.create_task(agent.listen())
    heartbeat_task = asyncio.create_task(agent.send_heartbeat())
    
    try:
        while agent.is_connected:
            print("\n" + "="*50)
            print("🛡️  LOCAL TEST AGENT - MENU")
            print("="*50)
            print("1. Send Ransomware Alert (Critical)")
            print("2. Send Trojan Alert (High)")
            print("3. Send Suspicious Activity Alert (Medium)") 
            print("4. Send Cryptominer Alert (High)")
            print("5. Send Status Update")
            print("6. Open Admin Console")
            print("7. Exit")
            print("="*50)
            
            try:
                choice = input("Select option (1-7): ").strip()
                
                if choice == "1":
                    await agent.send_test_alert("ransomware")
                elif choice == "2":
                    await agent.send_test_alert("trojan")
                elif choice == "3":
                    await agent.send_test_alert("suspicious")
                elif choice == "4":
                    await agent.send_test_alert("miner")
                elif choice == "5":
                    await agent.send_status_update()
                elif choice == "6":
                    print("🌐 Admin Console: http://localhost:8767")
                    print("   Open this in your browser to see real-time updates!")
                elif choice == "7":
                    print("👋 Exiting...")
                    break
                else:
                    print("❌ Invalid choice")
                    
                await asyncio.sleep(2)  # Brief pause between actions
                
            except KeyboardInterrupt:
                print("\n👋 Interrupted by user")
                break
            except Exception as e:
                print(f"❌ Menu error: {e}")
                
    except Exception as e:
        print(f"❌ Main loop error: {e}")
    finally:
        # Cleanup
        agent.is_connected = False
        listen_task.cancel()
        heartbeat_task.cancel()
        
        if agent.websocket:
            await agent.websocket.close()
            
        print("✅ Test agent shutdown complete")

if __name__ == "__main__":
    print("🚀 Starting Local Test Agent")
    print("Note: Make sure Central System is running on localhost:8765")
    print("-" * 50)
    
    asyncio.run(interactive_local_test())