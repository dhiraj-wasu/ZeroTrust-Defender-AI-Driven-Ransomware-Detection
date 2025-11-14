#!/usr/bin/env python3
"""
Agent Listener (PC2) - Windows Firewall Blocker (FINAL FIXED)
"""

import asyncio
import websockets
import json
import subprocess
import platform
import logging
from datetime import datetime
import sys

class AgentListener:
    def __init__(self, agent_id="PC-LISTENER-002", central_server="ws://10.80.11.74:8080"):
        self.agent_id = agent_id
        self.central_server = central_server
        self.websocket = None
        self.blocked_ips = set()

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger(f"AgentListener-{agent_id}")

    def is_windows(self):
        """Check if running on Windows"""
        return platform.system().lower() == "windows"

    async def run_listener(self):
        """Run the agent listener"""
        if not self.is_windows():
            self.logger.error("❌ This agent requires Windows OS for firewall commands")
            return

        print("🛡 AGENT LISTENER (PC2) - WINDOWS FIREWALL BLOCKER")
        print("=" * 60)
        print("🔧 Capabilities:")
        print("   • Listen for central system commands")
        print("   • Block infected IPs")
        print("   • Execute security actions")
        print("   • Monitor network incidents")
        print("=" * 60)

        try:
            url = f"{self.central_server}/ws/{self.agent_id}"
            self.logger.info(f"🔄 Connecting to {url}")
            self.websocket = await websockets.connect(url)
            self.logger.info(f"✅ CONNECTED to central system as {self.agent_id}")

            # Register agent
            await self._register_agent()

            # Listen for messages
            await self._listen_for_messages()

        except Exception as e:
            self.logger.error(f"💥 Listener failed: {e}")

    async def _register_agent(self):
        """Register agent with central system"""
        registration_data = {
            "type": "REGISTER",
            "payload": {
                "agent_id": self.agent_id,
                "hostname": "SECURITY-LISTENER-PC",
                "ip_address": "192.168.1.101",
                "os_type": "Windows 10/11",
                "department": "Security",
                "critical_assets": ["firewall_rules", "network_monitoring"],
                "capabilities": ["firewall_management", "network_isolation", "threat_blocking"],
                "status": "monitoring",
                "last_seen": datetime.now().isoformat()
            }
        }

        self.logger.info("📝 Registering agent with central system...")
        await self.websocket.send(json.dumps(registration_data))

        try:
            response = await asyncio.wait_for(self.websocket.recv(), timeout=10.0)
            await self._process_message(response)
        except asyncio.TimeoutError:
            self.logger.warning("⚠ No registration response received")

    async def _listen_for_messages(self):
        """Listen for messages from central system"""
        self.logger.info("👂 Listening for central system commands...")

        try:
            async for message in self.websocket:
                await self._process_message(message)
        except websockets.exceptions.ConnectionClosed:
            self.logger.warning("🔌 Connection closed by central system")
        except Exception as e:
            self.logger.error(f"💥 Error in message listener: {e}")

    async def _process_message(self, message):
        """Process incoming message safely"""
        try:
            data = json.loads(message)
            message_type = data.get("type")
            self.logger.info(f"📨 Received message type: {message_type}")

            if message_type == "NETWORK_INCIDENT_BROADCAST":
                await self._handle_network_broadcast(data)
            elif message_type == "REGISTRATION_ACK":
                self.logger.info("✅ Agent registered successfully")
            elif message_type == "AGENT_COMMAND":
                await self._handle_agent_command(data)
            elif message_type == "HEARTBEAT":
                await self._handle_heartbeat()
            else:
                self.logger.warning(f"🤔 Unknown message type: {message_type}")

        except json.JSONDecodeError:
            self.logger.warning(f"⚠ Non-JSON message received: {message}")
        except Exception as e:
            self.logger.error(f"💥 Error processing message: {e}")

    async def _handle_network_broadcast(self, data):
        """Handle network incident broadcast"""
        payload = data.get("payload", {})
        incident_id = payload.get("incident_id", "UNKNOWN")
        infected_ip = payload.get("affected_agent_ip", "unknown")
        affected_agent = payload.get("affected_agent", "unknown")
        threat_level = payload.get("threat_level", "unknown")
        malware_process = payload.get("malware_process", "unknown")

        self.logger.info("🚨 NETWORK INCIDENT DETECTED")
        self.logger.info(f"   💀 Affected Agent: {affected_agent}")
        self.logger.info(f"   🌐 Infected IP: {infected_ip}")
        self.logger.info(f"   🔴 Threat Level: {threat_level}")
        self.logger.info(f"   🦠 Malware: {malware_process}")

        if infected_ip != "unknown":
            await self.block_ip(infected_ip, incident_id)
        else:
            self.logger.warning("⚠ No valid IP address found to block")

    async def block_ip(self, ip_address, incident_id):
        """Block given IP using Windows Firewall"""
        if ip_address in self.blocked_ips:
            self.logger.info(f"🛡 IP {ip_address} already blocked")
            return

        try:
            rule_name = f"Block_Threat_{incident_id}_{ip_address.replace('.', '')}"

            cmds = [
                f'netsh advfirewall firewall add rule name="{rule_name}_In" dir=in action=block remoteip={ip_address} description="Block threat {incident_id}"',
                f'netsh advfirewall firewall add rule name="{rule_name}_Out" dir=out action=block remoteip={ip_address} description="Block threat {incident_id}"'
            ]

            for cmd in cmds:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    self.logger.info(f"✅ Rule added: {cmd}")
                else:
                    self.logger.error(f"❌ Failed: {result.stderr}")

            self.blocked_ips.add(ip_address)
            self.logger.info(f"🎯 IP {ip_address} blocked successfully")

        except Exception as e:
            self.logger.error(f"💥 Error blocking IP {ip_address}: {e}")

    async def _handle_agent_command(self, data):
        """Handle direct agent commands"""
        payload = data.get("payload", {})
        commands = payload.get("commands", [])
        incident_id = payload.get("incident_id", "UNKNOWN")

        self.logger.info(f"⚡ AGENT COMMANDS for {incident_id}: {commands}")
        for command in commands:
            if command.startswith("block_ip_"):
                ip = command.replace("block_ip_", "")
                await self.block_ip(ip, incident_id)

    async def _handle_heartbeat(self):
        """Respond to heartbeat from central"""
        response = {"type": "HEARTBEAT_ACK", "timestamp": datetime.now().isoformat()}
        await self.websocket.send(json.dumps(response))
        self.logger.info("💓 Heartbeat acknowledged")

async def main():
    listener = AgentListener(
        agent_id="PC-LISTENER-002",
        central_server="ws://10.80.11.74:8080"
    )

    try:
        await listener.run_listener()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down agent listener...")
    finally:
        if listener.websocket:
            await listener.websocket.close()

if __name__ == "__main__":
    if platform.system().lower() != "windows":
        print("❌ This agent requires Windows OS for firewall commands")
        sys.exit(1)

    asyncio.run(main())
