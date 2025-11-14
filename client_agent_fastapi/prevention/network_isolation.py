import os
import subprocess
import socket
import threading
from typing import Dict, Any, List
import psutil

class NetworkIsolation:
    """Network isolation and firewall management"""
    
    def __init__(self):
        self.is_isolated = False
        self.isolation_lock = threading.Lock()
        self.backup_rules: List[str] = []
        
    def isolate_machine(self) -> bool:
        """Isolate machine from network"""
        with self.isolation_lock:
            if self.is_isolated:
                print("⚠️ Machine already isolated")
                return True
            
            print("🌐 Isolating machine from network...")
            
            try:
                if os.name == 'nt':  # Windows
                    success = self._isolate_windows()
                else:  # Linux/Mac
                    success = self._isolate_linux()
                
                if success:
                    self.is_isolated = True
                    print("✅ Network isolation enabled")
                else:
                    print("❌ Network isolation failed")
                
                return success
                
            except Exception as e:
                print(f"❌ Network isolation error: {e}")
                return False

    def restore_network(self) -> bool:
        """Restore network connectivity"""
        with self.isolation_lock:
            if not self.is_isolated:
                print("⚠️ Machine not isolated")
                return True
            
            print("🌐 Restoring network connectivity...")
            
            try:
                if os.name == 'nt':  # Windows
                    success = self._restore_windows()
                else:  # Linux/Mac
                    success = self._restore_linux()
                
                if success:
                    self.is_isolated = False
                    print("✅ Network connectivity restored")
                else:
                    print("❌ Network restoration failed")
                
                return success
                
            except Exception as e:
                print(f"❌ Network restoration error: {e}")
                return False

    def _isolate_windows(self) -> bool:
        """Isolate Windows machine using Windows Firewall"""
        try:
            # Block all outgoing traffic (except local)
            result1 = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name="RansomwareEmergency_OUT"',
                'dir=out',
                'action=block',
                'enable=yes'
            ], capture_output=True, text=True)
            
            # Block all incoming traffic
            result2 = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name="RansomwareEmergency_IN"', 
                'dir=in',
                'action=block',
                'enable=yes'
            ], capture_output=True, text=True)
            
            # Disable network adapters (more aggressive)
            self._disable_network_adapters()
            
            return result1.returncode == 0 and result2.returncode == 0
            
        except Exception as e:
            print(f"Windows isolation error: {e}")
            return False

    def _restore_windows(self) -> bool:
        """Restore Windows network connectivity"""
        try:
            # Remove isolation rules
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name="RansomwareEmergency_OUT"'
            ], capture_output=True)
            
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name="RansomwareEmergency_IN"'
            ], capture_output=True)
            
            # Re-enable network adapters
            self._enable_network_adapters()
            
            return True
            
        except Exception as e:
            print(f"Windows restoration error: {e}")
            return False

    def _isolate_linux(self) -> bool:
        """Isolate Linux machine using iptables"""
        try:
            # Flush existing rules
            subprocess.run(['iptables', '-F'], check=True)
            subprocess.run(['iptables', '-X'], check=True)
            
            # Set default policies to DROP
            subprocess.run(['iptables', '-P', 'INPUT', 'DROP'], check=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'], check=True)
            subprocess.run(['iptables', '-P', 'FORWARD', 'DROP'], check=True)
            
            # Allow localhost traffic
            subprocess.run(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'], check=True)
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Linux isolation error: {e}")
            return False

    def _restore_linux(self) -> bool:
        """Restore Linux network connectivity"""
        try:
            # Reset iptables to default accept
            subprocess.run(['iptables', '-F'], check=True)
            subprocess.run(['iptables', '-X'], check=True)
            subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Linux restoration error: {e}")
            return False

    def _disable_network_adapters(self):
        """Disable network adapters (Windows only)"""
        try:
            # Get network adapters
            adapters = psutil.net_if_stats()
            for adapter_name, adapter_stats in adapters.items():
                if adapter_stats.isup and not adapter_name.startswith('Loopback'):
                    try:
                        subprocess.run([
                            'netsh', 'interface', 'set', 'interface', 
                            f'name="{adapter_name}"', 'admin=disabled'
                        ], capture_output=True)
                        print(f"    📡 Disabled adapter: {adapter_name}")
                    except Exception as e:
                        print(f"    ⚠️ Failed to disable {adapter_name}: {e}")
        except Exception as e:
            print(f"Error disabling adapters: {e}")

    def _enable_network_adapters(self):
        """Enable network adapters (Windows only)"""
        try:
            # Get network adapters
            adapters = psutil.net_if_stats()
            for adapter_name, adapter_stats in adapters.items():
                if not adapter_stats.isup and not adapter_name.startswith('Loopback'):
                    try:
                        subprocess.run([
                            'netsh', 'interface', 'set', 'interface',
                            f'name="{adapter_name}"', 'admin=enabled'
                        ], capture_output=True)
                        print(f"    📡 Enabled adapter: {adapter_name}")
                    except Exception as e:
                        print(f"    ⚠️ Failed to enable {adapter_name}: {e}")
        except Exception as e:
            print(f"Error enabling adapters: {e}")

    def block_specific_ip(self, ip_address: str) -> bool:
        """Block specific IP address"""
        try:
            if os.name == 'nt':  # Windows
                return self._block_ip_windows(ip_address)
            else:  # Linux
                return self._block_ip_linux(ip_address)
        except Exception as e:
            print(f"Error blocking IP {ip_address}: {e}")
            return False

    def _block_ip_windows(self, ip_address: str) -> bool:
        """Block IP using Windows Firewall"""
        try:
            rule_name = f"BlockRansomwareIP_{ip_address.replace('.', '_')}"
            
            # Block outbound to IP
            result1 = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_OUT',
                'dir=out',
                'action=block',
                f'remoteip={ip_address}',
                'enable=yes'
            ], capture_output=True, check=True)
            
            # Block inbound from IP
            result2 = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_IN',
                'dir=in', 
                'action=block',
                f'remoteip={ip_address}',
                'enable=yes'
            ], capture_output=True, check=True)
            
            self.backup_rules.extend([f"{rule_name}_OUT", f"{rule_name}_IN"])
            print(f"✅ Blocked IP: {ip_address}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip_address}: {e}")
            return False

    def _block_ip_linux(self, ip_address: str) -> bool:
        """Block IP using iptables"""
        try:
            # Block outgoing to IP
            subprocess.run([
                'iptables', '-A', 'OUTPUT', '-d', ip_address, '-j', 'DROP'
            ], check=True)
            
            # Block incoming from IP
            subprocess.run([
                'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ], check=True)
            
            print(f"✅ Blocked IP: {ip_address}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip_address}: {e}")
            return False

    def get_isolation_status(self) -> Dict[str, Any]:
        """Get current isolation status"""
        return {
            "is_isolated": self.is_isolated,
            "blocked_ips_count": len(self.backup_rules) // 2,
            "os_type": "Windows" if os.name == 'nt' else "Linux/Mac"
        }

    def emergency_restore(self) -> bool:
        """Emergency restore all network functionality"""
        print("🚨 Performing emergency network restoration...")
        
        # Restore network
        success = self.restore_network()
        
        # Remove all blocked IP rules
        for rule_name in self.backup_rules:
            try:
                if os.name == 'nt':
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                        f'name={rule_name}'
                    ], capture_output=True)
            except Exception as e:
                print(f"Warning: Could not remove rule {rule_name}: {e}")
        
        self.backup_rules.clear()
        return success