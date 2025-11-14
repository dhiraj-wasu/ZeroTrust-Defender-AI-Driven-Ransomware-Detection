import os
import time
import threading
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import asyncio

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, file_callback, event_loop):
        self.file_callback = file_callback
        self.event_loop = event_loop
        self.event_count = 0

    def on_created(self, event):
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.file_callback('created', event.src_path), 
                self.event_loop
            )

    def on_modified(self, event):
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.file_callback('modified', event.src_path, {
                    'size': os.path.getsize(event.src_path) if os.path.exists(event.src_path) else 0,
                    'timestamp': datetime.now().isoformat()
                }), 
                self.event_loop
            )

    def on_deleted(self, event):
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.file_callback('deleted', event.src_path), 
                self.event_loop
            )

    def on_moved(self, event):
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.file_callback('renamed', event.dest_path, {
                    'old_path': event.src_path,
                    'new_path': event.dest_path,
                    'timestamp': datetime.now().isoformat()
                }), 
                self.event_loop
            )

class ProcessMonitor:
    def __init__(self, process_callback, event_loop):
        self.process_callback = process_callback
        self.event_loop = event_loop
        self.monitoring = False
        self.known_processes = set()

    def start(self):
        self.monitoring = True
        self.known_processes = {p.pid for p in psutil.process_iter(['pid'])}
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def stop(self):
        self.monitoring = False

    def _monitor_loop(self):
        while self.monitoring:
            try:
                current_processes = {}
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time', 'username']):
                    try:
                        current_processes[proc.info['pid']] = proc.info
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Detect new processes
                current_pids = set(current_processes.keys())
                new_pids = current_pids - self.known_processes

                for pid in new_pids:
                    if pid in current_processes:
                        proc_info = current_processes[pid]
                        asyncio.run_coroutine_threadsafe(
                            self.process_callback({
                                'type': 'process_start',
                                'pid': pid,
                                'name': proc_info['name'],
                                'cpu': proc_info['cpu_percent'],
                                'memory': proc_info['memory_percent'],
                                'username': proc_info.get('username', 'unknown'),
                                'timestamp': time.time()
                            }),
                            self.event_loop
                        )

                # Detect high resource usage
                for pid, proc_info in current_processes.items():
                    if proc_info['cpu_percent'] > 80.0 or proc_info['memory_percent'] > 80.0:
                        asyncio.run_coroutine_threadsafe(
                            self.process_callback({
                                'type': 'high_usage',
                                'pid': pid,
                                'name': proc_info['name'],
                                'cpu': proc_info['cpu_percent'],
                                'memory': proc_info['memory_percent'],
                                'timestamp': time.time()
                            }),
                            self.event_loop
                        )

                self.known_processes = current_pids
                time.sleep(2)

            except Exception as e:
                print(f"Process monitoring error: {e}")
                time.sleep(5)

class NetworkMonitor:
    def __init__(self, network_callback, event_loop):
        self.network_callback = network_callback
        self.event_loop = event_loop
        self.monitoring = False

    def start(self):
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def stop(self):
        self.monitoring = False

    def _monitor_loop(self):
        previous_connections = set()

        while self.monitoring:
            try:
                current_connections = set()
                
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        connection_str = f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}"
                        current_connections.add(connection_str)

                        # Check for suspicious ports
                        suspicious_ports = [445, 3389, 135, 139]  # SMB, RDP
                        if conn.raddr.port in suspicious_ports:
                            asyncio.run_coroutine_threadsafe(
                                self.network_callback({
                                    'type': 'suspicious_connection',
                                    'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                                    'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                                    'protocol': 'tcp',
                                    'status': conn.status,
                                    'timestamp': time.time()
                                }),
                                self.event_loop
                            )

                # Detect new connections
                new_connections = current_connections - previous_connections
                for conn in new_connections:
                    asyncio.run_coroutine_threadsafe(
                        self.network_callback({
                            'type': 'new_connection',
                            'connection': conn,
                            'timestamp': time.time()
                        }),
                        self.event_loop
                    )

                previous_connections = current_connections
                time.sleep(5)

            except Exception as e:
                print(f"Network monitoring error: {e}")
                time.sleep(5)

class RealTimeMonitor:
    def __init__(self, monitor_dir, file_callback, process_callback, network_callback):
        self.monitor_dir = monitor_dir
        self.file_callback = file_callback
        self.process_callback = process_callback
        self.network_callback = network_callback
        
        # Create event loop for this thread
        self.loop = asyncio.new_event_loop()
        
        self.observer = None
        self.process_monitor = ProcessMonitor(process_callback, self.loop)
        self.network_monitor = NetworkMonitor(network_callback, self.loop)
        self.monitoring = False

    def start(self):
        """Start all monitoring services"""
        self.monitoring = True
        
        # Set the event loop for this thread
        asyncio.set_event_loop(self.loop)
        
        # File system monitoring
        event_handler = FileEventHandler(self.file_callback, self.loop)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.monitor_dir, recursive=True)
        self.observer.start()
        
        # Process monitoring
        self.process_monitor.start()
        
        # Network monitoring
        self.network_monitor.start()
        
        print(f"✅ Monitoring started on: {self.monitor_dir}")
        
        # Start the event loop
        try:
            self.loop.run_forever()
        except Exception as e:
            print(f"Monitor event loop error: {e}")
        finally:
            self.loop.close()

    def stop(self):
        """Stop all monitoring services"""
        self.monitoring = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        self.process_monitor.stop()
        self.network_monitor.stop()
        
        # Stop the event loop
        if self.loop and self.loop.is_running():
            self.loop.stop()
        
        print("✅ Monitoring stopped.")