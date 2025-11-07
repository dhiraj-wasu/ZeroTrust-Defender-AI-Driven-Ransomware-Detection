from aiohttp import web
import json
import logging
from datetime import datetime
from typing import Dict, List, Any

class DashboardRoutes:
    def __init__(self, central_system):
        self.central_system = central_system
        self.logger = logging.getLogger(__name__)
        self.routes = web.RouteTableDef()
        self._setup_routes()

    def _setup_routes(self):
        """Setup dashboard routes"""
        
        @self.routes.get('/')
        async def dashboard(request):
            """Serve the main dashboard page"""
            self.logger.info("📊 Dashboard page requested")
            return web.Response(
                text=self._get_dashboard_html(),
                content_type='text/html'
            )

        @self.routes.get('/api/dashboard/overview')
        async def get_overview(request):
            """Get dashboard overview data"""
            self.logger.info("📈 Dashboard overview API called")
            try:
                metrics = {
                    'system_health': {
                        'status': 'healthy',
                        'uptime': '24h'
                    },
                    'metrics': {
                        'containment_success_rate': 0.95,
                        'average_response_time_seconds': 2.5,
                        'false_positives': 0,
                        'true_positives': 5
                    },
                    'topology': {
                        'total_agents': 3,
                        'online_agents': 2,
                        'connected_agents': 2
                    },
                    'active_incidents': {
                        'total': 2,
                        'critical': 1,
                        'emergencies': 0
                    }
                }
                
                self.logger.info(f"✅ Dashboard overview returned: {metrics}")
                return web.json_response(metrics)
                
            except Exception as e:
                self.logger.error(f"❌ Dashboard overview error: {e}")
                return web.json_response({'error': str(e)}, status=500)

        @self.routes.get('/api/agents')
        async def get_agents_list(request):
            """Get detailed agents list"""
            self.logger.info("👥 Agents API called")
            try:
                # Sample agent data
                agents = [
                    {
                        'agent_id': 'PC-A',
                        'hostname': 'pc-a.local',
                        'ip_address': '192.168.1.10',
                        'os_type': 'Windows 11',
                        'status': 'online',
                        'connected': True,
                        'last_seen': datetime.now().isoformat()
                    },
                    {
                        'agent_id': 'PC-B', 
                        'hostname': 'pc-b.local',
                        'ip_address': '192.168.1.11',
                        'os_type': 'Windows 10',
                        'status': 'online',
                        'connected': True,
                        'last_seen': datetime.now().isoformat()
                    },
                    {
                        'agent_id': 'PC-C',
                        'hostname': 'pc-c.local',
                        'ip_address': '192.168.1.12',
                        'os_type': 'Linux',
                        'status': 'offline',
                        'connected': False,
                        'last_seen': '2024-01-15T10:00:00Z'
                    }
                ]
                
                self.logger.info(f"✅ Agents returned: {len(agents)} agents")
                return web.json_response({
                    'agents': agents,
                    'total_count': len(agents),
                    'connected_count': len([a for a in agents if a['connected']])
                })
                
            except Exception as e:
                self.logger.error(f"❌ Agents error: {e}")
                return web.json_response({'error': str(e)}, status=500)

        @self.routes.get('/api/incidents')
        async def get_incidents_list(request):
            """Get incidents with filtering"""
            self.logger.info("🚨 Incidents API called")
            try:
                hours = request.query.get('hours', '24')
                self.logger.info(f"📅 Incidents filter - hours: {hours}")
                
                # Sample incident data
                incidents = [
                    {
                        'incident_id': 'INC_20240115_140500_abc123',
                        'agent_id': 'PC-A',
                        'timestamp': datetime.now().isoformat(),
                        'threat_level': 'critical',
                        'malware_process': 'crypto_stealth.exe',
                        'detection_confidence': 0.92,
                        'status': 'contained'
                    },
                    {
                        'incident_id': 'INC_20240115_120000_def456',
                        'agent_id': 'PC-B',
                        'timestamp': '2024-01-15T12:00:00Z',
                        'threat_level': 'medium',
                        'malware_process': 'suspicious_script.js',
                        'detection_confidence': 0.65,
                        'status': 'investigating'
                    }
                ]
                
                self.logger.info(f"✅ Incidents returned: {len(incidents)} incidents")
                return web.json_response({
                    'incidents': incidents,
                    'total': len(incidents)
                })
                
            except Exception as e:
                self.logger.error(f"❌ Incidents error: {e}")
                return web.json_response({'error': str(e)}, status=500)

        @self.routes.get('/api/logs')
        async def get_system_logs(request):
            """Get system logs with filtering"""
            self.logger.info("📋 Logs API called")
            try:
                lines = int(request.query.get('lines', '50'))
                level = request.query.get('level', '')
                self.logger.info(f"📝 Logs filter - lines: {lines}, level: {level}")
                
                # Sample logs with timestamps
                logs = [
                    f"{datetime.now().isoformat()} - INFO - Dashboard overview API called",
                    f"{datetime.now().isoformat()} - INFO - Agents API called", 
                    f"{datetime.now().isoformat()} - INFO - Incidents API called",
                    f"{datetime.now().isoformat()} - INFO - Logs API called",
                    f"{datetime.now().isoformat()} - INFO - Central system started successfully",
                    f"{datetime.now().isoformat()} - INFO - WebSocket server running on port 8765",
                    f"{datetime.now().isoformat()} - INFO - Admin console started on port 8767",
                    f"{datetime.now().isoformat()} - WARNING - No agents connected yet",
                    f"{datetime.now().isoformat()} - INFO - System ready to receive connections"
                ]
                
                # Filter by level if specified
                if level:
                    logs = [log for log in logs if level.upper() in log]
                
                # Limit to requested number of lines
                logs = logs[-lines:]
                
                self.logger.info(f"✅ Logs returned: {len(logs)} lines")
                return web.json_response({
                    'logs': logs,
                    'total_lines': len(logs)
                })
                
            except Exception as e:
                self.logger.error(f"❌ Logs error: {e}")
                return web.json_response({'error': str(e)}, status=500)

    def _get_dashboard_html(self):
        """Return the dashboard HTML content"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Central Intelligence System - Admin Console</title>
    <style>
        :root {
            --primary: #2563eb;
            --danger: #dc2626;
            --warning: #d97706;
            --success: #059669;
            --gray: #6b7280;
            --light-bg: #f8fafc;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--light-bg);
            color: #1f2937;
        }
        
        .navbar {
            background: white;
            border-bottom: 1px solid #e5e7eb;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .nav-brand {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--primary);
        }
        
        .nav-links {
            display: flex;
            gap: 2rem;
        }
        
        .nav-link {
            text-decoration: none;
            color: var(--gray);
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            transition: all 0.2s;
        }
        
        .nav-link.active {
            background: var(--primary);
            color: white;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: white;
            border-radius: 0.5rem;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border: 1px solid #e5e7eb;
        }
        
        .card-header {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }
        
        .stat-card {
            text-align: center;
            padding: 1rem;
            border-radius: 0.375rem;
            background: var(--light-bg);
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: var(--gray);
            font-size: 0.875rem;
        }
        
        .critical { color: var(--danger); }
        .warning { color: var(--warning); }
        .success { color: var(--success); }
        .info { color: var(--primary); }
        
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th, .table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .table th {
            background: var(--light-bg);
            font-weight: 600;
        }
        
        .badge {
            padding: 0.25rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .badge-critical { background: #fee2e2; color: var(--danger); }
        .badge-high { background: #ffedd5; color: var(--warning); }
        .badge-medium { background: #fef3c7; color: #d97706; }
        .badge-low { background: #dcfce7; color: var(--success); }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 0.375rem;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .btn-primary { background: var(--primary); color: white; }
        
        .log-entry {
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            padding: 0.25rem 0;
            border-bottom: 1px solid #f1f5f9;
        }
        
        .log-error { color: var(--danger); }
        .log-warning { color: var(--warning); }
        .log-info { color: var(--primary); }
        
        .loading {
            color: var(--gray);
            font-style: italic;
        }
        
        .error {
            color: var(--danger);
            background: #fef2f2;
            padding: 1rem;
            border-radius: 0.375rem;
            border: 1px solid #fecaca;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-brand">🛡️ Central Intelligence System</div>
        <div class="nav-links">
            <a href="#" class="nav-link active" onclick="showTab('dashboard')">Dashboard</a>
            <a href="#" class="nav-link" onclick="showTab('agents')">Agents</a>
            <a href="#" class="nav-link" onclick="showTab('incidents')">Incidents</a>
            <a href="#" class="nav-link" onclick="showTab('logs')">Logs</a>
        </div>
    </nav>

    <div class="container">
        <!-- Dashboard Tab -->
        <div id="dashboard" class="tab-content active">
            <h1>System Overview</h1>
            <p class="loading" id="dashboard-status">Loading dashboard...</p>
            
            <div class="dashboard-grid">
                <div class="card">
                    <div class="card-header">System Health</div>
                    <div id="system-health" class="stat-grid">
                        <div class="loading">Loading...</div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">Threat Overview</div>
                    <div id="threat-overview" class="stat-grid">
                        <div class="loading">Loading...</div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">Network Topology</div>
                    <div id="network-topology" class="stat-grid">
                        <div class="loading">Loading...</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">Recent Incidents</div>
                <div id="recent-incidents">
                    <div class="loading">Loading incidents...</div>
                </div>
            </div>
        </div>

        <!-- Agents Tab -->
        <div id="agents" class="tab-content">
            <div class="card">
                <div class="card-header">
                    Managed Agents
                    <button class="btn btn-primary" onclick="loadAgents()">Refresh</button>
                </div>
                <div id="agents-list">
                    <div class="loading">Loading agents...</div>
                </div>
            </div>
        </div>

        <!-- Incidents Tab -->
        <div id="incidents" class="tab-content">
            <div class="card">
                <div class="card-header">
                    Security Incidents
                    <button class="btn btn-primary" onclick="loadIncidents()">Refresh</button>
                </div>
                <div id="incidents-list">
                    <div class="loading">Loading incidents...</div>
                </div>
            </div>
        </div>

        <!-- Logs Tab -->
        <div id="logs" class="tab-content">
            <div class="card">
                <div class="card-header">
                    System Logs
                    <div>
                        <select id="log-level" onchange="loadLogs()">
                            <option value="">All Levels</option>
                            <option value="ERROR">Errors</option>
                            <option value="WARNING">Warnings</option>
                            <option value="INFO">Info</option>
                        </select>
                        <button class="btn btn-primary" onclick="loadLogs()">Refresh Logs</button>
                    </div>
                </div>
                <div id="logs-content" style="max-height: 600px; overflow-y: auto;">
                    <div class="loading">Loading logs...</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        console.log("🚀 Dashboard JavaScript loaded");
        
        let currentTab = 'dashboard';

        // API calls with logging
        async function apiCall(endpoint, options = {}) {
            console.log(`📞 API Call: ${endpoint}`);
            
            try {
                const response = await fetch(`/api${endpoint}`, options);
                console.log(`📥 Response status: ${response.status}`);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                console.log(`✅ API Success: ${endpoint}`, data);
                return data;
                
            } catch (error) {
                console.error(`❌ API Error (${endpoint}):`, error);
                showNotification(`API call failed: ${error.message}`, 'error');
                return null;
            }
        }

        // Dashboard functions
        async function loadDashboard() {
            console.log("📊 Loading dashboard...");
            document.getElementById('dashboard-status').textContent = 'Loading dashboard data...';
            
            const data = await apiCall('/dashboard/overview');
            
            if (!data) {
                document.getElementById('dashboard-status').textContent = 'Error loading dashboard';
                return;
            }

            document.getElementById('dashboard-status').textContent = 'Dashboard loaded successfully';

            // System Health
            document.getElementById('system-health').innerHTML = `
                <div class="stat-card">
                    <div class="stat-value success">✓</div>
                    <div class="stat-label">Status</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${data.topology?.online_agents || 0}</div>
                    <div class="stat-label">Agents Online</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${data.active_incidents?.emergencies || 0}</div>
                    <div class="stat-label">Active Emergencies</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${Math.round((data.metrics?.containment_success_rate || 0) * 100)}%</div>
                    <div class="stat-label">Containment Rate</div>
                </div>
            `;

            // Threat Overview
            document.getElementById('threat-overview').innerHTML = `
                <div class="stat-card">
                    <div class="stat-value critical">${data.active_incidents?.critical || 0}</div>
                    <div class="stat-label">Critical Incidents</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${data.active_incidents?.total || 0}</div>
                    <div class="stat-label">Total Incidents</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value warning">${data.metrics?.false_positives || 0}</div>
                    <div class="stat-label">False Positives</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${Math.round(data.metrics?.average_response_time_seconds || 0)}s</div>
                    <div class="stat-label">Avg Response Time</div>
                </div>
            `;

            // Network Topology
            document.getElementById('network-topology').innerHTML = `
                <div class="stat-card">
                    <div class="stat-value">${data.topology?.total_agents || 0}</div>
                    <div class="stat-label">Total Agents</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${data.topology?.connected_agents || 0}</div>
                    <div class="stat-label">Connected Now</div>
                </div>
            `;

            // Load recent incidents
            await loadRecentIncidents();
        }

        async function loadRecentIncidents() {
            console.log("🚨 Loading recent incidents...");
            const data = await apiCall('/incidents?hours=24&per_page=5');
            
            if (!data || !data.incidents) {
                document.getElementById('recent-incidents').innerHTML = '<div class="error">No incidents found</div>';
                return;
            }

            const html = `
                <table class="table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Agent</th>
                            <th>Threat</th>
                            <th>Level</th>
                            <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.incidents.map(incident => `
                            <tr>
                                <td>${new Date(incident.timestamp).toLocaleString()}</td>
                                <td>${incident.agent_id}</td>
                                <td>${incident.malware_process || 'Unknown'}</td>
                                <td><span class="badge badge-${incident.threat_level}">${incident.threat_level}</span></td>
                                <td>${Math.round((incident.detection_confidence || 0) * 100)}%</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;

            document.getElementById('recent-incidents').innerHTML = html;
        }

        async function loadAgents() {
            console.log("👥 Loading agents...");
            document.getElementById('agents-list').innerHTML = '<div class="loading">Loading agents...</div>';
            
            const data = await apiCall('/agents');
            
            if (!data || !data.agents) {
                document.getElementById('agents-list').innerHTML = '<div class="error">No agents found</div>';
                return;
            }

            const html = `
                <table class="table">
                    <thead>
                        <tr>
                            <th>Agent ID</th>
                            <th>Hostname</th>
                            <th>IP Address</th>
                            <th>OS</th>
                            <th>Status</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.agents.map(agent => `
                            <tr>
                                <td>${agent.agent_id}</td>
                                <td>${agent.hostname}</td>
                                <td>${agent.ip_address}</td>
                                <td>${agent.os_type}</td>
                                <td>
                                    <span class="badge ${agent.connected ? 'badge-low' : 'badge-warning'}">
                                        ${agent.connected ? 'Online' : 'Offline'}
                                    </span>
                                </td>
                                <td>${new Date(agent.last_seen).toLocaleString()}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
                <div style="margin-top: 1rem; color: var(--gray);">
                    Total: ${data.total_count} agents, Connected: ${data.connected_count}
                </div>
            `;

            document.getElementById('agents-list').innerHTML = html;
        }

        async function loadIncidents() {
            console.log("🚨 Loading all incidents...");
            document.getElementById('incidents-list').innerHTML = '<div class="loading">Loading incidents...</div>';
            
            const data = await apiCall('/incidents?hours=24');
            
            if (!data || !data.incidents) {
                document.getElementById('incidents-list').innerHTML = '<div class="error">No incidents found</div>';
                return;
            }

            const html = `
                <table class="table">
                    <thead>
                        <tr>
                            <th>Incident ID</th>
                            <th>Time</th>
                            <th>Agent</th>
                            <th>Threat</th>
                            <th>Level</th>
                            <th>Confidence</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.incidents.map(incident => `
                            <tr>
                                <td><small>${incident.incident_id}</small></td>
                                <td>${new Date(incident.timestamp).toLocaleString()}</td>
                                <td>${incident.agent_id}</td>
                                <td>${incident.malware_process || 'Unknown'}</td>
                                <td><span class="badge badge-${incident.threat_level}">${incident.threat_level}</span></td>
                                <td>${Math.round((incident.detection_confidence || 0) * 100)}%</td>
                                <td>${incident.status || 'unknown'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;

            document.getElementById('incidents-list').innerHTML = html;
        }

        async function loadLogs() {
            console.log("📋 Loading logs...");
            document.getElementById('logs-content').innerHTML = '<div class="loading">Loading logs...</div>';
            
            const level = document.getElementById('log-level').value;
            const data = await apiCall('/logs?lines=100&level=' + level);
            
            if (!data || !data.logs) {
                document.getElementById('logs-content').innerHTML = '<div class="error">No logs available</div>';
                return;
            }

            const html = data.logs.map(log => {
                let className = 'log-info';
                if (log.includes('ERROR')) className = 'log-error';
                else if (log.includes('WARNING')) className = 'log-warning';
                
                return `<div class="log-entry ${className}">${log}</div>`;
            }).join('');

            document.getElementById('logs-content').innerHTML = html;
        }

        function showNotification(message, type = 'info') {
            alert(`${type.toUpperCase()}: ${message}`);
        }

        function showTab(tabName) {
            console.log(`🔍 Switching to tab: ${tabName}`);
            
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
            currentTab = tabName;
            
            // Load tab-specific data
            switch(tabName) {
                case 'dashboard':
                    loadDashboard();
                    break;
                case 'agents':
                    loadAgents();
                    break;
                case 'incidents':
                    loadIncidents();
                    break;
                case 'logs':
                    loadLogs();
                    break;
            }
        }

        // Initialize dashboard on load
        document.addEventListener('DOMContentLoaded', function() {
            console.log("🎯 Dashboard initialized");
            loadDashboard();
            
            // Auto-refresh dashboard every 30 seconds
            setInterval(() => {
                if (currentTab === 'dashboard') {
                    console.log("🔄 Auto-refreshing dashboard...");
                    loadDashboard();
                }
            }, 30000);
        });
    </script>
</body>
</html>
        """

    def get_routes(self):
        return self.routes