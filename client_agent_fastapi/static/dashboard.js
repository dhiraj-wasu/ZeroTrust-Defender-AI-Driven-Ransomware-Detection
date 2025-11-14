// WebSocket connection for real-time updates
class AgentDashboard {
    constructor() {
        this.ws = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        
        this.initializeDashboard();
        this.connectWebSocket();
    }

    initializeDashboard() {
        // Initialize charts and UI components
        this.initializeCharts();
        this.initializeEventListeners();
        this.updateStatus('initializing');
    }

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;
        
        try {
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onopen = () => {
                console.log('✅ Connected to agent dashboard');
                this.isConnected = true;
                this.reconnectAttempts = 0;
                this.updateStatus('connected');
                this.requestStatusUpdate();
            };
            
            this.ws.onmessage = (event) => {
                this.handleMessage(JSON.parse(event.data));
            };
            
            this.ws.onclose = () => {
                console.log('❌ Disconnected from agent dashboard');
                this.isConnected = false;
                this.updateStatus('disconnected');
                this.attemptReconnect();
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateStatus('error');
            };
            
        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
            this.attemptReconnect();
        }
    }

    attemptReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Attempting reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
            setTimeout(() => this.connectWebSocket(), 3000);
        } else {
            console.error('Max reconnection attempts reached');
            this.updateStatus('failed');
        }
    }

    handleMessage(message) {
        const messageType = message.type;
        
        switch (messageType) {
            case 'THREAT_DETECTED':
                this.handleThreatDetected(message);
                break;
            case 'EMERGENCY_RESPONSE':
                this.handleEmergencyResponse(message);
                break;
            case 'HIGH_ALERT_RESPONSE':
                this.handleHighAlertResponse(message);
                break;
            case 'ENHANCED_MONITORING':
                this.handleEnhancedMonitoring(message);
                break;
            case 'STATUS_UPDATE':
                this.handleStatusUpdate(message);
                break;
            case 'COMMAND_EXECUTED':
                this.handleCommandExecuted(message);
                break;
            default:
                console.log('Unknown message type:', messageType);
        }
    }

    handleThreatDetected(message) {
        this.showAlert('threat', message.data);
        this.updateThreatStats(message.detection_stats);
        this.addToEventLog('THREAT_DETECTED', message.data, 'critical');
    }

    handleEmergencyResponse(message) {
        this.showAlert('emergency', message);
        this.addToEventLog('EMERGENCY_RESPONSE', `Actions: ${message.actions.join(', ')}`, 'critical');
    }

    handleHighAlertResponse(message) {
        this.showAlert('high', message);
        this.addToEventLog('HIGH_ALERT', `Actions: ${message.actions.join(', ')}`, 'warning');
    }

    handleEnhancedMonitoring(message) {
        this.showAlert('info', message);
        this.addToEventLog('ENHANCED_MONITORING', 'Enhanced monitoring activated', 'info');
    }

    handleStatusUpdate(message) {
        this.updateDashboard(message);
    }

    handleCommandExecuted(message) {
        this.addToEventLog('COMMAND_EXECUTED', `Executed: ${message.commands.join(', ')}`, 'info');
    }

    showAlert(type, data) {
        const alertsContainer = document.getElementById('alerts-container');
        const alertDiv = document.createElement('div');
        
        alertDiv.className = `alert alert-${type}`;
        alertDiv.innerHTML = `
            <strong>${this.getAlertTitle(type)}</strong>
            <div>${this.formatAlertContent(data)}</div>
            <small>${new Date().toLocaleTimeString()}</small>
        `;
        
        alertsContainer.insertBefore(alertDiv, alertsContainer.firstChild);
        
        // Remove alert after 10 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.parentNode.removeChild(alertDiv);
            }
        }, 10000);
    }

    getAlertTitle(type) {
        const titles = {
            'threat': '🚨 THREAT DETECTED',
            'emergency': '🛑 EMERGENCY RESPONSE',
            'high': '⚠️ HIGH ALERT',
            'info': '🔍 ENHANCED MONITORING'
        };
        return titles[type] || 'ALERT';
    }

    formatAlertContent(data) {
        if (data.threat_level) {
            return `Level: ${data.threat_level.toUpperCase()} | Confidence: ${(data.confidence * 100).toFixed(1)}%`;
        } else if (data.actions) {
            return `Actions taken: ${data.actions.join(', ')}`;
        }
        return JSON.stringify(data, null, 2);
    }

    updateStatus(status) {
        const statusElement = document.getElementById('agent-status');
        if (statusElement) {
            statusElement.innerHTML = `
                <div class="status-${status}">
                    <h4>Agent Status: ${status.toUpperCase()}</h4>
                    <p>WebSocket: ${this.isConnected ? 'Connected' : 'Disconnected'}</p>
                </div>
            `;
        }
    }

    updateDashboard(statusData) {
        this.updateSystemInfo(statusData);
        this.updateThreatStats(statusData.detection_stats);
        this.updateCharts(statusData);
    }

    updateSystemInfo(statusData) {
        const systemElement = document.getElementById('system-info');
        if (systemElement && statusData.agent_status) {
            systemElement.innerHTML = `
                <p><strong>Status:</strong> ${statusData.agent_status}</p>
                <p><strong>Monitoring:</strong> ${statusData.monitoring_active ? 'Active' : 'Inactive'}</p>
                <p><strong>Files Monitored:</strong> ${statusData.stats?.files_monitored || 0}</p>
                <p><strong>Last Detection:</strong> ${statusData.stats?.last_detection || 'Never'}</p>
            `;
        }
    }

    updateThreatStats(stats) {
        const statsElement = document.getElementById('threat-stats');
        if (statsElement && stats) {
            statsElement.innerHTML = `
                <p><strong>Total Detections:</strong> ${stats.total_detections || 0}</p>
                <p><strong>Supervised ML:</strong> ${stats.layer1_supervised || 0}</p>
                <p><strong>Anomaly Detection:</strong> ${stats.layer2_anomaly || 0}</p>
                <p><strong>Rule-based:</strong> ${stats.layer3_rules || 0}</p>
                <p><strong>Slow Ransomware:</strong> ${stats.layer4_slow || 0}</p>
            `;
        }
    }

    addToEventLog(eventType, message, level = 'info') {
        const eventLog = document.getElementById('event-log');
        const logEntry = document.createElement('div');
        
        logEntry.className = `log-entry log-${level}`;
        logEntry.innerHTML = `
            <strong>${eventType}</strong>
            <div>${message}</div>
            <small>${new Date().toLocaleTimeString()}</small>
        `;
        
        eventLog.insertBefore(logEntry, eventLog.firstChild);
        
        // Keep only last 50 entries
        while (eventLog.children.length > 50) {
            eventLog.removeChild(eventLog.lastChild);
        }
    }

    initializeCharts() {
        // Initialize Chart.js charts for visualization
        this.initializeThreatLevelChart();
        this.initializeDetectionLayerChart();
    }

    initializeThreatLevelChart() {
        // Implementation for threat level chart
        const ctx = document.getElementById('threatLevelChart');
        if (ctx) {
            this.threatLevelChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Suspicious', 'Normal'],
                    datasets: [{
                        data: [0, 0, 0, 100],
                        backgroundColor: ['#dc2626', '#ea580c', '#d97706', '#16a34a']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Threat Level Distribution'
                        }
                    }
                }
            });
        }
    }

    initializeDetectionLayerChart() {
        // Implementation for detection layer chart
        const ctx = document.getElementById('detectionLayerChart');
        if (ctx) {
            this.detectionLayerChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Supervised', 'Anomaly', 'Rules', 'Slow'],
                    datasets: [{
                        label: 'Detections',
                        data: [0, 0, 0, 0],
                        backgroundColor: '#3b82f6'
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Detection Layer Performance'
                        }
                    }
                }
            });
        }
    }

    initializeEventListeners() {
        // Add event listeners for dashboard controls
        document.getElementById('btn-start-monitoring')?.addEventListener('click', () => this.startMonitoring());
        document.getElementById('btn-stop-monitoring')?.addEventListener('click', () => this.stopMonitoring());
        document.getElementById('btn-simulate-threat')?.addEventListener('click', () => this.simulateThreat());
        document.getElementById('btn-request-status')?.addEventListener('click', () => this.requestStatusUpdate());
    }

    startMonitoring() {
        this.sendMessage({ type: 'START_MONITORING' });
    }

    stopMonitoring() {
        this.sendMessage({ type: 'STOP_MONITORING' });
    }

    simulateThreat() {
        this.sendMessage({ type: 'SIMULATE_THREAT' });
    }

    requestStatusUpdate() {
        this.sendMessage({ type: 'GET_STATUS' });
    }

    sendMessage(message) {
        if (this.ws && this.isConnected) {
            this.ws.send(JSON.stringify(message));
        } else {
            console.error('WebSocket not connected');
        }
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.agentDashboard = new AgentDashboard();
});

// API functions for configuration
async function configureAgent() {
    const monitorDir = prompt('Enter directory to monitor:');
    const backupDir = prompt('Enter backup directory:');
    
    if (monitorDir && backupDir) {
        try {
            const response = await fetch('/api/v1/configure', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    monitor_directory: monitorDir,
                    backup_directory: backupDir,
                    important_folders: []
                })
            });
            
            if (response.ok) {
                alert('Agent configured successfully!');
            } else {
                alert('Configuration failed!');
            }
        } catch (error) {
            console.error('Configuration error:', error);
            alert('Configuration error!');
        }
    }
}

async function startMonitoring() {
    try {
        const response = await fetch('/api/v1/start-monitoring', {
            method: 'POST'
        });
        
        if (response.ok) {
            alert('Monitoring started!');
        } else {
            alert('Failed to start monitoring!');
        }
    } catch (error) {
        console.error('Start monitoring error:', error);
        alert('Start monitoring error!');
    }
}

async function simulateThreat() {
    try {
        const response = await fetch('/api/v1/simulate-threat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                threat_type: 'DEMO_RANSOMWARE',
                threat_level: 'critical',
                confidence: 0.95
            })
        });
        
        if (response.ok) {
            alert('Threat simulation started!');
        } else {
            alert('Failed to simulate threat!');
        }
    } catch (error) {
        console.error('Threat simulation error:', error);
        alert('Threat simulation error!');
    }
}