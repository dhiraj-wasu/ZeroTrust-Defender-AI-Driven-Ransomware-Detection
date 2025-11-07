// Real-time dashboard functionality
class DashboardUpdater {
    constructor() {
        this.statsInterval = null;
        this.charts = {};
    }

    initialize() {
        this.startRealTimeUpdates();
        this.initializeCharts();
    }

    startRealTimeUpdates() {
        // Update stats every 5 seconds
        this.statsInterval = setInterval(() => {
            this.updateStats();
            this.updateIncidents();
            this.updateAgents();
        }, 5000);

        this.updateStats(); // Initial call
    }

    async updateStats() {
        try {
            const response = await fetch('/admin/api/stats');
            const data = await response.json();
            
            document.getElementById('liveAgents').textContent = data.online_agents;
            document.getElementById('liveIncidents').textContent = data.critical_incidents;
            document.getElementById('responseTime').textContent = '125ms'; // Mock data
            document.getElementById('systemHealth').textContent = '95%';
            
        } catch (error) {
            console.error('Error updating stats:', error);
        }
    }

    async updateIncidents() {
        try {
            const response = await fetch('/admin/api/incidents/recent');
            const data = await response.json();
            
            // Update incidents table if needed
            if (data.incidents.length > 0) {
                this.updateIncidentsTable(data.incidents);
            }
            
        } catch (error) {
            console.error('Error updating incidents:', error);
        }
    }

    async updateAgents() {
        try {
            const response = await fetch('/admin/api/agents/status');
            const data = await response.json();
            
            // Update agent chart
            this.updateAgentChart(data);
            
        } catch (error) {
            console.error('Error updating agents:', error);
        }
    }

    updateIncidentsTable(incidents) {
        // Implement dynamic table update
        console.log('Updating incidents table with:', incidents.length, 'incidents');
    }

    initializeCharts() {
        // Initialize agent status chart
        const agentCtx = document.getElementById('agentChart').getContext('2d');
        this.charts.agent = new Chart(agentCtx, {
            type: 'doughnut',
            data: {
                labels: ['Online', 'Offline', 'Quarantined'],
                datasets: [{
                    data: [8, 2, 1], // Mock data
                    backgroundColor: ['#28a745', '#6c757d', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    updateAgentChart(data) {
        if (this.charts.agent) {
            const online = data.agents.filter(a => a.status === 'online').length;
            const offline = data.agents.filter(a => a.status === 'offline').length;
            const quarantined = data.agents.filter(a => a.status === 'quarantined').length;
            
            this.charts.agent.data.datasets[0].data = [online, offline, quarantined];
            this.charts.agent.update();
        }
    }

    stop() {
        if (this.statsInterval) {
            clearInterval(this.statsInterval);
        }
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    window.dashboardUpdater = new DashboardUpdater();
    window.dashboardUpdater.initialize();
});

// Utility functions
function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function getSeverityBadge(level) {
    const classes = {
        'critical': 'bg-danger',
        'high': 'bg-warning',
        'medium': 'bg-info',
        'low': 'bg-secondary'
    };
    return `<span class="badge ${classes[level] || 'bg-secondary'}">${level.toUpperCase()}</span>`;
}