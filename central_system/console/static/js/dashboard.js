// Additional JavaScript for dashboard functionality

// Real-time updates
function startRealTimeUpdates() {
    setInterval(() => {
        if (currentTab === 'dashboard') {
            updateDashboard();
        }
    }, 10000); // Update every 10 seconds
}

// Chart initialization
function initializeCharts() {
    const ctx = document.getElementById('metrics-chart').getContext('2d');
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Response Time (s)',
                data: [],
                borderColor: '#2563eb',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

// Notification system
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <div class="toast-content">
            <span class="toast-message">${message}</span>
            <button class="toast-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
    `;
    
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}