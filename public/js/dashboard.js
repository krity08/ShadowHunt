async function loadDashboardData() {
    try {
        const response = await fetch('/api/dashboard-data');
        const data = await response.json();
        
        // Update main stats
        document.getElementById('totalIncidents').textContent = data.totalScans;
        document.getElementById('highSeverity').textContent = data.highThreatCount;
        document.getElementById('mediumSeverity').textContent = data.mediumThreatCount || 0;
        document.getElementById('lowSeverity').textContent = data.lowThreatCount;
        
        // Update clean vs infected lines
        document.getElementById('totalClean').textContent = data.totalClean;
        document.getElementById('totalInfected').textContent = data.totalInfected;
        
        const total = data.totalClean + data.totalInfected;
        const cleanPercent = total > 0 ? (data.totalClean / total) * 100 : 0;
        const infectedPercent = total > 0 ? (data.totalInfected / total) * 100 : 0;
        
        document.getElementById('cleanProgress').style.width = cleanPercent + '%';
        document.getElementById('infectedProgress').style.width = infectedPercent + '%';
        
        // Update threat level
        const threatLevelValue = document.getElementById('threatLevelValue');
        if (data.threatSeverity === 'high') {
            threatLevelValue.innerHTML = '🔴 CRITICAL - IMMEDIATE ACTION REQUIRED';
            threatLevelValue.style.color = '#ff4444';
        } else {
            threatLevelValue.innerHTML = '🟢 NORMAL - MONITORING ACTIVE';
            threatLevelValue.style.color = '#00ff88';
        }
        
        // Create threat distribution chart
        const ctx = document.getElementById('threatChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['High Severity', 'Medium Severity', 'Low Severity'],
                datasets: [{
                    data: [data.highThreatCount, data.mediumThreatCount || 0, data.lowThreatCount],
                    backgroundColor: ['#ff4444', '#ffaa00', '#00ff88'],
                    borderColor: '#0a0c15',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#e0e0e0' }
                    }
                }
            }
        });
        
        // Display recent scans
        const recentScansDiv = document.getElementById('recentScans');
        if (data.recentScans.length === 0) {
            recentScansDiv.innerHTML = '<div class="empty-state">No incidents detected yet</div>';
        } else {
            recentScansDiv.innerHTML = data.recentScans.map(scan => {
                let threatClass = '';
                if (scan.analysis.threatLevel === 'high') threatClass = 'scan-threat-high';
                else if (scan.analysis.threatLevel === 'medium') threatClass = 'scan-threat-medium';
                else threatClass = 'scan-threat-low';
                
                return `
                    <div class="scan-item ${threatClass}">
                        <div class="scan-filename">📄 ${scan.filename}</div>
                        <div>🎯 Threat: ${scan.analysis.threatLevel.toUpperCase()} | Score: ${scan.analysis.threatScore}/100</div>
                        <div>🔍 Keywords Found: ${scan.analysis.keywordsFound || 0}</div>
                        <div>⏱️ ${new Date(scan.timestamp).toLocaleString()}</div>
                    </div>
                `;
            }).join('');
        }
        
        // Display failed logins
        const failedLoginsDiv = document.getElementById('failedLogins');
        if (data.failedLogins.length === 0) {
            failedLoginsDiv.innerHTML = '<div class="empty-state">No suspicious activity detected</div>';
        } else {
            failedLoginsDiv.innerHTML = data.failedLogins.map(login => `
                <div class="login-item">
                    <div>⚠️ Failed login attempt</div>
                    <div>👤 Username: ${login.username}</div>
                    <div>⏱️ ${new Date(login.timestamp).toLocaleString()}</div>
                </div>
            `).join('');
        }
        
        // Update timestamp
        document.getElementById('timestamp').innerHTML = `🕐 LAST UPDATE: ${new Date().toLocaleString()}`;
        
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

// Auto-refresh every 10 seconds
loadDashboardData();
setInterval(loadDashboardData, 10000);