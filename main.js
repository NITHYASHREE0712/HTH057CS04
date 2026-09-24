document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('scanForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const targetUrl = document.getElementById('targetUrl').value.trim();
        const resultEl = document.getElementById('scanResult');
        
        if (!targetUrl) {
            resultEl.innerHTML = '<span style="color: #ff4444;">❌ Please enter a target URL!</span>';
            return;
        }

        resultEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running SQLmap scan... (up to 2 minutes)';

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targetUrl })
            });
            const data = await res.json();
            resultEl.innerHTML = `
                <div style="background: rgba(0,0,0,0.8); padding: 20px; border-radius: 10px; border-left: 5px solid ${
                    data.severity === 'High' ? '#ff4444' : 
                    data.severity === 'Medium' ? '#ffaa00' : '#00ff88'
                }">
                    <h3 style="margin: 0 0 10px 0; color: ${
                        data.severity === 'High' ? '#ff4444' : 
                        data.severity === 'Medium' ? '#ffaa00' : '#00ff88'
                    }"><i class="fas fa-${data.severity === 'High' ? 'exclamation-triangle' : 'check-circle'}"></i> ${data.severity || 'Info'}</h3>
                    <p><strong>Injection Type:</strong> ${data.injectionType || 'Unknown'}</p>
                    <p><strong>Status:</strong> ${data.message}</p>
                    ${data.error ? `<p style="color: #ffaa00;"><strong>Warning:</strong> ${data.error}</p>` : ''}
                </div>
            `;
            
            // 🚨 Show threat popup if SQL injection detected
            if (data.severity === 'High' || (data.injectionType && data.injectionType.includes('SQLi'))) {
                if (typeof showThreatPopup === 'function') {
                    showThreatPopup(targetUrl, data.severity, data.injectionType);
                }
            }
            
            // Auto refresh logs
            loadLogs();
        } catch (error) {
            resultEl.innerHTML = `<span style="color: #ff4444;">❌ Scan failed: ${error.message}</span>`;
        }
    });

    // Handle secure login
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const resultEl = document.getElementById('loginResult');
        
        resultEl.textContent = 'Checking credentials...';

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await res.json();
            
            if (data.success) {
                resultEl.innerHTML = `<span style="color: #00ff88;">✅ ${data.message}!</span>`;
            } else {
                resultEl.innerHTML = `<span style="color: #ff4444;">❌ ${data.message}</span>`;
            }
        } catch (error) {
            resultEl.innerHTML = `<span style="color: #ff4444;">❌ Login failed: ${error.message}</span>`;
        }
    });

    // ✅ FIXED: Matches server.js field names (targeturl, injectiontype, severity, etc)
    async function loadLogs() {
        try {
            const res = await fetch('/api/logs');
            const data = await res.json();
            const tbody = document.getElementById('logsTableBody');
            
            if (!data.success || !data.logs || data.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px; color: #aaa;">No attack logs yet. Run a scan!</td></tr>';
                return;
            }

            tbody.innerHTML = data.logs.map(log => {
                const severityClass = log.severity?.toLowerCase() || 'info';
                const severityColor = log.severity === 'High' ? '#ff4444' : 
                                    log.severity === 'Medium' ? '#ffaa00' : 
                                    log.severity === 'Low' ? '#00ff88' : '#aaa';
                
                return `
                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.1);">
                        <td style="font-weight: bold; color: #00d4ff;">${log.id}</td>
                        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${log.targeturl}">${log.targeturl}</td>
                        <td>${log.injectiontype}</td>
                        <td>
                            <span style="padding: 4px 12px; border-radius: 15px; background: ${severityColor}20; 
                                         color: ${severityColor}; font-weight: bold; font-size: 12px; border: 1px solid ${severityColor};">
                                ${log.severity || 'Info'}
                            </span>
                        </td>
                        <td>${log.ipaddress || 'Unknown'}</td>
                        <td>${new Date(log.createdat).toLocaleString('en-IN')}</td>
                    </tr>
                `;
            }).join('');
        } catch (error) {
            console.error('Load logs error:', error);
            document.getElementById('logsTableBody').innerHTML = 
                '<tr><td colspan="6" style="text-align: center; color: #ff4444;">Failed to load logs</td></tr>';
        }
    }

    // Event listeners
    document.getElementById('refreshLogs')?.addEventListener('click', loadLogs);
    
    // Auto-refresh logs every 5 seconds
    setInterval(loadLogs, 5000);
    
    // Initial load
    loadLogs();
});
