/**
 * Network Monitoring Tool - Frontend JavaScript
 * Handles dynamic interactions and real-time updates
 */

// Global variables
let scanStatusCheckInterval;
let notificationCheckInterval;

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApplication();
});

/**
 * Initialize the application
 */
function initializeApplication() {
    // Initialize tooltips
    initializeTooltips();
    
    // Initialize auto-refresh for dashboard
    initializeAutoRefresh();
    
    // Initialize scan status checking
    initializeScanStatusCheck();
    
    // Initialize form validation
    initializeFormValidation();
    
    // Initialize keyboard shortcuts
    initializeKeyboardShortcuts();
    
    console.log('Network Monitoring Tool initialized successfully');
}

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Initialize auto-refresh functionality for dashboard
 */
function initializeAutoRefresh() {
    // Auto-refresh recent scans every 30 seconds on dashboard
    if (window.location.pathname === '/') {
        setInterval(function() {
            refreshRecentScans();
        }, 30000);
    }
}

/**
 * Initialize scan status checking for active scans
 */
function initializeScanStatusCheck() {
    // Check if we're on a results page with an active scan
    const scanProgressElement = document.getElementById('scan-progress');
    if (scanProgressElement) {
        const ipAddress = getIpAddressFromUrl();
        if (ipAddress) {
            startScanStatusCheck(ipAddress);
        }
    }
}

/**
 * Initialize form validation
 */
function initializeFormValidation() {
    // Custom IP address validation
    const ipInputs = document.querySelectorAll('input[type="text"][pattern*="ip"]');
    ipInputs.forEach(function(input) {
        input.addEventListener('input', function(e) {
            validateIpAddress(e.target);
        });
    });
    
    // Prevent double-submission of forms
    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            const submitButton = form.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
                
                // Re-enable after 10 seconds as fallback
                setTimeout(function() {
                    submitButton.disabled = false;
                    submitButton.innerHTML = submitButton.getAttribute('data-original-text') || 'Submit';
                }, 10000);
            }
        });
    });
}

/**
 * Initialize keyboard shortcuts
 */
function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl+R or F5 - Refresh page
        if ((e.ctrlKey && e.key === 'r') || e.key === 'F5') {
            e.preventDefault();
            location.reload();
        }
        
        // Ctrl+N - Focus on IP input (new scan)
        if (e.ctrlKey && e.key === 'n') {
            e.preventDefault();
            const ipInput = document.getElementById('ip_address');
            if (ipInput) {
                ipInput.focus();
            }
        }
        
        // Escape - Close modals or clear focus
        if (e.key === 'Escape') {
            const activeElement = document.activeElement;
            if (activeElement && activeElement.blur) {
                activeElement.blur();
            }
        }
    });
}

/**
 * Validate IP address input
 */
function validateIpAddress(input) {
    const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const value = input.value.trim();
    
    if (value === '') {
        input.classList.remove('is-valid', 'is-invalid');
        return;
    }
    
    if (ipPattern.test(value)) {
        input.classList.remove('is-invalid');
        input.classList.add('is-valid');
    } else {
        input.classList.remove('is-valid');
        input.classList.add('is-invalid');
    }
}

/**
 * Get IP address from current URL
 */
function getIpAddressFromUrl() {
    const path = window.location.pathname;
    const matches = path.match(/\/results\/(.+)$/);
    return matches ? matches[1] : null;
}

/**
 * Start checking scan status for a specific IP
 */
function startScanStatusCheck(ipAddress) {
    if (scanStatusCheckInterval) {
        clearInterval(scanStatusCheckInterval);
    }
    
    scanStatusCheckInterval = setInterval(function() {
        checkScanStatus(ipAddress);
    }, 3000); // Check every 3 seconds
    
    // Initial check
    checkScanStatus(ipAddress);
}

/**
 * Check scan status for a specific IP
 */
function checkScanStatus(ipAddress) {
    fetch(`/api/scan_status/${encodeURIComponent(ipAddress)}`)
        .then(response => response.json())
        .then(data => {
            updateScanProgress(data);
            
            if (data.status === 'completed' || data.status === 'failed') {
                if (scanStatusCheckInterval) {
                    clearInterval(scanStatusCheckInterval);
                    scanStatusCheckInterval = null;
                }
                
                if (data.status === 'completed') {
                    showNotification('Scan completed successfully!', 'success');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showNotification(`Scan failed: ${data.error || 'Unknown error'}`, 'danger');
                }
            }
        })
        .catch(error => {
            console.error('Error checking scan status:', error);
            showNotification('Error checking scan status', 'warning');
        });
}

/**
 * Update scan progress display
 */
function updateScanProgress(statusData) {
    const progressElement = document.getElementById('scan-progress');
    if (!progressElement) return;
    
    const status = statusData.status;
    const startTime = statusData.start_time;
    
    let progressHtml = '';
    
    switch (status) {
        case 'running':
            const elapsed = startTime ? getElapsedTime(startTime) : 'Unknown';
            progressHtml = `
                <div class="progress mb-2">
                    <div class="progress-bar progress-bar-striped progress-bar-animated" 
                         style="width: 100%"></div>
                </div>
                <small class="text-muted">Elapsed time: ${elapsed}</small>
            `;
            break;
            
        case 'completed':
            progressHtml = `
                <div class="alert alert-success mb-0">
                    <i data-feather="check-circle" class="me-2"></i>
                    Scan completed successfully!
                </div>
            `;
            break;
            
        case 'failed':
            progressHtml = `
                <div class="alert alert-danger mb-0">
                    <i data-feather="x-circle" class="me-2"></i>
                    Scan failed: ${statusData.error || 'Unknown error'}
                </div>
            `;
            break;
            
        default:
            progressHtml = `
                <div class="alert alert-info mb-0">
                    <i data-feather="info" class="me-2"></i>
                    Status: ${status}
                </div>
            `;
    }
    
    progressElement.innerHTML = progressHtml;
    
    // Re-initialize feather icons
    if (typeof feather !== 'undefined') {
        feather.replace();
    }
}

/**
 * Calculate elapsed time from start time
 */
function getElapsedTime(startTime) {
    try {
        const start = new Date(startTime);
        const now = new Date();
        const elapsed = Math.floor((now - start) / 1000);
        
        if (elapsed < 60) {
            return `${elapsed} seconds`;
        } else {
            const minutes = Math.floor(elapsed / 60);
            const seconds = elapsed % 60;
            return `${minutes}m ${seconds}s`;
        }
    } catch (error) {
        return 'Unknown';
    }
}

/**
 * Show notification to user
 */
function showNotification(message, type = 'info', duration = 5000) {
    const alertClass = type === 'danger' ? 'alert-danger' : 
                      type === 'warning' ? 'alert-warning' :
                      type === 'success' ? 'alert-success' : 'alert-info';
    
    const icon = type === 'danger' ? 'alert-circle' :
                 type === 'warning' ? 'alert-triangle' :
                 type === 'success' ? 'check-circle' : 'info';
    
    const notificationHtml = `
        <div class="alert ${alertClass} alert-dismissible fade show notification" role="alert">
            <i data-feather="${icon}" class="me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    // Create notification container if it doesn't exist
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.position = 'fixed';
        container.style.top = '20px';
        container.style.right = '20px';
        container.style.zIndex = '9999';
        container.style.maxWidth = '400px';
        document.body.appendChild(container);
    }
    
    // Add notification
    const notificationElement = document.createElement('div');
    notificationElement.innerHTML = notificationHtml;
    container.appendChild(notificationElement.firstElementChild);
    
    // Re-initialize feather icons
    if (typeof feather !== 'undefined') {
        feather.replace();
    }
    
    // Auto-remove after duration
    if (duration > 0) {
        setTimeout(function() {
            const notification = container.querySelector('.notification');
            if (notification) {
                const alert = new bootstrap.Alert(notification);
                alert.close();
            }
        }, duration);
    }
}

/**
 * Refresh recent scans on dashboard
 */
function refreshRecentScans() {
    const recentScansTable = document.querySelector('.table tbody');
    if (!recentScansTable) return;
    
    // Add loading indicator
    recentScansTable.style.opacity = '0.6';
    
    fetch('/api/recent_scans')
        .then(response => response.json())
        .then(data => {
            if (data.scans) {
                updateRecentScansTable(data.scans);
            }
        })
        .catch(error => {
            console.error('Error refreshing recent scans:', error);
        })
        .finally(() => {
            recentScansTable.style.opacity = '1';
        });
}

/**
 * Update recent scans table with new data
 */
function updateRecentScansTable(scans) {
    const tbody = document.querySelector('.table tbody');
    if (!tbody) return;
    
    // Generate new table rows
    let tableHtml = '';
    scans.forEach(scan => {
        const statusBadge = scan.success ? 
            '<span class="badge bg-success"><i data-feather="check" class="me-1"></i>Success</span>' :
            '<span class="badge bg-danger"><i data-feather="x" class="me-1"></i>Failed</span>';
        
        const openPorts = scan.success ? 
            `<span class="badge bg-info">${scan.open_ports_count}</span>` :
            '<span class="text-muted">-</span>';
        
        tableHtml += `
            <tr>
                <td><strong>${scan.ip_address}</strong></td>
                <td><span class="text-muted">${formatDateTime(scan.timestamp)}</span></td>
                <td>${statusBadge}</td>
                <td>${openPorts}</td>
                <td><span class="text-muted">${scan.scan_time}s</span></td>
                <td>
                    <a href="/results/${scan.ip_address}" class="btn btn-sm btn-outline-primary">
                        <i data-feather="eye" class="me-1"></i>View
                    </a>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = tableHtml;
    
    // Re-initialize feather icons
    if (typeof feather !== 'undefined') {
        feather.replace();
    }
}

/**
 * Format datetime string for display
 */
function formatDateTime(timestamp) {
    try {
        const date = new Date(timestamp);
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: '2-digit',
            year: 'numeric'
        }) + ' ' + date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        });
    } catch (error) {
        return timestamp;
    }
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Copied to clipboard!', 'success', 2000);
        }).catch(err => {
            console.error('Failed to copy to clipboard:', err);
            showNotification('Failed to copy to clipboard', 'danger');
        });
    } else {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            showNotification('Copied to clipboard!', 'success', 2000);
        } catch (err) {
            console.error('Failed to copy to clipboard:', err);
            showNotification('Failed to copy to clipboard', 'danger');
        }
        
        document.body.removeChild(textArea);
    }
}

/**
 * Export scan data
 */
function exportScanData(ipAddress, format = 'json') {
    const url = `/api/export/${encodeURIComponent(ipAddress)}?format=${format}`;
    
    fetch(url)
        .then(response => {
            if (!response.ok) {
                throw new Error('Export failed');
            }
            return response.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `scan_data_${ipAddress}.${format}`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            showNotification(`Scan data exported as ${format.toUpperCase()}`, 'success');
        })
        .catch(error => {
            console.error('Export error:', error);
            showNotification('Failed to export scan data', 'danger');
        });
}

/**
 * Confirm action with user
 */
function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}

/**
 * Debounce function to limit API calls
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Check if element is in viewport
 */
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

/**
 * Smooth scroll to element
 */
function scrollToElement(selector) {
    const element = document.querySelector(selector);
    if (element) {
        element.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    }
}

/**
 * Handle window resize events
 */
window.addEventListener('resize', debounce(function() {
    // Recalculate any responsive elements if needed
    console.log('Window resized');
}, 250));

/**
 * Handle page visibility changes
 */
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        // Page is hidden, pause any active polling
        if (scanStatusCheckInterval) {
            clearInterval(scanStatusCheckInterval);
        }
    } else {
        // Page is visible, resume polling if needed
        const ipAddress = getIpAddressFromUrl();
        if (ipAddress && document.getElementById('scan-progress')) {
            startScanStatusCheck(ipAddress);
        }
    }
});

/**
 * Clean up intervals when page is unloaded
 */
window.addEventListener('beforeunload', function() {
    if (scanStatusCheckInterval) {
        clearInterval(scanStatusCheckInterval);
    }
    if (notificationCheckInterval) {
        clearInterval(notificationCheckInterval);
    }
});

/**
 * Tableau 20 color palette
 */
const TABLEAU_20_COLORS = [
    '#4E79A7', '#F28E2C', '#E15759', '#76B7B2', '#59A14F',
    '#EDC949', '#AF7AA1', '#FF9D9A', '#9C755F', '#BAB0AB',
    '#1F77B4', '#FF7F0E', '#2CA02C', '#D62728', '#9467BD',
    '#8C564B', '#E377C2', '#7F7F7F', '#BCBD22', '#17BECF'
];

/**
 * Initialize port history chart
 */
function initializePortHistoryChart(ipAddress) {
    const chartCanvas = document.getElementById('port-history-chart');
    const loadingElement = document.getElementById('chart-loading');
    
    if (!chartCanvas || !loadingElement) {
        console.error('Chart elements not found');
        return;
    }
    
    // Fetch port history data
    fetch(`/api/port_history/${encodeURIComponent(ipAddress)}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            
            if (!data.port_list || data.port_list.length === 0) {
                loadingElement.innerHTML = '<p class="text-muted text-center">No port history data available.</p>';
                return;
            }
            
            createPortHistoryChart(data, chartCanvas);
            createPortToggles(data.port_list, data.ports);
            loadingElement.style.display = 'none';
        })
        .catch(error => {
            console.error('Error loading port history:', error);
            loadingElement.innerHTML = '<div class="alert alert-danger">Error loading port history data.</div>';
        });
}

/**
 * Create the port history chart
 */
function createPortHistoryChart(data, canvas) {
    const ctx = canvas.getContext('2d');
    
    // Prepare datasets for each port
    const datasets = data.port_list.map((port, index) => {
        const color = TABLEAU_20_COLORS[index % TABLEAU_20_COLORS.length];
        const portData = data.ports[port];
        
        return {
            label: `Port ${port}`,
            data: portData.data,
            borderColor: color,
            backgroundColor: color + '20', // Add transparency
            borderWidth: 2,
            pointBackgroundColor: color,
            pointBorderColor: color,
            pointRadius: 4,
            pointHoverRadius: 6,
            tension: 0, // Straight lines
            stepped: false,
            fill: false
        };
    });
    
    // Prepare labels from timestamps
    const labels = data.timeline.map(timestamp => {
        const date = new Date(timestamp);
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: '2-digit'
        }) + ' ' + date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        });
    });

    // Create chart
    window.portHistoryChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Scan Time'
                    },
                    ticks: {
                        maxTicksLimit: 10
                    }
                },
                y: {
                    min: 0,
                    max: 2,
                    ticks: {
                        stepSize: 1,
                        callback: function(value) {
                            if (value === 0) return 'Closed';
                            if (value === 1) return 'Open';
                            return ''; // Hide label for value 2
                        }
                    },
                    title: {
                        display: true,
                        text: 'Port Status'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false // We'll use custom toggles
                },
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            const timestamp = data.timeline[context[0].dataIndex];
                            const date = new Date(timestamp);
                            return 'Scan Time: ' + date.toLocaleDateString('en-US', {
                                month: 'short',
                                day: '2-digit',
                                year: 'numeric'
                            }) + ' ' + date.toLocaleTimeString('en-US', {
                                hour: '2-digit',
                                minute: '2-digit',
                                hour12: false
                            });
                        },
                        label: function(context) {
                            const port = context.dataset.label.replace('Port ', '');
                            const status = context.parsed.y === 1 ? 'Open' : 'Closed';
                            const portInfo = data.ports[port];
                            
                            let tooltip = `${context.dataset.label}: ${status}`;
                            if (portInfo) {
                                const firstSeen = new Date(portInfo.first_seen);
                                const lastSeen = new Date(portInfo.last_seen);
                                tooltip += `\nFirst seen: ${firstSeen.toLocaleDateString('en-US', {
                                    month: 'short',
                                    day: '2-digit',
                                    year: 'numeric'
                                })} ${firstSeen.toLocaleTimeString('en-US', {
                                    hour: '2-digit',
                                    minute: '2-digit',
                                    hour12: false
                                })}`;
                                tooltip += `\nLast seen: ${lastSeen.toLocaleDateString('en-US', {
                                    month: 'short',
                                    day: '2-digit',
                                    year: 'numeric'
                                })} ${lastSeen.toLocaleTimeString('en-US', {
                                    hour: '2-digit',
                                    minute: '2-digit',
                                    hour12: false
                                })}`;
                            }
                            
                            return tooltip.split('\n');
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create port toggle chips
 */
function createPortToggles(portList, portsData) {
    const toggleContainer = document.getElementById('port-toggle-list');
    if (!toggleContainer) return;
    
    toggleContainer.innerHTML = '';
    
    portList.forEach((port, index) => {
        const color = TABLEAU_20_COLORS[index % TABLEAU_20_COLORS.length];
        
        const chip = document.createElement('div');
        chip.className = 'port-toggle-chip';
        chip.style.cssText = `
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            margin: 2px;
            background-color: ${color};
            color: white;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            user-select: none;
            transition: opacity 0.2s ease;
        `;
        
        const colorIndicator = document.createElement('span');
        colorIndicator.style.cssText = `
            width: 8px;
            height: 8px;
            background-color: white;
            border-radius: 50%;
            margin-right: 6px;
        `;
        
        const label = document.createElement('span');
        label.textContent = `Port ${port}`;
        
        chip.appendChild(colorIndicator);
        chip.appendChild(label);
        
        // Add click handler to toggle port visibility
        chip.addEventListener('click', function() {
            togglePortVisibility(index, chip);
        });
        
        // Store initial state
        chip.dataset.visible = 'true';
        chip.dataset.datasetIndex = index;
        
        toggleContainer.appendChild(chip);
    });
}

/**
 * Toggle port visibility on chart
 */
function togglePortVisibility(datasetIndex, chipElement) {
    if (!window.portHistoryChart) return;
    
    const chart = window.portHistoryChart;
    const isVisible = chipElement.dataset.visible === 'true';
    
    // Toggle dataset visibility
    chart.data.datasets[datasetIndex].hidden = isVisible;
    chart.update();
    
    // Update chip appearance
    if (isVisible) {
        chipElement.style.opacity = '0.4';
        chipElement.dataset.visible = 'false';
    } else {
        chipElement.style.opacity = '1';
        chipElement.dataset.visible = 'true';
    }
}

/**
 * Initialize aggregate port history chart
 */
function initializeAggregatePortHistoryChart() {
    const chartCanvas = document.getElementById('aggregate-port-history-chart');
    const loadingElement = document.getElementById('aggregate-chart-loading');
    const timeRangeSelect = document.getElementById('time-range-select');
    
    if (!chartCanvas || !loadingElement) {
        console.error('Aggregate chart elements not found');
        return;
    }
    
    // Function to load chart data
    function loadAggregateChart() {
        const days = timeRangeSelect.value;
        const enabledTargets = getEnabledTargetIds();
        
        if (enabledTargets.length === 0) {
            loadingElement.innerHTML = '<p class="text-muted text-center">No targets selected. Please select targets to view aggregate data.</p>';
            return;
        }
        
        loadingElement.style.display = 'block';
        loadingElement.innerHTML = `
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading chart...</span>
            </div>
            <p class="text-muted mt-2">Loading aggregate port history data...</p>
        `;
        
        fetch(`/api/aggregate_port_history?days=${days}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    throw new Error(data.error);
                }
                
                if (!data.port_list || data.port_list.length === 0) {
                    loadingElement.innerHTML = '<p class="text-muted text-center">No port history data available for selected targets.</p>';
                    return;
                }
                
                createAggregatePortHistoryChart(data, chartCanvas);
                createAggregatePortToggles(data.port_list, data.ports);
                loadingElement.style.display = 'none';
            })
            .catch(error => {
                console.error('Error loading aggregate port history:', error);
                loadingElement.innerHTML = '<div class="alert alert-danger">Error loading aggregate port history data.</div>';
            });
    }
    
    // Load initial chart
    loadAggregateChart();
    
    // Reload chart when time range changes
    if (timeRangeSelect) {
        timeRangeSelect.addEventListener('change', loadAggregateChart);
    }
    
    // Store reload function globally for checkbox changes
    window.reloadAggregateChart = loadAggregateChart;
}

/**
 * Create the aggregate port history chart
 */
function createAggregatePortHistoryChart(data, canvas) {
    const ctx = canvas.getContext('2d');
    
    // Destroy existing chart if it exists
    if (window.aggregatePortHistoryChart) {
        window.aggregatePortHistoryChart.destroy();
    }
    
    // Prepare datasets for each port
    const datasets = data.port_list.map((port, index) => {
        const color = TABLEAU_20_COLORS[index % TABLEAU_20_COLORS.length];
        const portData = data.ports[port];
        
        return {
            label: `Port ${port}`,
            data: portData.data,
            borderColor: color,
            backgroundColor: color + '20',
            borderWidth: 2,
            pointBackgroundColor: color,
            pointBorderColor: color,
            pointRadius: 4,
            pointHoverRadius: 6,
            tension: 0,
            stepped: false,
            fill: false
        };
    });
    
    // Prepare labels from timeline
    const labels = data.timeline.map(point => {
        const date = new Date(point.date + 'T00:00:00');
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: '2-digit'
        });
    });
    
    // Create warning symbol annotations for no-data days
    const annotations = {};
    data.timeline.forEach((point, index) => {
        if (point.no_data) {
            annotations[`warning-${index}`] = {
                type: 'point',
                xValue: index,
                yValue: 0,
                backgroundColor: '#ffc107',
                borderColor: '#ffc107',
                borderWidth: 2,
                radius: 8,
                display: true,
                label: {
                    enabled: true,
                    content: '⚠️',
                    position: 'center'
                }
            };
        }
    });
    
    // Create chart
    window.aggregatePortHistoryChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Date'
                    },
                    ticks: {
                        maxTicksLimit: 10
                    }
                },
                y: {
                    min: 0,
                    max: 2,
                    ticks: {
                        stepSize: 1,
                        callback: function(value) {
                            if (value === 0) return 'Closed';
                            if (value === 1) return 'Open';
                            return '';
                        }
                    },
                    title: {
                        display: true,
                        text: 'Port Status'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            const pointIndex = context[0].dataIndex;
                            const timelinePoint = data.timeline[pointIndex];
                            
                            if (timelinePoint.no_data) {
                                return 'No scan data available for this date';
                            }
                            
                            const date = new Date(timelinePoint.date + 'T00:00:00');
                            return 'Date: ' + date.toLocaleDateString('en-US', {
                                month: 'short',
                                day: '2-digit',
                                year: 'numeric'
                            });
                        },
                        label: function(context) {
                            const pointIndex = context.dataIndex;
                            const timelinePoint = data.timeline[pointIndex];
                            
                            if (timelinePoint.no_data) {
                                return 'No scan data available for this date';
                            }
                            
                            const port = context.dataset.label.replace('Port ', '');
                            const portInfo = timelinePoint.ports[port];
                            const status = portInfo.status === 1 ? 'Open' : 'Closed';
                            
                            let tooltip = `${context.dataset.label}: ${status}`;
                            
                            if (portInfo.status === 1 && portInfo.ips.length > 0) {
                                tooltip += `\nIPs: ${portInfo.ips.join(', ')}`;
                            }
                            
                            return tooltip.split('\n');
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create aggregate port toggle chips
 */
function createAggregatePortToggles(portList, portsData) {
    const toggleContainer = document.getElementById('aggregate-port-toggle-list');
    if (!toggleContainer) return;
    
    toggleContainer.innerHTML = '';
    
    portList.forEach((port, index) => {
        const color = TABLEAU_20_COLORS[index % TABLEAU_20_COLORS.length];
        
        const chip = document.createElement('div');
        chip.className = 'port-toggle-chip';
        chip.style.cssText = `
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            margin: 2px;
            background-color: ${color};
            color: white;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            user-select: none;
            transition: opacity 0.2s ease;
        `;
        
        const colorIndicator = document.createElement('span');
        colorIndicator.style.cssText = `
            width: 8px;
            height: 8px;
            background-color: white;
            border-radius: 50%;
            margin-right: 6px;
        `;
        
        const label = document.createElement('span');
        label.textContent = `Port ${port}`;
        
        chip.appendChild(colorIndicator);
        chip.appendChild(label);
        
        // Add click handler to toggle port visibility
        chip.addEventListener('click', function() {
            toggleAggregatePortVisibility(index, chip);
        });
        
        // Store initial state
        chip.dataset.visible = 'true';
        chip.dataset.datasetIndex = index;
        
        toggleContainer.appendChild(chip);
    });
}

/**
 * Toggle aggregate port visibility on chart
 */
function toggleAggregatePortVisibility(datasetIndex, chipElement) {
    if (!window.aggregatePortHistoryChart) return;
    
    const chart = window.aggregatePortHistoryChart;
    const isVisible = chipElement.dataset.visible === 'true';
    
    // Toggle dataset visibility
    chart.data.datasets[datasetIndex].hidden = isVisible;
    chart.update();
    
    // Update chip appearance
    if (isVisible) {
        chipElement.style.opacity = '0.4';
        chipElement.dataset.visible = 'false';
    } else {
        chipElement.style.opacity = '1';
        chipElement.dataset.visible = 'true';
    }
}

/**
 * Initialize target checkboxes
 */
function initializeTargetCheckboxes() {
    const selectAllCheckbox = document.getElementById('select-all-targets');
    const targetCheckboxes = document.querySelectorAll('.target-checkbox');
    
    // Load saved checkbox states from localStorage
    loadCheckboxStates();
    
    // Select all checkbox handler
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function() {
            const isChecked = this.checked;
            targetCheckboxes.forEach(checkbox => {
                checkbox.checked = isChecked;
                saveCheckboxState(checkbox);
            });
            
            // Reload aggregate chart
            if (window.reloadAggregateChart) {
                window.reloadAggregateChart();
            }
        });
    }
    
    // Individual checkbox handlers
    targetCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            saveCheckboxState(this);
            
            // Update select all checkbox state
            const allChecked = Array.from(targetCheckboxes).every(cb => cb.checked);
            const noneChecked = Array.from(targetCheckboxes).every(cb => !cb.checked);
            
            if (selectAllCheckbox) {
                selectAllCheckbox.checked = allChecked;
                selectAllCheckbox.indeterminate = !allChecked && !noneChecked;
            }
            
            // Reload aggregate chart
            if (window.reloadAggregateChart) {
                window.reloadAggregateChart();
            }
        });
    });
}

/**
 * Save checkbox state to localStorage
 */
function saveCheckboxState(checkbox) {
    const targetId = checkbox.dataset.targetId;
    const isChecked = checkbox.checked;
    localStorage.setItem(`target-${targetId}`, isChecked.toString());
}

/**
 * Load checkbox states from localStorage
 */
function loadCheckboxStates() {
    const targetCheckboxes = document.querySelectorAll('.target-checkbox');
    let anyUnchecked = false;
    
    targetCheckboxes.forEach(checkbox => {
        const targetId = checkbox.dataset.targetId;
        const savedState = localStorage.getItem(`target-${targetId}`);
        
        if (savedState !== null) {
            checkbox.checked = savedState === 'true';
        } else {
            checkbox.checked = true; // Default to checked
        }
        
        if (!checkbox.checked) {
            anyUnchecked = true;
        }
    });
    
    // Update select all checkbox
    const selectAllCheckbox = document.getElementById('select-all-targets');
    if (selectAllCheckbox) {
        const allChecked = Array.from(targetCheckboxes).every(cb => cb.checked);
        selectAllCheckbox.checked = allChecked;
        selectAllCheckbox.indeterminate = anyUnchecked && !allChecked;
    }
}

/**
 * Get enabled target IDs
 */
function getEnabledTargetIds() {
    const targetCheckboxes = document.querySelectorAll('.target-checkbox:checked');
    return Array.from(targetCheckboxes).map(cb => cb.dataset.targetId);
}

// Export functions for global access
window.NetworkMonitor = {
    showNotification,
    copyToClipboard,
    exportScanData,
    confirmAction,
    validateIpAddress,
    refreshRecentScans,
    initializePortHistoryChart,
    initializeAggregatePortHistoryChart
};
