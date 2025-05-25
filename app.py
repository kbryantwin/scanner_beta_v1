#!/usr/bin/env python3
"""
Network Monitoring Tool - Main Flask Application
Provides web interface for nmap scanning and port monitoring
"""

import os
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from scanner import NetworkScanner
from data_manager import ScanDataManager
from scheduler import ScanScheduler
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize components
scanner = NetworkScanner()
data_manager = ScanDataManager()
scheduler = ScanScheduler(scanner, data_manager)

# Global variable to track active scans
active_scans = {}

@app.route('/')
def index():
    """Main dashboard page"""
    try:
        # Get recent scan summaries
        recent_scans = data_manager.get_recent_scans(limit=10)
        active_targets = data_manager.get_active_targets()
        
        return render_template('index.html', 
                             recent_scans=recent_scans,
                             active_targets=active_targets)
    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        flash(f"Error loading dashboard: {str(e)}", 'error')
        return render_template('index.html', recent_scans=[], active_targets=[])

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new scan for the specified IP address"""
    try:
        ip_address = request.form.get('ip_address', '').strip()
        
        if not ip_address:
            flash('Please provide an IP address', 'error')
            return redirect(url_for('index'))
        
        # Validate IP address format (basic validation)
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, ip_address):
            flash('Please provide a valid IP address format', 'error')
            return redirect(url_for('index'))
        
        # Check if scan is already running for this IP
        if ip_address in active_scans:
            flash(f'Scan already in progress for {ip_address}', 'warning')
            return redirect(url_for('index'))
        
        # Start scan in background thread
        scan_thread = threading.Thread(
            target=perform_scan_async,
            args=(ip_address,)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        active_scans[ip_address] = {
            'start_time': datetime.now(),
            'status': 'running'
        }
        
        flash(f'Scan started for {ip_address}', 'success')
        return redirect(url_for('results', ip=ip_address))
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        flash(f"Error starting scan: {str(e)}", 'error')
        return redirect(url_for('index'))

def perform_scan_async(ip_address):
    """Perform scan in background thread"""
    try:
        logger.info(f"Starting scan for {ip_address}")
        
        # Perform the scan
        scan_result = scanner.scan_host(ip_address)
        
        if scan_result['success']:
            # Store the scan result
            data_manager.store_scan_result(ip_address, scan_result)
            
            # Check for port changes
            changes = data_manager.check_port_changes(ip_address)
            if changes['new_ports']:
                logger.info(f"New ports detected for {ip_address}: {changes['new_ports']}")
            
            active_scans[ip_address]['status'] = 'completed'
        else:
            active_scans[ip_address]['status'] = 'failed'
            active_scans[ip_address]['error'] = scan_result.get('error', 'Unknown error')
        
    except Exception as e:
        logger.error(f"Error in async scan for {ip_address}: {e}")
        active_scans[ip_address]['status'] = 'failed'
        active_scans[ip_address]['error'] = str(e)

@app.route('/results/<ip>')
def results(ip):
    """Display scan results for specific IP"""
    try:
        # Get scan history for this IP
        scan_history = data_manager.get_scan_history(ip)
        
        # Get latest scan result
        latest_scan = scan_history[0] if scan_history else None
        
        # Get port changes
        port_changes = data_manager.check_port_changes(ip)
        
        # Check if scan is currently running
        scan_status = active_scans.get(ip, {})
        
        return render_template('results.html',
                             ip_address=ip,
                             latest_scan=latest_scan,
                             scan_history=scan_history,
                             port_changes=port_changes,
                             scan_status=scan_status)
        
    except Exception as e:
        logger.error(f"Error loading results for {ip}: {e}")
        flash(f"Error loading results: {str(e)}", 'error')
        return redirect(url_for('index'))

@app.route('/api/scan_status/<ip>')
def get_scan_status(ip):
    """API endpoint to get current scan status"""
    try:
        status = active_scans.get(ip, {'status': 'not_found'})
        
        # If scan is completed, remove from active scans
        if status.get('status') in ['completed', 'failed']:
            if ip in active_scans:
                del active_scans[ip]
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting scan status for {ip}: {e}")
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/api/latest_scan/<ip>')
def get_latest_scan(ip):
    """API endpoint to get latest scan results"""
    try:
        scan_history = data_manager.get_scan_history(ip, limit=1)
        latest_scan = scan_history[0] if scan_history else None
        
        return jsonify({'scan': latest_scan})
        
    except Exception as e:
        logger.error(f"Error getting latest scan for {ip}: {e}")
        return jsonify({'error': str(e)})

@app.route('/schedule/<ip>')
def schedule_monitoring(ip):
    """Enable 24-hour monitoring for an IP address"""
    try:
        scheduler.add_target(ip)
        flash(f'24-hour monitoring enabled for {ip}', 'success')
        return redirect(url_for('results', ip=ip))
        
    except Exception as e:
        logger.error(f"Error scheduling monitoring for {ip}: {e}")
        flash(f"Error scheduling monitoring: {str(e)}", 'error')
        return redirect(url_for('results', ip=ip))

@app.route('/unschedule/<ip>')
def unschedule_monitoring(ip):
    """Disable 24-hour monitoring for an IP address"""
    try:
        scheduler.remove_target(ip)
        flash(f'24-hour monitoring disabled for {ip}', 'info')
        return redirect(url_for('results', ip=ip))
        
    except Exception as e:
        logger.error(f"Error unscheduling monitoring for {ip}: {e}")
        flash(f"Error unscheduling monitoring: {str(e)}", 'error')
        return redirect(url_for('results', ip=ip))

@app.route('/api/port_changes/<ip>')
def get_port_changes(ip):
    """API endpoint to get port changes for an IP"""
    try:
        changes = data_manager.check_port_changes(ip)
        return jsonify(changes)
        
    except Exception as e:
        logger.error(f"Error getting port changes for {ip}: {e}")
        return jsonify({'error': str(e)})

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return render_template('index.html'), 500

if __name__ == '__main__':
    # Start the scheduler in a background thread
    scheduler_thread = threading.Thread(target=scheduler.start)
    scheduler_thread.daemon = True
    scheduler_thread.start()
    
    logger.info("Starting Network Monitoring Tool on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
