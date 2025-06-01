#!/usr/bin/env python3
"""
Network Monitoring Tool - Main Flask Application
Provides web interface for nmap scanning and port monitoring
"""

import os
import json
import logging
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, session, g
from scanner import NetworkScanner
from scheduler import ScanScheduler
from db_manager import DatabaseManager
from auth import AuthManager
from user_manager import UserScanManager
from email_manager import EmailManager

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

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24)

# Initialize components
scanner = NetworkScanner()
db_manager = DatabaseManager()
auth_manager = AuthManager()
user_scan_manager = UserScanManager()
email_manager = EmailManager()
scheduler = ScanScheduler(scanner, db_manager)

# Global variable to track active scans
active_scans = {}

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for session token
        session_token = session.get('session_token')
        if not session_token:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Validate session
        user = auth_manager.validate_session(session_token)
        if not user:
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
        
        # Store user in g for access in views
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function

# Before request handler to check authentication
@app.before_request
def load_user():
    g.current_user = None
    session_token = session.get('session_token')
    if session_token:
        user = auth_manager.validate_session(session_token)
        if user:
            g.current_user = user

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if g.current_user:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return render_template('login.html')
        
        user = auth_manager.authenticate_user(email, password)
        if user:
            session_token = auth_manager.create_session(user['id'])
            session['session_token'] = session_token
            flash(f'Welcome back, {email}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if g.current_user:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        if auth_manager.register_user(email, password):
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('An account with this email already exists.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """User logout"""
    session_token = session.get('session_token')
    if session_token:
        auth_manager.invalidate_session(session_token)
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/')
def index():
    """Landing page - redirect based on auth status"""
    if g.current_user:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard page"""
    try:
        user_id = g.current_user['id']
        targets = user_scan_manager.get_user_targets(user_id)
        recent_scans = user_scan_manager.get_user_scan_history(user_id, limit=10)
        
        return render_template('dashboard.html', 
                             targets=targets,
                             recent_scans=recent_scans,
                             scanner_info=scanner.get_scanner_info(),
                             user=g.current_user)
    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        flash('Error loading dashboard data.', 'error')
        return render_template('dashboard.html', 
                             targets=[],
                             recent_scans=[],
                             scanner_info={},
                             user=g.current_user)

# User scan management routes
@app.route('/add_target', methods=['POST'])
@login_required
def add_scan_target():
    """Add a new scan target for the user"""
    try:
        ip_address = request.form.get('ip_address', '').strip()
        description = request.form.get('description', '').strip()
        scan_interval_minutes = int(request.form.get('scan_interval_minutes', 720))
        
        if not ip_address:
            flash('Please enter an IP address.', 'error')
            return redirect(url_for('dashboard'))
        
        # Validate scan interval (minimum 30 minutes)
        if scan_interval_minutes < 30:
            scan_interval_minutes = 30
            flash('Scan interval set to minimum of 30 minutes.', 'warning')
        
        user_id = g.current_user['id']
        if user_scan_manager.add_scan_target(user_id, ip_address, description, scan_interval_minutes):
            flash(f'Successfully added {ip_address} to your monitoring targets.', 'success')
        else:
            flash(f'IP address {ip_address} is already being monitored.', 'warning')
        
        return redirect(url_for('dashboard'))
        
    except ValueError:
        flash('Invalid scan interval. Please enter a number.', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Error adding scan target: {e}")
        flash('Error adding scan target.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/update_interval', methods=['POST'])
@login_required
def update_scan_interval():
    """Update scan interval for a target"""
    try:
        target_id = int(request.form.get('target_id'))
        scan_interval_minutes = int(request.form.get('scan_interval_minutes'))
        
        # Validate scan interval (minimum 30 minutes)
        if scan_interval_minutes < 30:
            flash('Scan interval must be at least 30 minutes.', 'error')
            return redirect(url_for('dashboard'))
        
        user_id = g.current_user['id']
        if user_scan_manager.update_scan_interval(user_id, target_id, scan_interval_minutes):
            flash('Scan interval updated successfully.', 'success')
        else:
            flash('Error updating scan interval.', 'error')
        
        return redirect(url_for('dashboard'))
        
    except (ValueError, TypeError):
        flash('Invalid input. Please check your values.', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Error updating scan interval: {e}")
        flash('Error updating scan interval.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/pause_target/<int:target_id>')
@login_required
def pause_target(target_id):
    """Pause scanning for a target"""
    try:
        user_id = g.current_user['id']
        if user_scan_manager.pause_target(user_id, target_id):
            flash('Target scanning paused.', 'success')
        else:
            flash('Error pausing target.', 'error')
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Error pausing target: {e}")
        flash('Error pausing target.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/resume_target/<int:target_id>')
@login_required
def resume_target(target_id):
    """Resume scanning for a target"""
    try:
        user_id = g.current_user['id']
        if user_scan_manager.resume_target(user_id, target_id):
            flash('Target scanning resumed.', 'success')
        else:
            flash('Error resuming target.', 'error')
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Error resuming target: {e}")
        flash('Error resuming target.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete_target/<int:target_id>')
@login_required
def delete_target(target_id):
    """Delete a scan target"""
    try:
        user_id = g.current_user['id']
        if user_scan_manager.delete_target(user_id, target_id):
            flash('Target deleted successfully.', 'success')
        else:
            flash('Error deleting target.', 'error')
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Error deleting target: {e}")
        flash('Error deleting target.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/scan', methods=['POST'])
@login_required
def start_scan():
    """Start a manual scan for a specific target"""
    try:
        ip_address = request.form.get('ip_address', '').strip()
        user_id = g.current_user['id']
        
        if not ip_address:
            flash('Please provide an IP address', 'error')
            return redirect(url_for('dashboard'))
        
        # Validate IP address format (basic validation)
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, ip_address):
            flash('Please provide a valid IP address format', 'error')
            return redirect(url_for('dashboard'))
        
        # Check if this IP is already in user's targets
        user_targets = user_scan_manager.get_user_targets(user_id)
        existing_target = None
        for target in user_targets:
            if target['ip_address'] == ip_address:
                existing_target = target
                break
        
        # If not in targets, automatically add it
        if not existing_target:
            success = user_scan_manager.add_scan_target(
                user_id=user_id,
                ip_address=ip_address,
                description="Autoadded",
                scan_interval_minutes=720
            )
            if success:
                flash(f'Added {ip_address} to your monitoring targets for manual scan', 'success')
                # Get the newly added target
                user_targets = user_scan_manager.get_user_targets(user_id)
                for target in user_targets:
                    if target['ip_address'] == ip_address:
                        existing_target = target
                        break
            else:
                flash(f'Error adding {ip_address} to monitoring targets', 'error')
                return redirect(url_for('dashboard'))
        
        # Check if scan is already running for this IP
        if ip_address in active_scans:
            flash(f'Scan already in progress for {ip_address}', 'warning')
            return redirect(url_for('results', ip=ip_address))
        
        # Start scan in background thread with user context
        scan_thread = threading.Thread(
            target=perform_scan_async,
            args=(ip_address, user_id, existing_target['id'])
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        active_scans[ip_address] = {
            'start_time': datetime.now(),
            'status': 'running',
            'user_id': user_id
        }
        
        flash(f'Scan started for {ip_address}', 'success')
        return redirect(url_for('results', ip=ip_address))
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        flash(f"Error starting scan: {str(e)}", 'error')
        return redirect(url_for('dashboard'))

def perform_scan_async(ip_address, user_id, target_id):
    """Perform scan in background thread"""
    try:
        logger.info(f"Starting scan for {ip_address} for user {user_id}")
        
        # Get user's scan mode preference
        user = auth_manager.get_user_by_id(user_id)
        scan_mode = user.get('scan_mode', 'fast') if user else 'fast'
        
        # Perform the scan with appropriate mode
        scan_result = scanner.scan_host(ip_address, scan_mode=scan_mode)
        
        if scan_result['success']:
            # Store the scan result in user-specific tables
            user_scan_manager.store_scan_result(user_id, target_id, ip_address, scan_result)
            
            logger.info(f"Scan result stored in user database for {ip_address}, user {user_id}")
            active_scans[ip_address]['status'] = 'completed'
        else:
            active_scans[ip_address]['status'] = 'failed'
            active_scans[ip_address]['error'] = scan_result.get('error', 'Unknown error')
        
    except Exception as e:
        logger.error(f"Error in async scan for {ip_address}: {e}")
        active_scans[ip_address]['status'] = 'failed'
        active_scans[ip_address]['error'] = str(e)

@app.route('/results/<ip>')
@login_required
def results(ip):
    """Display scan results for specific IP"""
    try:
        user_id = g.current_user['id']
        
        # Get detailed latest scan result with port information
        latest_scan = user_scan_manager.get_detailed_scan_result(user_id, ip)
        
        # Get scan history for this IP from user-specific database
        scan_history = user_scan_manager.get_user_scan_history(user_id, ip_address=ip)
        
        # Calculate port changes from database history
        port_changes = calculate_port_changes_from_user_db_detailed(user_id, ip)
        
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
        return redirect(url_for('dashboard'))

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

def calculate_port_changes_from_user_db(scan_history):
    """Calculate port changes from user database scan history"""
    try:
        if len(scan_history) < 2:
            return {
                'new_ports': [],
                'closed_ports': [],
                'unchanged_ports': [],
                'has_changes': False,
                'comparison_available': False
            }
        
        latest_scan = scan_history[0]
        previous_scan = scan_history[1]
        
        # For user scan history, we need to get the detailed port data
        # Since user_scan_history returns summary data, we'll need to fetch detailed results
        # For now, return basic comparison data
        return {
            'new_ports': [],
            'closed_ports': [],
            'unchanged_ports': [],
            'has_changes': False,
            'comparison_available': True,
            'latest_scan_time': latest_scan['timestamp'],
            'previous_scan_time': previous_scan['timestamp']
        }
        
    except Exception as e:
        logger.error(f"Error calculating port changes: {e}")
        return {
            'new_ports': [],
            'closed_ports': [],
            'unchanged_ports': [],
            'has_changes': False,
            'comparison_available': False,
            'error': str(e)
        }

def calculate_port_changes_from_user_db_detailed(user_id, ip_address):
    """Calculate port changes using detailed port data from user database"""
    try:
        # Get the last 2 successful scans for this IP
        cursor = user_scan_manager.conn.cursor()
        cursor.execute("""
            SELECT usr.id, usr.timestamp,
                   array_agg(upr.port ORDER BY upr.port) as ports
            FROM user_scan_results usr
            LEFT JOIN user_port_results upr ON usr.id = upr.scan_result_id
            WHERE usr.user_id = %s AND usr.ip_address = %s AND usr.success = TRUE
            GROUP BY usr.id, usr.timestamp
            ORDER BY usr.timestamp DESC
            LIMIT 2
        """, (user_id, ip_address))
        
        results = cursor.fetchall()
        
        if len(results) < 2:
            return {
                'new_ports': [],
                'closed_ports': [],
                'unchanged_ports': [],
                'has_changes': False,
                'comparison_available': False
            }
        
        latest_result = results[0]
        previous_result = results[1]
        
        latest_ports = set(p for p in (latest_result[2] or []) if p is not None)
        previous_ports = set(p for p in (previous_result[2] or []) if p is not None)
        
        new_ports = latest_ports - previous_ports
        closed_ports = previous_ports - latest_ports
        unchanged_ports = latest_ports & previous_ports
        
        return {
            'new_ports': sorted(list(new_ports)),
            'closed_ports': sorted(list(closed_ports)),
            'unchanged_ports': sorted(list(unchanged_ports)),
            'has_changes': bool(new_ports or closed_ports),
            'comparison_available': True,
            'latest_scan_time': latest_result[1],
            'previous_scan_time': previous_result[1]
        }
        
    except Exception as e:
        logger.error(f"Error calculating detailed port changes: {e}")
        return {
            'new_ports': [],
            'closed_ports': [],
            'unchanged_ports': [],
            'has_changes': False,
            'comparison_available': False,
            'error': str(e)
        }

@app.route('/api/latest_scan/<ip>')
@login_required
def get_latest_scan(ip):
    """API endpoint to get latest scan results"""
    try:
        user_id = g.current_user['id']
        scan_history = user_scan_manager.get_user_scan_history(user_id, ip_address=ip, limit=1)
        latest_scan = scan_history[0] if scan_history else None
        
        return jsonify({'scan': latest_scan})
        
    except Exception as e:
        logger.error(f"Error getting latest scan for {ip}: {e}")
        return jsonify({'error': str(e)})

# Legacy monitoring routes removed - all monitoring is now user-specific through targets

@app.route('/api/port_changes/<ip>')
@login_required
def get_port_changes(ip):
    """API endpoint to get port changes for an IP"""
    try:
        user_id = g.current_user['id']
        scan_history = user_scan_manager.get_user_scan_history(user_id, ip_address=ip, limit=2)
        changes = calculate_port_changes_from_user_db(scan_history)
        return jsonify(changes)
        
    except Exception as e:
        logger.error(f"Error getting port changes for {ip}: {e}")
        return jsonify({'error': str(e)})

@app.route('/api/port_history/<ip>')
def get_port_history(ip):
    """API endpoint to get port timeline data for chart"""
    try:
        # Get scan history for this IP from database
        scan_history = db_manager.get_scan_history(ip)
        
        if not scan_history:
            return jsonify({'ports': {}, 'timeline': []})
        
        # Process successful scans only
        successful_scans = [scan for scan in scan_history if scan.get('success')]
        
        if not successful_scans:
            return jsonify({'ports': {}, 'timeline': []})
        
        # Get all unique ports that have been open at least once
        all_ports = set()
        for scan in successful_scans:
            open_ports = set(port['port'] for port in scan.get('open_ports', []))
            all_ports.update(open_ports)
        
        # Sort ports numerically
        sorted_ports = sorted(list(all_ports))
        
        # Create timeline data
        timeline = []
        port_data = {}
        
        # Initialize port data with metadata
        for port in sorted_ports:
            first_seen = None
            last_seen = None
            
            # Find first and last seen times
            for scan in reversed(successful_scans):  # Oldest first
                open_ports = set(port['port'] for port in scan.get('open_ports', []))
                if port in open_ports:
                    if first_seen is None:
                        first_seen = scan['timestamp']
                    last_seen = scan['timestamp']
            
            port_data[port] = {
                'first_seen': first_seen,
                'last_seen': last_seen,
                'data': []
            }
        
        # Process each scan to create timeline points
        for scan in reversed(successful_scans):  # Process oldest to newest
            timestamp = scan['timestamp']
            open_ports = set(port['port'] for port in scan.get('open_ports', []))
            
            timeline_point = {
                'timestamp': timestamp,
                'ports': {}
            }
            
            # For each port, record if it was open (1) or closed (0)
            for port in sorted_ports:
                status = 1 if port in open_ports else 0
                timeline_point['ports'][port] = status
                port_data[port]['data'].append({
                    'x': timestamp,
                    'y': status
                })
            
            timeline.append(timeline_point)
        
        return jsonify({
            'ports': port_data,
            'timeline': timeline,
            'port_list': sorted_ports
        })
        
    except Exception as e:
        logger.error(f"Error getting port history for {ip}: {e}")
        return jsonify({'error': str(e)})

@app.route('/api/aggregate_port_history')
@login_required
def get_aggregate_port_history():
    """API endpoint to get aggregate port timeline data for dashboard"""
    try:
        user_id = g.current_user['id']
        days = int(request.args.get('days', 7))
        
        # Get aggregate port history
        aggregate_data = user_scan_manager.get_aggregate_port_history(user_id, days)
        
        return jsonify(aggregate_data)
        
    except Exception as e:
        logger.error(f"Error getting aggregate port history: {e}")
        return jsonify({'error': str(e)})

@app.route('/api/scan_mode', methods=['POST'])
@login_required
def update_scan_mode():
    """API endpoint to update user's scan mode preference"""
    try:
        data = request.get_json()
        scan_mode = data.get('scan_mode', 'fast').lower()
        
        if scan_mode not in ['fast', 'full']:
            return jsonify({'success': False, 'error': 'Invalid scan mode'})
        
        user_id = g.current_user['id']
        if auth_manager.update_user_settings(user_id, scan_mode=scan_mode):
            return jsonify({'success': True, 'scan_mode': scan_mode})
        else:
            return jsonify({'success': False, 'error': 'Failed to update scan mode'})
            
    except Exception as e:
        logger.error(f"Error updating scan mode: {e}")
        return jsonify({'success': False, 'error': str(e)})

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
    
    logger.info("Starting Network Monitoring Tool with PostgreSQL database on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
