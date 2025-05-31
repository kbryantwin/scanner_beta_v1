#!/usr/bin/env python3
"""
Scan Scheduler Module
Handles automated 24-hour scanning schedule and notifications
"""

import time
import threading
import logging
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any
from scanner import NetworkScanner

logger = logging.getLogger(__name__)

class ScanScheduler:
    """Manages automated scanning schedule for multiple targets"""
    
    def __init__(self, scanner: NetworkScanner, db_manager):
        """
        Initialize the scheduler
        
        Args:
            scanner: NetworkScanner instance
            db_manager: DatabaseManager instance (legacy)
        """
        self.scanner = scanner
        self.db_manager = db_manager  # Keep for backwards compatibility but won't use
        self.running = False
        self.check_interval = 300  # Check every 5 minutes for due scans
        
        # Import user_scan_manager
        from user_manager import UserScanManager
        self.user_scan_manager = UserScanManager()
    
    def get_scheduled_targets(self) -> List[Dict[str, Any]]:
        """Get list of all scheduled targets from user manager"""
        try:
            return self.user_scan_manager.get_targets_due_for_scan()
        except Exception as e:
            logger.error(f"Error getting scheduled targets: {e}")
            return []
    
    def start(self):
        """Start the scheduler main loop"""
        self.running = True
        logger.info("Starting scan scheduler")
        
        while self.running:
            try:
                self._check_and_execute_scans()
                time.sleep(self.check_interval)
                
            except KeyboardInterrupt:
                logger.info("Scheduler interrupted by user")
                break
            except Exception as e:
                logger.error(f"Error in scheduler main loop: {e}")
                time.sleep(self.check_interval)
    
    def stop(self):
        """Stop the scheduler"""
        self.running = False
        logger.info("Stopping scan scheduler")
    
    def _check_and_execute_scans(self):
        """Check for due scans and execute them"""
        try:
            # Get all targets due for scanning from user manager
            due_targets = self.user_scan_manager.get_targets_due_for_scan()
            
            for target in due_targets:
                try:
                    logger.info(f"Executing scheduled scan for {target['ip_address']} (user {target['user_id']})")
                    self._execute_scheduled_scan(target)
                    
                except Exception as e:
                    logger.error(f"Error executing scheduled scan for {target['ip_address']}: {e}")
                    
        except Exception as e:
            logger.error(f"Error checking for due scans: {e}")
    
    def _execute_scheduled_scan(self, target: Dict[str, Any]):
        """Execute a scheduled scan for a target"""
        try:
            ip_address = target['ip_address']
            user_id = target['user_id']
            target_id = target['id']
            
            # Perform the scan
            scan_result = self.scanner.scan_host(ip_address)
            
            if scan_result['success']:
                # Store the scan result in user-specific tables
                self.user_scan_manager.store_scan_result(user_id, target_id, ip_address, scan_result)
                
                logger.info(f"Scheduled scan completed successfully for {ip_address} (user {user_id})")
                
            else:
                logger.warning(f"Scheduled scan failed for {ip_address}: {scan_result.get('error', 'Unknown error')}")
            
            # Update next scan time for this target
            self.user_scan_manager.update_next_scan_time(target_id)
            
        except Exception as e:
            logger.error(f"Error executing scheduled scan for {target['ip_address']}: {e}")
    
    def _send_notification(self, ip_address: str, changes: Dict[str, Any], scan_result: Dict[str, Any]):
        """
        Send notification about port changes
        
        Args:
            ip_address: Target IP address
            changes: Dictionary containing port changes
            scan_result: Latest scan result
        """
        try:
            notification = {
                'timestamp': datetime.now().isoformat(),
                'ip_address': ip_address,
                'type': 'port_change_alert',
                'changes': changes,
                'current_open_ports': [port['port'] for port in scan_result.get('open_ports', [])],
                'scan_timestamp': scan_result.get('timestamp')
            }
            
            # Log the notification
            if changes['new_ports']:
                logger.warning(f"NEW PORTS DETECTED on {ip_address}: {changes['new_ports']}")
            
            if changes['closed_ports']:
                logger.info(f"PORTS CLOSED on {ip_address}: {changes['closed_ports']}")
            
            # Store notification
            self._store_notification(notification)
            
            # Here you could add additional notification methods like:
            # - Email alerts
            # - Webhook calls
            # - Slack/Discord notifications
            # - System notifications
            
        except Exception as e:
            logger.error(f"Error sending notification for {ip_address}: {e}")
    
    def _store_notification(self, notification: Dict[str, Any]):
        """Store notification in the notifications file"""
        try:
            notifications_file = 'scan_data/notifications.json'
            
            # Load existing notifications
            notifications = []
            if os.path.exists(notifications_file):
                with open(notifications_file, 'r') as f:
                    notifications = json.load(f)
            
            # Add new notification
            notifications.append(notification)
            
            # Keep only last 100 notifications
            notifications = notifications[-100:]
            
            # Save notifications
            os.makedirs(os.path.dirname(notifications_file), exist_ok=True)
            with open(notifications_file, 'w') as f:
                json.dump(notifications, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error storing notification: {e}")
    
    def get_recent_notifications(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent notifications"""
        try:
            notifications_file = 'scan_data/notifications.json'
            
            if not os.path.exists(notifications_file):
                return []
            
            with open(notifications_file, 'r') as f:
                notifications = json.load(f)
            
            # Return most recent notifications
            return notifications[-limit:][::-1]  # Reverse to get newest first
            
        except Exception as e:
            logger.error(f"Error loading notifications: {e}")
            return []
    
    # Legacy methods removed - all target management is now handled by UserScanManager
