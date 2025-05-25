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
from data_manager import ScanDataManager

logger = logging.getLogger(__name__)

class ScanScheduler:
    """Manages automated scanning schedule for multiple targets"""
    
    def __init__(self, scanner: NetworkScanner, data_manager: ScanDataManager):
        """
        Initialize the scheduler
        
        Args:
            scanner: NetworkScanner instance
            data_manager: ScanDataManager instance
        """
        self.scanner = scanner
        self.data_manager = data_manager
        self.targets = {}  # Dict to store target IP addresses and their schedule info
        self.running = False
        self.check_interval = 300  # Check every 5 minutes for due scans
        self.schedule_file = 'scan_data/schedule.json'
        
        # Load existing scheduled targets
        self._load_schedule()
    
    def add_target(self, ip_address: str) -> bool:
        """
        Add an IP address to the automated scanning schedule
        
        Args:
            ip_address: IP address to monitor
            
        Returns:
            True if successfully added, False otherwise
        """
        try:
            current_time = datetime.now()
            
            self.targets[ip_address] = {
                'ip': ip_address,
                'added_at': current_time.isoformat(),
                'last_scan': None,
                'next_scan': current_time.isoformat(),  # Scan immediately when added
                'scan_interval_hours': 24,
                'active': True,
                'consecutive_failures': 0
            }
            
            self._save_schedule()
            logger.info(f"Added {ip_address} to scanning schedule")
            return True
            
        except Exception as e:
            logger.error(f"Error adding target {ip_address} to schedule: {e}")
            return False
    
    def remove_target(self, ip_address: str) -> bool:
        """
        Remove an IP address from the automated scanning schedule
        
        Args:
            ip_address: IP address to remove
            
        Returns:
            True if successfully removed, False otherwise
        """
        try:
            if ip_address in self.targets:
                del self.targets[ip_address]
                self._save_schedule()
                logger.info(f"Removed {ip_address} from scanning schedule")
                return True
            else:
                logger.warning(f"Target {ip_address} not found in schedule")
                return False
                
        except Exception as e:
            logger.error(f"Error removing target {ip_address} from schedule: {e}")
            return False
    
    def get_scheduled_targets(self) -> List[Dict[str, Any]]:
        """Get list of all scheduled targets"""
        return list(self.targets.values())
    
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
        current_time = datetime.now()
        
        for ip_address, target_info in self.targets.items():
            if not target_info.get('active', True):
                continue
            
            try:
                next_scan_time = datetime.fromisoformat(target_info['next_scan'])
                
                if current_time >= next_scan_time:
                    logger.info(f"Executing scheduled scan for {ip_address}")
                    self._execute_scheduled_scan(ip_address, target_info)
                    
            except Exception as e:
                logger.error(f"Error checking scan schedule for {ip_address}: {e}")
    
    def _execute_scheduled_scan(self, ip_address: str, target_info: Dict[str, Any]):
        """Execute a scheduled scan for a target"""
        try:
            scan_start_time = datetime.now()
            
            # Perform the scan
            scan_result = self.scanner.scan_host(ip_address)
            
            if scan_result['success']:
                # Store the scan result
                self.data_manager.store_scan_result(ip_address, scan_result)
                
                # Check for port changes and send notifications
                changes = self.data_manager.check_port_changes(ip_address)
                if changes['new_ports'] or changes['closed_ports']:
                    self._send_notification(ip_address, changes, scan_result)
                
                # Update target info for successful scan
                target_info['last_scan'] = scan_start_time.isoformat()
                target_info['consecutive_failures'] = 0
                
                logger.info(f"Scheduled scan completed successfully for {ip_address}")
                
            else:
                # Handle scan failure
                target_info['consecutive_failures'] += 1
                logger.warning(f"Scheduled scan failed for {ip_address}: {scan_result.get('error', 'Unknown error')}")
                
                # Disable target after too many consecutive failures
                if target_info['consecutive_failures'] >= 5:
                    target_info['active'] = False
                    logger.error(f"Disabling {ip_address} after 5 consecutive scan failures")
            
            # Schedule next scan
            next_scan_time = scan_start_time + timedelta(hours=target_info['scan_interval_hours'])
            target_info['next_scan'] = next_scan_time.isoformat()
            
            # Save updated schedule
            self._save_schedule()
            
        except Exception as e:
            logger.error(f"Error executing scheduled scan for {ip_address}: {e}")
    
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
    
    def _load_schedule(self):
        """Load scheduled targets from file"""
        try:
            if os.path.exists(self.schedule_file):
                with open(self.schedule_file, 'r') as f:
                    self.targets = json.load(f)
                logger.info(f"Loaded {len(self.targets)} scheduled targets")
            else:
                self.targets = {}
                logger.info("No existing schedule found, starting with empty schedule")
                
        except Exception as e:
            logger.error(f"Error loading schedule: {e}")
            self.targets = {}
    
    def _save_schedule(self):
        """Save scheduled targets to file"""
        try:
            os.makedirs(os.path.dirname(self.schedule_file), exist_ok=True)
            with open(self.schedule_file, 'w') as f:
                json.dump(self.targets, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving schedule: {e}")
    
    def get_target_info(self, ip_address: str) -> Dict[str, Any]:
        """Get scheduling information for a specific target"""
        return self.targets.get(ip_address, {})
    
    def update_scan_interval(self, ip_address: str, hours: int) -> bool:
        """
        Update scan interval for a target
        
        Args:
            ip_address: Target IP address
            hours: New scan interval in hours
            
        Returns:
            True if successfully updated, False otherwise
        """
        try:
            if ip_address in self.targets:
                self.targets[ip_address]['scan_interval_hours'] = hours
                
                # Recalculate next scan time
                if self.targets[ip_address]['last_scan']:
                    last_scan = datetime.fromisoformat(self.targets[ip_address]['last_scan'])
                    next_scan = last_scan + timedelta(hours=hours)
                    self.targets[ip_address]['next_scan'] = next_scan.isoformat()
                
                self._save_schedule()
                logger.info(f"Updated scan interval for {ip_address} to {hours} hours")
                return True
            else:
                logger.warning(f"Target {ip_address} not found in schedule")
                return False
                
        except Exception as e:
            logger.error(f"Error updating scan interval for {ip_address}: {e}")
            return False
