#!/usr/bin/env python3
"""
Data Manager Module
Handles storage, retrieval, and comparison of scan results
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

class ScanDataManager:
    """Manages scan data storage and retrieval"""
    
    def __init__(self, data_directory: str = 'scan_data'):
        """
        Initialize the data manager
        
        Args:
            data_directory: Directory to store scan data
        """
        self.data_directory = data_directory
        self.ensure_data_directory()
    
    def ensure_data_directory(self):
        """Ensure the data directory exists"""
        try:
            os.makedirs(self.data_directory, exist_ok=True)
            logger.info(f"Data directory ensured: {self.data_directory}")
        except Exception as e:
            logger.error(f"Error creating data directory: {e}")
            raise
    
    def store_scan_result(self, ip_address: str, scan_result: Dict[str, Any]) -> bool:
        """
        Store scan result for an IP address
        
        Args:
            ip_address: IP address that was scanned
            scan_result: Scan result dictionary
            
        Returns:
            True if successfully stored, False otherwise
        """
        try:
            # Create filename based on IP address
            filename = self._get_scan_file_path(ip_address)
            
            # Load existing scan history
            scan_history = self._load_scan_history(filename)
            
            # Add new scan result
            scan_history.append(scan_result)
            
            # Keep only last 30 days of scans (assuming max 1 scan per day)
            cutoff_date = datetime.now() - timedelta(days=30)
            scan_history = [
                scan for scan in scan_history
                if datetime.fromisoformat(scan['timestamp']) > cutoff_date
            ]
            
            # Sort by timestamp (newest first)
            scan_history.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # Save updated history
            with open(filename, 'w') as f:
                json.dump(scan_history, f, indent=2, default=str)
            
            logger.info(f"Stored scan result for {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing scan result for {ip_address}: {e}")
            return False
    
    def get_scan_history(self, ip_address: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get scan history for an IP address
        
        Args:
            ip_address: IP address to get history for
            limit: Maximum number of scans to return
            
        Returns:
            List of scan results, newest first
        """
        try:
            filename = self._get_scan_file_path(ip_address)
            scan_history = self._load_scan_history(filename)
            
            if limit:
                scan_history = scan_history[:limit]
            
            return scan_history
            
        except Exception as e:
            logger.error(f"Error getting scan history for {ip_address}: {e}")
            return []
    
    def get_latest_scan(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get the most recent scan result for an IP address
        
        Args:
            ip_address: IP address to get latest scan for
            
        Returns:
            Latest scan result or None if no scans found
        """
        history = self.get_scan_history(ip_address, limit=1)
        return history[0] if history else None
    
    def check_port_changes(self, ip_address: str) -> Dict[str, Any]:
        """
        Check for port changes between the latest and previous scan
        
        Args:
            ip_address: IP address to check changes for
            
        Returns:
            Dictionary containing port change information
        """
        try:
            scan_history = self.get_scan_history(ip_address, limit=2)
            
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
            
            # Extract port numbers from successful scans
            if not (latest_scan.get('success') and previous_scan.get('success')):
                return {
                    'new_ports': [],
                    'closed_ports': [],
                    'unchanged_ports': [],
                    'has_changes': False,
                    'comparison_available': False,
                    'error': 'One or both scans failed'
                }
            
            latest_ports = set(port['port'] for port in latest_scan.get('open_ports', []))
            previous_ports = set(port['port'] for port in previous_scan.get('open_ports', []))
            
            new_ports = list(latest_ports - previous_ports)
            closed_ports = list(previous_ports - latest_ports)
            unchanged_ports = list(latest_ports & previous_ports)
            
            # Get detailed information for new ports
            new_ports_details = [
                port for port in latest_scan.get('open_ports', [])
                if port['port'] in new_ports
            ]
            
            # Get detailed information for closed ports
            closed_ports_details = [
                port for port in previous_scan.get('open_ports', [])
                if port['port'] in closed_ports
            ]
            
            return {
                'new_ports': sorted(new_ports),
                'closed_ports': sorted(closed_ports),
                'unchanged_ports': sorted(unchanged_ports),
                'new_ports_details': new_ports_details,
                'closed_ports_details': closed_ports_details,
                'has_changes': bool(new_ports or closed_ports),
                'comparison_available': True,
                'latest_scan_time': latest_scan['timestamp'],
                'previous_scan_time': previous_scan['timestamp']
            }
            
        except Exception as e:
            logger.error(f"Error checking port changes for {ip_address}: {e}")
            return {
                'new_ports': [],
                'closed_ports': [],
                'unchanged_ports': [],
                'has_changes': False,
                'comparison_available': False,
                'error': str(e)
            }
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent scans across all IP addresses
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of recent scan summaries
        """
        try:
            recent_scans = []
            
            # Get all scan files
            for filename in os.listdir(self.data_directory):
                if filename.endswith('_scans.json'):
                    ip_address = filename.replace('_scans.json', '').replace('_', '.')
                    
                    latest_scan = self.get_latest_scan(ip_address)
                    if latest_scan:
                        scan_summary = {
                            'ip_address': ip_address,
                            'timestamp': latest_scan['timestamp'],
                            'success': latest_scan['success'],
                            'open_ports_count': len(latest_scan.get('open_ports', [])),
                            'scan_time': latest_scan.get('scan_time', 'unknown')
                        }
                        
                        if not latest_scan['success']:
                            scan_summary['error'] = latest_scan.get('error', 'Unknown error')
                        
                        recent_scans.append(scan_summary)
            
            # Sort by timestamp (newest first)
            recent_scans.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return recent_scans[:limit]
            
        except Exception as e:
            logger.error(f"Error getting recent scans: {e}")
            return []
    
    def get_active_targets(self) -> List[str]:
        """
        Get list of IP addresses that have been scanned
        
        Returns:
            List of IP addresses
        """
        try:
            targets = []
            
            for filename in os.listdir(self.data_directory):
                if filename.endswith('_scans.json'):
                    ip_address = filename.replace('_scans.json', '').replace('_', '.')
                    targets.append(ip_address)
            
            return sorted(targets)
            
        except Exception as e:
            logger.error(f"Error getting active targets: {e}")
            return []
    
    def get_port_statistics(self, ip_address: str, days: int = 7) -> Dict[str, Any]:
        """
        Get port statistics for an IP address over a period
        
        Args:
            ip_address: IP address to analyze
            days: Number of days to analyze
            
        Returns:
            Dictionary containing port statistics
        """
        try:
            scan_history = self.get_scan_history(ip_address)
            
            cutoff_date = datetime.now() - timedelta(days=days)
            recent_scans = [
                scan for scan in scan_history
                if datetime.fromisoformat(scan['timestamp']) > cutoff_date and scan.get('success')
            ]
            
            if not recent_scans:
                return {
                    'port_frequency': {},
                    'always_open': [],
                    'sometimes_open': [],
                    'total_scans': 0,
                    'period_days': days
                }
            
            # Count port occurrences
            port_count = defaultdict(int)
            total_scans = len(recent_scans)
            
            for scan in recent_scans:
                open_ports = set(port['port'] for port in scan.get('open_ports', []))
                for port in open_ports:
                    port_count[port] += 1
            
            # Calculate frequency
            port_frequency = {
                port: {
                    'count': count,
                    'frequency': count / total_scans,
                    'percentage': round((count / total_scans) * 100, 1)
                }
                for port, count in port_count.items()
            }
            
            # Categorize ports
            always_open = [port for port, data in port_frequency.items() if data['frequency'] == 1.0]
            sometimes_open = [port for port, data in port_frequency.items() if data['frequency'] < 1.0]
            
            return {
                'port_frequency': dict(sorted(port_frequency.items())),
                'always_open': sorted(always_open),
                'sometimes_open': sorted(sometimes_open),
                'total_scans': total_scans,
                'period_days': days,
                'analysis_period': {
                    'start': recent_scans[-1]['timestamp'] if recent_scans else None,
                    'end': recent_scans[0]['timestamp'] if recent_scans else None
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting port statistics for {ip_address}: {e}")
            return {
                'port_frequency': {},
                'always_open': [],
                'sometimes_open': [],
                'total_scans': 0,
                'period_days': days,
                'error': str(e)
            }
    
    def delete_scan_data(self, ip_address: str) -> bool:
        """
        Delete all scan data for an IP address
        
        Args:
            ip_address: IP address to delete data for
            
        Returns:
            True if successfully deleted, False otherwise
        """
        try:
            filename = self._get_scan_file_path(ip_address)
            
            if os.path.exists(filename):
                os.remove(filename)
                logger.info(f"Deleted scan data for {ip_address}")
                return True
            else:
                logger.warning(f"No scan data found for {ip_address}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting scan data for {ip_address}: {e}")
            return False
    
    def _get_scan_file_path(self, ip_address: str) -> str:
        """Get file path for storing scan data for an IP address"""
        # Replace dots with underscores for filename
        safe_ip = ip_address.replace('.', '_')
        return os.path.join(self.data_directory, f"{safe_ip}_scans.json")
    
    def _load_scan_history(self, filename: str) -> List[Dict[str, Any]]:
        """Load scan history from file"""
        try:
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    return json.load(f)
            else:
                return []
        except Exception as e:
            logger.error(f"Error loading scan history from {filename}: {e}")
            return []
    
    def export_scan_data(self, ip_address: str, format: str = 'json') -> Optional[str]:
        """
        Export scan data for an IP address
        
        Args:
            ip_address: IP address to export
            format: Export format ('json' or 'csv')
            
        Returns:
            Exported data as string or None if error
        """
        try:
            scan_history = self.get_scan_history(ip_address)
            
            if format.lower() == 'json':
                return json.dumps(scan_history, indent=2, default=str)
            elif format.lower() == 'csv':
                # Simple CSV export
                csv_lines = ['timestamp,success,open_ports_count,scan_time']
                
                for scan in scan_history:
                    csv_lines.append(f"{scan['timestamp']},{scan['success']},{len(scan.get('open_ports', []))},{scan.get('scan_time', '')}")
                
                return '\n'.join(csv_lines)
            else:
                logger.error(f"Unsupported export format: {format}")
                return None
                
        except Exception as e:
            logger.error(f"Error exporting scan data for {ip_address}: {e}")
            return None
