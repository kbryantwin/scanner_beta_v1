"""
User Scan Management Module
Handles user-specific scan targets and monitoring
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import psycopg2
import os

logger = logging.getLogger(__name__)

class UserScanManager:
    """Manages user-specific scan targets and results"""
    
    def __init__(self):
        """Initialize user scan manager"""
        self.conn = None
        self.connect()
    
    def connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
            logger.info("User scan manager connected to database")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def ensure_connection(self):
        """Ensure database connection is active, reconnect if needed"""
        try:
            if self.conn is None or self.conn.closed:
                self.connect()
            else:
                # Test the connection
                cursor = self.conn.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
        except:
            # Connection is bad, reconnect
            try:
                if self.conn:
                    self.conn.close()
            except:
                pass
            self.connect()
    
    def add_scan_target(self, user_id: int, ip_address: str, description: str = "", 
                       scan_interval_minutes: int = 720) -> bool:
        """Add a new scan target for user"""
        try:
            # Ensure database connection
            self.ensure_connection()
            
            # Validate scan interval (minimum 30 minutes)
            if scan_interval_minutes < 30:
                scan_interval_minutes = 30
            
            # Calculate next scan time
            next_scan_at = datetime.now() + timedelta(minutes=scan_interval_minutes)
            
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO user_scan_targets 
                (user_id, ip_address, description, scan_interval_minutes, next_scan_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, ip_address, description, scan_interval_minutes, next_scan_at))
            
            self.conn.commit()
            logger.info(f"Scan target added for user {user_id}: {ip_address}")
            return True
            
        except psycopg2.IntegrityError:
            logger.warning(f"Scan target already exists for user {user_id}: {ip_address}")
            self.conn.rollback()
            return False
        except Exception as e:
            logger.error(f"Failed to add scan target: {e}")
            self.conn.rollback()
            return False
    
    def get_user_targets(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all scan targets for a user"""
        try:
            # Ensure database connection
            self.ensure_connection()
            
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, ip_address, description, scan_interval_minutes, 
                       is_active, is_paused, last_scan_at, next_scan_at, created_at
                FROM user_scan_targets
                WHERE user_id = %s
                ORDER BY created_at DESC
            """, (user_id,))
            
            targets = []
            for row in cursor.fetchall():
                targets.append({
                    'id': row[0],
                    'ip_address': str(row[1]),
                    'description': row[2],
                    'scan_interval_minutes': row[3],
                    'is_active': row[4],
                    'is_paused': row[5],
                    'last_scan_at': row[6],
                    'next_scan_at': row[7],
                    'created_at': row[8]
                })
            
            return targets
            
        except Exception as e:
            logger.error(f"Failed to get user targets: {e}")
            return []
    
    def update_scan_interval(self, user_id: int, target_id: int, 
                           scan_interval_minutes: int) -> bool:
        """Update scan interval for a target"""
        try:
            # Validate scan interval (minimum 30 minutes)
            if scan_interval_minutes < 30:
                scan_interval_minutes = 30
            
            # Calculate next scan time based on new interval
            next_scan_at = datetime.now() + timedelta(minutes=scan_interval_minutes)
            
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE user_scan_targets 
                SET scan_interval_minutes = %s, next_scan_at = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND user_id = %s
            """, (scan_interval_minutes, next_scan_at, target_id, user_id))
            
            if cursor.rowcount > 0:
                self.conn.commit()
                logger.info(f"Scan interval updated for target {target_id}: {scan_interval_minutes} minutes")
                return True
            else:
                logger.warning(f"Target {target_id} not found for user {user_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to update scan interval: {e}")
            self.conn.rollback()
            return False
    
    def pause_target(self, user_id: int, target_id: int) -> bool:
        """Pause scanning for a target"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE user_scan_targets 
                SET is_paused = TRUE, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND user_id = %s
            """, (target_id, user_id))
            
            if cursor.rowcount > 0:
                self.conn.commit()
                logger.info(f"Target {target_id} paused for user {user_id}")
                return True
            else:
                logger.warning(f"Target {target_id} not found for user {user_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to pause target: {e}")
            self.conn.rollback()
            return False
    
    def resume_target(self, user_id: int, target_id: int) -> bool:
        """Resume scanning for a target"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE user_scan_targets 
                SET is_paused = FALSE, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND user_id = %s
            """, (target_id, user_id))
            
            if cursor.rowcount > 0:
                self.conn.commit()
                logger.info(f"Target {target_id} resumed for user {user_id}")
                return True
            else:
                logger.warning(f"Target {target_id} not found for user {user_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to resume target: {e}")
            self.conn.rollback()
            return False
    
    def delete_target(self, user_id: int, target_id: int) -> bool:
        """Delete a scan target"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                DELETE FROM user_scan_targets 
                WHERE id = %s AND user_id = %s
            """, (target_id, user_id))
            
            if cursor.rowcount > 0:
                self.conn.commit()
                logger.info(f"Target {target_id} deleted for user {user_id}")
                return True
            else:
                logger.warning(f"Target {target_id} not found for user {user_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to delete target: {e}")
            self.conn.rollback()
            return False
    
    def store_scan_result(self, user_id: int, target_id: int, ip_address: str, 
                         scan_result: Dict[str, Any]) -> bool:
        """Store scan result for user"""
        try:
            cursor = self.conn.cursor()
            
            # Store main scan result
            cursor.execute("""
                INSERT INTO user_scan_results 
                (user_id, target_id, ip_address, success, scan_time, error_message, 
                 host_state, open_ports_count, raw_result)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                user_id, target_id, ip_address, scan_result.get('success', False),
                scan_result.get('scan_time'), scan_result.get('error_message'),
                scan_result.get('host_state'), len(scan_result.get('open_ports', [])),
                psycopg2.extras.Json(scan_result)
            ))
            
            scan_result_id = cursor.fetchone()[0]
            
            # Store port results
            for port_info in scan_result.get('open_ports', []):
                cursor.execute("""
                    INSERT INTO user_port_results 
                    (scan_result_id, port, protocol, state, service, version, product)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    scan_result_id, port_info.get('port'), port_info.get('protocol', 'tcp'),
                    port_info.get('state'), port_info.get('service'), 
                    port_info.get('version'), port_info.get('product')
                ))
            
            # Update last scan time for target
            cursor.execute("""
                UPDATE user_scan_targets 
                SET last_scan_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (target_id,))
            
            self.conn.commit()
            logger.info(f"Scan result stored for user {user_id}, target {target_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store scan result: {e}")
            self.conn.rollback()
            return False
    
    def get_targets_due_for_scan(self) -> List[Dict[str, Any]]:
        """Get all targets that are due for scanning"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, user_id, ip_address, scan_interval_minutes, next_scan_at
                FROM user_scan_targets
                WHERE is_active = TRUE AND is_paused = FALSE 
                AND next_scan_at <= CURRENT_TIMESTAMP
                ORDER BY next_scan_at
            """)
            
            targets = []
            for row in cursor.fetchall():
                targets.append({
                    'id': row[0],
                    'user_id': row[1],
                    'ip_address': str(row[2]),
                    'scan_interval_minutes': row[3],
                    'next_scan_at': row[4]
                })
            
            return targets
            
        except Exception as e:
            logger.error(f"Failed to get targets due for scan: {e}")
            return []
    
    def update_next_scan_time(self, target_id: int) -> bool:
        """Update next scan time for a target"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE user_scan_targets 
                SET next_scan_at = CURRENT_TIMESTAMP + INTERVAL '1 minute' * scan_interval_minutes
                WHERE id = %s
            """, (target_id,))
            
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to update next scan time: {e}")
            self.conn.rollback()
            return False
    
    def get_user_scan_history(self, user_id: int, ip_address: str = None, 
                             limit: int = 50) -> List[Dict[str, Any]]:
        """Get scan history for user"""
        try:
            # Ensure database connection
            self.ensure_connection()
            
            cursor = self.conn.cursor()
            
            if ip_address:
                cursor.execute("""
                    SELECT usr.id, usr.ip_address, usr.timestamp, usr.success,
                           usr.scan_time, usr.host_state, usr.open_ports_count,
                           ust.description
                    FROM user_scan_results usr
                    JOIN user_scan_targets ust ON usr.target_id = ust.id
                    WHERE usr.user_id = %s AND usr.ip_address = %s
                    ORDER BY usr.timestamp DESC
                    LIMIT %s
                """, (user_id, ip_address, limit))
            else:
                cursor.execute("""
                    SELECT usr.id, usr.ip_address, usr.timestamp, usr.success,
                           usr.scan_time, usr.host_state, usr.open_ports_count,
                           ust.description
                    FROM user_scan_results usr
                    JOIN user_scan_targets ust ON usr.target_id = ust.id
                    WHERE usr.user_id = %s
                    ORDER BY usr.timestamp DESC
                    LIMIT %s
                """, (user_id, limit))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'id': row[0],
                    'ip_address': str(row[1]),
                    'timestamp': row[2],
                    'success': row[3],
                    'scan_time': row[4],
                    'host_state': row[5],
                    'open_ports_count': row[6],
                    'description': row[7]
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    def get_port_changes_for_user(self, user_id: int, hours: int = 24) -> List[Dict[str, Any]]:
        """Get port changes for user within specified hours"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                WITH recent_scans AS (
                    SELECT DISTINCT ON (usr.ip_address) 
                           usr.ip_address, usr.id as latest_scan_id, usr.timestamp
                    FROM user_scan_results usr
                    WHERE usr.user_id = %s 
                    AND usr.timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s hours'
                    AND usr.success = TRUE
                    ORDER BY usr.ip_address, usr.timestamp DESC
                ),
                previous_scans AS (
                    SELECT DISTINCT ON (usr.ip_address) 
                           usr.ip_address, usr.id as previous_scan_id
                    FROM user_scan_results usr
                    WHERE usr.user_id = %s 
                    AND usr.timestamp < (CURRENT_TIMESTAMP - INTERVAL '%s hours')
                    AND usr.success = TRUE
                    ORDER BY usr.ip_address, usr.timestamp DESC
                )
                SELECT rs.ip_address, rs.latest_scan_id, ps.previous_scan_id,
                       array_agg(DISTINCT upr_latest.port) as latest_ports,
                       array_agg(DISTINCT upr_previous.port) as previous_ports
                FROM recent_scans rs
                LEFT JOIN previous_scans ps ON rs.ip_address = ps.ip_address
                LEFT JOIN user_port_results upr_latest ON rs.latest_scan_id = upr_latest.scan_result_id
                LEFT JOIN user_port_results upr_previous ON ps.previous_scan_id = upr_previous.scan_result_id
                GROUP BY rs.ip_address, rs.latest_scan_id, ps.previous_scan_id
            """, (user_id, hours, user_id, hours))
            
            changes = []
            for row in cursor.fetchall():
                ip_address = str(row[0])
                latest_ports = set(row[3] or [])
                previous_ports = set(row[4] or [])
                
                new_ports = latest_ports - previous_ports
                closed_ports = previous_ports - latest_ports
                
                if new_ports or closed_ports:
                    changes.append({
                        'ip_address': ip_address,
                        'new_ports': list(new_ports),
                        'closed_ports': list(closed_ports),
                        'latest_ports': list(latest_ports)
                    })
            
            return changes
            
        except Exception as e:
            logger.error(f"Failed to get port changes: {e}")
            return []
    
    def get_aggregate_port_history(self, user_id: int, days: int = 7) -> Dict[str, Any]:
        """Get aggregate port history for all user targets"""
        try:
            # Ensure database connection
            self.ensure_connection()
            
            cursor = self.conn.cursor()
            
            # Get enabled target IDs from request (simulated from localStorage)
            # For now, get all active targets
            cursor.execute("""
                SELECT id, ip_address FROM user_scan_targets
                WHERE user_id = %s AND is_active = TRUE
            """, (user_id,))
            
            targets = cursor.fetchall()
            target_ids = [t[0] for t in targets]
            target_ips = {t[0]: str(t[1]) for t in targets}
            
            if not target_ids:
                return {
                    'ports': {},
                    'timeline': [],
                    'port_list': [],
                    'target_ips': {}
                }
            
            # Get scan results for the date range
            cursor.execute("""
                SELECT usr.target_id, usr.ip_address, 
                       DATE(usr.timestamp) as scan_date,
                       usr.timestamp, usr.success,
                       array_agg(upr.port) as ports
                FROM user_scan_results usr
                LEFT JOIN user_port_results upr ON usr.id = upr.scan_result_id
                WHERE usr.user_id = %s 
                AND usr.target_id = ANY(%s)
                AND usr.timestamp >= CURRENT_DATE - INTERVAL '%s days'
                AND usr.success = TRUE
                GROUP BY usr.target_id, usr.ip_address, DATE(usr.timestamp), usr.timestamp, usr.success
                ORDER BY scan_date, usr.timestamp
            """, (user_id, target_ids, days))
            
            scan_results = cursor.fetchall()
            
            if not scan_results:
                return {
                    'ports': {},
                    'timeline': [],
                    'port_list': [],
                    'target_ips': target_ips
                }
            
            # Process data by date (ignore time)
            daily_data = {}
            all_ports = set()
            
            for row in scan_results:
                target_id, ip_address, scan_date, timestamp, success, ports = row
                ports = [p for p in (ports or []) if p is not None]
                
                date_str = scan_date.strftime('%Y-%m-%d')
                
                if date_str not in daily_data:
                    daily_data[date_str] = {}
                
                # Aggregate ports by date (if any scan shows port open that day, mark as open)
                for port in ports:
                    all_ports.add(port)
                    if port not in daily_data[date_str]:
                        daily_data[date_str][port] = set()
                    daily_data[date_str][port].add(str(ip_address))
            
            # Sort ports and dates
            sorted_ports = sorted(list(all_ports))
            sorted_dates = sorted(daily_data.keys())
            
            # Create timeline data
            timeline = []
            port_data = {}
            
            # Initialize port data
            for port in sorted_ports:
                port_data[port] = {
                    'first_seen': None,
                    'last_seen': None,
                    'data': []
                }
            
            # Generate complete date range
            from datetime import datetime, timedelta, date
            start_date = date.today() - timedelta(days=days-1)
            complete_dates = []
            
            for i in range(days):
                current_date = start_date + timedelta(days=i)
                complete_dates.append(current_date.strftime('%Y-%m-%d'))
            
            # Process each date
            for date_str in complete_dates:
                has_any_data = date_str in daily_data
                
                # Check if this date has no scan data for any target
                if not has_any_data:
                    timeline.append({
                        'date': date_str,
                        'timestamp': date_str,
                        'no_data': True,
                        'ports': {}
                    })
                    
                    # Add zero data points for chart
                    for port in sorted_ports:
                        port_data[port]['data'].append({
                            'x': date_str,
                            'y': 0
                        })
                    continue
                
                day_ports = daily_data[date_str]
                timeline_point = {
                    'date': date_str,
                    'timestamp': date_str,
                    'no_data': False,
                    'ports': {}
                }
                
                # For each port, check if it was open on this date
                for port in sorted_ports:
                    if port in day_ports:
                        timeline_point['ports'][port] = {
                            'status': 1,
                            'ips': list(day_ports[port])
                        }
                        port_data[port]['data'].append({
                            'x': date_str,
                            'y': 1
                        })
                        
                        # Update first/last seen
                        if port_data[port]['first_seen'] is None:
                            port_data[port]['first_seen'] = date_str
                        port_data[port]['last_seen'] = date_str
                    else:
                        timeline_point['ports'][port] = {
                            'status': 0,
                            'ips': []
                        }
                        port_data[port]['data'].append({
                            'x': date_str,
                            'y': 0
                        })
                
                timeline.append(timeline_point)
            
            return {
                'ports': port_data,
                'timeline': timeline,
                'port_list': sorted_ports,
                'target_ips': target_ips
            }
            
        except Exception as e:
            logger.error(f"Failed to get aggregate port history: {e}")
            return {
                'ports': {},
                'timeline': [],
                'port_list': [],
                'target_ips': {}
            }
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()