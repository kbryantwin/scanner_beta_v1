#!/usr/bin/env python3
"""
Database Manager for Network Monitoring Tool
Simple database integration using PostgreSQL
"""

import os
import json
import logging
import psycopg2
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages database operations for scan results and monitoring"""
    
    def __init__(self):
        """Initialize database connection"""
        self.connection = None
        self.connect()
        self.create_tables()
    
    def connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.connection = psycopg2.connect(
                host=os.environ.get('PGHOST'),
                database=os.environ.get('PGDATABASE'),
                user=os.environ.get('PGUSER'),
                password=os.environ.get('PGPASSWORD'),
                port=os.environ.get('PGPORT')
            )
            self.connection.autocommit = True
            logger.info("Connected to PostgreSQL database successfully")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            self.connection = None
    
    def create_tables(self):
        """Create necessary database tables"""
        if not self.connection:
            return
        
        try:
            cursor = self.connection.cursor()
            
            # Create scan_results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id SERIAL PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN NOT NULL,
                    scan_time VARCHAR(20),
                    error_message TEXT,
                    host_state VARCHAR(50),
                    open_ports_count INTEGER DEFAULT 0,
                    raw_result JSONB
                )
            """)
            
            # Create port_results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS port_results (
                    id SERIAL PRIMARY KEY,
                    scan_id INTEGER REFERENCES scan_results(id) ON DELETE CASCADE,
                    port INTEGER NOT NULL,
                    protocol VARCHAR(10) DEFAULT 'tcp',
                    state VARCHAR(20) NOT NULL,
                    service VARCHAR(100),
                    version VARCHAR(255),
                    product VARCHAR(255)
                )
            """)
            
            # Create monitoring_targets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS monitoring_targets (
                    id SERIAL PRIMARY KEY,
                    ip_address VARCHAR(45) UNIQUE NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    scan_interval_hours INTEGER DEFAULT 24,
                    next_scan_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_scan_at TIMESTAMP
                )
            """)
            
            cursor.close()
            logger.info("Database tables created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
    
    def store_scan_result(self, ip_address: str, scan_result: Dict[str, Any]) -> bool:
        """Store scan result in database"""
        if not self.connection:
            return False
        
        try:
            cursor = self.connection.cursor()
            
            # Insert scan result
            cursor.execute("""
                INSERT INTO scan_results (ip_address, success, scan_time, error_message, 
                                        host_state, open_ports_count, raw_result)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                ip_address,
                scan_result.get('success', False),
                scan_result.get('scan_time', '0'),
                scan_result.get('error', None),
                scan_result.get('host_info', {}).get('state', 'unknown'),
                len(scan_result.get('open_ports', [])),
                json.dumps(scan_result)
            ))
            
            scan_id = cursor.fetchone()[0]
            
            # Store port results if scan was successful
            if scan_result.get('success') and scan_result.get('open_ports'):
                for port_data in scan_result['open_ports']:
                    cursor.execute("""
                        INSERT INTO port_results (scan_id, port, protocol, state, service, version, product)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        scan_id,
                        port_data.get('port'),
                        port_data.get('protocol', 'tcp'),
                        port_data.get('state', 'open'),
                        port_data.get('service', ''),
                        port_data.get('version', ''),
                        port_data.get('product', '')
                    ))
            
            cursor.close()
            logger.info(f"Stored scan result for {ip_address} in database")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store scan result: {e}")
            return False
    
    def get_scan_history(self, ip_address: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get scan history for an IP address"""
        if not self.connection:
            return []
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT id, timestamp, success, scan_time, error_message, 
                       host_state, open_ports_count, raw_result
                FROM scan_results 
                WHERE ip_address = %s 
                ORDER BY timestamp DESC 
                LIMIT %s
            """, (ip_address, limit))
            
            results = []
            for row in cursor.fetchall():
                # Try to extract host info from raw_result, fallback to basic info
                raw_result = row[7] if row[7] else {}
                host_info = raw_result.get('host_info', {})
                
                # Ensure OS info structure exists
                if 'os' not in host_info:
                    host_info['os'] = {
                        'name': '',
                        'accuracy': 0,
                        'family': '',
                        'generation': '',
                        'type': '',
                        'vendor': ''
                    }
                
                # Ensure basic host info exists
                host_info.update({
                    'state': host_info.get('state', row[5] or 'unknown'),
                    'reason': host_info.get('reason', 'unknown'),
                    'hostname': host_info.get('hostname', ''),
                    'vendor': host_info.get('vendor', {})
                })
                
                result = {
                    'id': row[0],
                    'timestamp': row[1].isoformat(),
                    'success': row[2],
                    'scan_time': row[3],
                    'error': row[4],
                    'host_info': host_info,
                    'open_ports_count': row[6]
                }
                
                # Get port details if available
                if row[2] and row[6] > 0:  # successful scan with open ports
                    result['open_ports'] = self.get_ports_for_scan(row[0])
                else:
                    result['open_ports'] = []
                
                results.append(result)
            
            cursor.close()
            return results
            
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    def get_ports_for_scan(self, scan_id: int) -> List[Dict[str, Any]]:
        """Get port results for a specific scan"""
        if not self.connection:
            return []
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT port, protocol, state, service, version, product
                FROM port_results 
                WHERE scan_id = %s 
                ORDER BY port
            """, (scan_id,))
            
            ports = []
            for row in cursor.fetchall():
                ports.append({
                    'port': row[0],
                    'protocol': row[1],
                    'state': row[2],
                    'service': row[3],
                    'version': row[4],
                    'product': row[5]
                })
            
            cursor.close()
            return ports
            
        except Exception as e:
            logger.error(f"Failed to get ports for scan: {e}")
            return []
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans across all IP addresses"""
        if not self.connection:
            return []
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT DISTINCT ON (ip_address) 
                       ip_address, timestamp, success, scan_time, open_ports_count
                FROM scan_results 
                ORDER BY ip_address, timestamp DESC 
                LIMIT %s
            """, (limit,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'ip_address': row[0],
                    'timestamp': row[1].isoformat(),
                    'success': row[2],
                    'scan_time': row[3],
                    'open_ports_count': row[4]
                })
            
            cursor.close()
            return results
            
        except Exception as e:
            logger.error(f"Failed to get recent scans: {e}")
            return []
    
    def add_monitoring_target(self, ip_address: str) -> bool:
        """Add IP address to monitoring targets"""
        if not self.connection:
            return False
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO monitoring_targets (ip_address, next_scan_at)
                VALUES (%s, %s)
                ON CONFLICT (ip_address) DO UPDATE SET
                is_active = TRUE,
                next_scan_at = %s
            """, (ip_address, datetime.now(), datetime.now()))
            
            cursor.close()
            logger.info(f"Added {ip_address} to monitoring targets")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add monitoring target: {e}")
            return False
    
    def remove_monitoring_target(self, ip_address: str) -> bool:
        """Remove IP address from monitoring targets"""
        if not self.connection:
            return False
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                UPDATE monitoring_targets 
                SET is_active = FALSE 
                WHERE ip_address = %s
            """, (ip_address,))
            
            cursor.close()
            logger.info(f"Removed {ip_address} from monitoring targets")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove monitoring target: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")