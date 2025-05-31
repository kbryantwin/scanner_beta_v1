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
            
            # Only create tables that may still be needed for legacy compatibility
            # All new functionality uses user-specific tables managed by UserScanManager
            
            cursor.close()
            logger.info("Database manager initialized (using user-specific tables)")
            
        except Exception as e:
            logger.error(f"Failed to initialize database manager: {e}")
    
    # All scan result methods removed - using user-specific tables managed by UserScanManager
    # This class is kept for backwards compatibility but no longer manages scan data
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")