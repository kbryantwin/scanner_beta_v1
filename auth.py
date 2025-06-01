"""
Authentication Module for Network Monitoring Tool
Handles user registration, login, and session management
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import psycopg2
import os
import logging

logger = logging.getLogger(__name__)

class AuthManager:
    """Manages user authentication and sessions"""

    def __init__(self):
        """Initialize auth manager with database connection"""
        self.conn = None
        self.connect()
        self.create_auth_tables()

    def connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
            logger.info("Auth manager connected to database")
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

    def create_auth_tables(self):
        """Create authentication tables"""
        try:
            cursor = self.conn.cursor()

            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    email_notifications BOOLEAN DEFAULT TRUE,
                    scan_mode VARCHAR(50) DEFAULT 'fast'
                )
            """)

            # Create sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    session_token VARCHAR(255) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE
                )
            """)

            # Create user_scan_targets table (user-specific scan targets)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_scan_targets (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    ip_address INET NOT NULL,
                    description TEXT,
                    scan_interval_minutes INTEGER DEFAULT 720,
                    is_active BOOLEAN DEFAULT TRUE,
                    is_paused BOOLEAN DEFAULT FALSE,
                    last_scan_at TIMESTAMP,
                    next_scan_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, ip_address)
                )
            """)

            # Create user_scan_results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_scan_results (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    target_id INTEGER REFERENCES user_scan_targets(id) ON DELETE CASCADE,
                    ip_address INET NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN NOT NULL,
                    scan_time VARCHAR(20),
                    error_message TEXT,
                    host_state VARCHAR(50),
                    open_ports_count INTEGER DEFAULT 0,
                    raw_result JSONB
                )
            """)

            # Create user_port_results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_port_results (
                    id SERIAL PRIMARY KEY,
                    scan_result_id INTEGER REFERENCES user_scan_results(id) ON DELETE CASCADE,
                    port INTEGER NOT NULL,
                    protocol VARCHAR(10) DEFAULT 'tcp',
                    state VARCHAR(20) NOT NULL,
                    service VARCHAR(100),
                    version VARCHAR(255),
                    product VARCHAR(255)
                )
            """)

            # Create email_notifications table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_notifications (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    email_type VARCHAR(50) NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    subject VARCHAR(255),
                    content TEXT,
                    success BOOLEAN DEFAULT TRUE
                )
            """)

            self.conn.commit()
            logger.info("Authentication tables created successfully")

        except Exception as e:
            logger.error(f"Failed to create auth tables: {e}")
            self.conn.rollback()
            raise

    def register_user(self, email: str, password: str) -> bool:
        """Register a new user"""
        try:
            # Ensure database connection
            self.ensure_connection()

            # Hash password with salt
            salt = secrets.token_hex(16)
            password_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest() + ':' + salt

            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO users (email, password_hash)
                VALUES (%s, %s)
            """, (email.lower(), password_hash))

            self.conn.commit()
            logger.info(f"User registered successfully: {email}")
            return True

        except psycopg2.IntegrityError:
            logger.warning(f"Registration failed - email already exists: {email}")
            self.conn.rollback()
            return False
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            self.conn.rollback()
            return False

    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user and return user data"""
        try:
            # Ensure database connection
            self.ensure_connection()

            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, email, password_hash, is_active
                FROM users
                WHERE email = %s
            """, (email.lower(),))

            user = cursor.fetchone()
            if not user:
                return None

            user_id, user_email, password_hash, is_active = user

            if not is_active:
                return None

            # Check password
            stored_hash, salt = password_hash.split(':')
            if hashlib.sha256((password + salt).encode('utf-8')).hexdigest() == stored_hash:
                return {
                    'id': user_id,
                    'email': user_email,
                    'is_active': is_active
                }

            return None

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return None

    def create_session(self, user_id: int) -> str:
        """Create a new session for user"""
        try:
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(days=30)  # 30-day sessions

            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (%s, %s, %s)
            """, (user_id, session_token, expires_at))

            self.conn.commit()
            logger.info(f"Session created for user {user_id}")
            return session_token

        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            self.conn.rollback()
            raise

    def validate_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Validate session and return user data"""
        try:
            # Ensure database connection
            self.ensure_connection()

            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT u.id, u.email, u.is_active, s.expires_at
                FROM users u
                JOIN user_sessions s ON u.id = s.user_id
                WHERE s.session_token = %s AND s.is_active = TRUE
            """, (session_token,))

            result = cursor.fetchone()
            if not result:
                return None

            user_id, email, is_active, expires_at = result

            # Check if session expired
            if datetime.now() > expires_at:
                self.invalidate_session(session_token)
                return None

            if not is_active:
                return None

            return {
                'id': user_id,
                'email': email,
                'is_active': is_active
            }

        except Exception as e:
            logger.error(f"Session validation failed: {e}")
            return None

    def invalidate_session(self, session_token: str) -> bool:
        """Invalidate a session"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE user_sessions 
                SET is_active = FALSE 
                WHERE session_token = %s
            """, (session_token,))

            self.conn.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to invalidate session: {e}")
            self.conn.rollback()
            return False

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, email, is_active, email_notifications, created_at
                FROM users
                WHERE id = %s
            """, (user_id,))

            user = cursor.fetchone()
            if user:
                return {
                    'id': user[0],
                    'email': user[1],
                    'is_active': user[2],
                    'email_notifications': user[3],
                    'created_at': user[4]
                }
            return None

        except Exception as e:
            logger.error(f"Failed to get user: {e}")
            return None
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, email, password_hash, created_at, updated_at, is_active, email_notifications, scan_mode
                FROM users WHERE email = %s
            """, (email,))

            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'email': row[1],
                    'password_hash': row[2],
                    'created_at': row[3],
                    'updated_at': row[4],
                    'is_active': row[5],
                    'email_notifications': row[6],
                    'scan_mode': row[7] or 'fast'
                }
            return None

        except Exception as e:
            logger.error(f"Failed to get user by email: {e}")
            return None

    def update_user_settings(self, user_id: int, email_notifications: bool = None, scan_mode: str = None) -> bool:
        """Update user settings"""
        try:
            cursor = self.conn.cursor()

            if email_notifications is not None:
                cursor.execute("""
                    UPDATE users 
                    SET email_notifications = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (email_notifications, user_id))

            if scan_mode is not None:
                cursor.execute("""
                    UPDATE users
                    SET scan_mode = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (scan_mode, user_id))

            self.conn.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to update user settings: {e}")
            self.conn.rollback()
            return False

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()