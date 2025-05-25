#!/usr/bin/env python3
"""
Database Models for Network Monitoring Tool
"""

from datetime import datetime

def create_models(db):
    """Create database models with the given db instance"""
    
    class ScanTarget(db.Model):
    """Model for scan targets (IP addresses being monitored)"""
    __tablename__ = 'scan_targets'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    hostname = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    last_scan_at = Column(DateTime)
    is_monitoring = Column(Boolean, default=False)
    scan_interval_hours = Column(Integer, default=24)
    
    # Relationships
    scans = relationship("ScanResult", back_populates="target", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="target", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ScanTarget(ip='{self.ip_address}', monitoring={self.is_monitoring})>"

class ScanResult(Base):
    """Model for individual scan results"""
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('scan_targets.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    success = Column(Boolean, nullable=False)
    scan_time = Column(String(20))  # Duration in seconds
    error_message = Column(Text)
    host_state = Column(String(50))
    host_reason = Column(String(100))
    os_name = Column(String(255))
    os_accuracy = Column(Integer)
    raw_result = Column(JSON)  # Store complete nmap result
    
    # Relationships
    target = relationship("ScanTarget", back_populates="scans")
    ports = relationship("PortResult", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ScanResult(target={self.target_id}, success={self.success}, timestamp={self.timestamp})>"

class PortResult(Base):
    """Model for individual port scan results"""
    __tablename__ = 'port_results'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan_results.id'), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default='tcp')
    state = Column(String(20), nullable=False)
    service = Column(String(100))
    version = Column(String(255))
    product = Column(String(255))
    extrainfo = Column(String(255))
    confidence = Column(String(10))
    
    # Relationships
    scan = relationship("ScanResult", back_populates="ports")
    
    def __repr__(self):
        return f"<PortResult(port={self.port}, state='{self.state}', service='{self.service}')>"

class Notification(Base):
    """Model for port change notifications"""
    __tablename__ = 'notifications'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('scan_targets.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    notification_type = Column(String(50), default='port_change')
    message = Column(Text, nullable=False)
    new_ports = Column(JSON)  # List of newly opened ports
    closed_ports = Column(JSON)  # List of closed ports
    is_read = Column(Boolean, default=False)
    
    # Relationships
    target = relationship("ScanTarget", back_populates="notifications")
    
    def __repr__(self):
        return f"<Notification(target={self.target_id}, type='{self.notification_type}', timestamp={self.timestamp})>"

class ScheduledTask(Base):
    """Model for scheduled monitoring tasks"""
    __tablename__ = 'scheduled_tasks'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('scan_targets.id'), nullable=False)
    next_scan_at = Column(DateTime, nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    consecutive_failures = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    target = relationship("ScanTarget")
    
    def __repr__(self):
        return f"<ScheduledTask(target={self.target_id}, next_scan={self.next_scan_at}, active={self.is_active})>"