"""
Email Notification Manager
Handles sending daily digest emails to users about port changes
"""

import smtplib
import os
import logging
from datetime import datetime, timedelta
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from typing import List, Dict, Any
import psycopg2

logger = logging.getLogger(__name__)

class EmailManager:
    """Manages email notifications for users"""
    
    def __init__(self):
        """Initialize email manager"""
        self.conn = None
        self.connect()
    
    def connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
            logger.info("Email manager connected to database")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    def send_daily_digest(self, user_email: str, user_id: int, 
                         port_changes: List[Dict[str, Any]], 
                         scan_summary: Dict[str, Any]) -> bool:
        """Send daily digest email to user"""
        try:
            # Create email content
            subject = f"Network Monitor Daily Report - {datetime.now().strftime('%Y-%m-%d')}"
            
            # Generate HTML content
            html_content = self._generate_digest_html(port_changes, scan_summary)
            
            # Generate plain text content
            text_content = self._generate_digest_text(port_changes, scan_summary)
            
            # Send email
            success = self._send_email(user_email, subject, text_content, html_content)
            
            # Log notification in database
            self._log_notification(user_id, 'daily_digest', subject, text_content, success)
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to send daily digest to {user_email}: {e}")
            return False
    
    def _generate_digest_html(self, port_changes: List[Dict[str, Any]], 
                             scan_summary: Dict[str, Any]) -> str:
        """Generate HTML content for digest email"""
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f4f4f4; padding: 15px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; }}
                .changes {{ margin: 20px 0; }}
                .ip-section {{ margin: 15px 0; padding: 10px; border-left: 3px solid #007bff; }}
                .new-ports {{ color: #28a745; }}
                .closed-ports {{ color: #dc3545; }}
                .no-changes {{ color: #6c757d; font-style: italic; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Network Monitor Daily Report</h2>
                <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h3>Scan Summary</h3>
                <ul>
                    <li>Total monitored IPs: {scan_summary.get('total_targets', 0)}</li>
                    <li>Successful scans: {scan_summary.get('successful_scans', 0)}</li>
                    <li>Failed scans: {scan_summary.get('failed_scans', 0)}</li>
                    <li>IPs with port changes: {len(port_changes)}</li>
                </ul>
            </div>
            
            <div class="changes">
                <h3>Port Changes</h3>
        """
        
        if port_changes:
            for change in port_changes:
                html += f"""
                <div class="ip-section">
                    <h4>IP Address: {change['ip_address']}</h4>
                """
                
                if change['new_ports']:
                    html += f"""
                    <p class="new-ports"><strong>New Open Ports:</strong> {', '.join(map(str, change['new_ports']))}</p>
                    """
                
                if change['closed_ports']:
                    html += f"""
                    <p class="closed-ports"><strong>Closed Ports:</strong> {', '.join(map(str, change['closed_ports']))}</p>
                    """
                
                html += f"""
                    <p><strong>All Current Open Ports:</strong> {', '.join(map(str, change['latest_ports'])) if change['latest_ports'] else 'None'}</p>
                </div>
                """
        else:
            html += '<p class="no-changes">No port changes detected in the last 24 hours.</p>'
        
        html += """
            </div>
            
            <div class="footer">
                <p><em>This is an automated report from your Network Monitoring Tool.</em></p>
                <p>You can manage your scan targets and settings by logging into your account.</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_digest_text(self, port_changes: List[Dict[str, Any]], 
                             scan_summary: Dict[str, Any]) -> str:
        """Generate plain text content for digest email"""
        
        text = f"""
Network Monitor Daily Report
Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SCAN SUMMARY
============
Total monitored IPs: {scan_summary.get('total_targets', 0)}
Successful scans: {scan_summary.get('successful_scans', 0)}
Failed scans: {scan_summary.get('failed_scans', 0)}
IPs with port changes: {len(port_changes)}

PORT CHANGES
============
"""
        
        if port_changes:
            for change in port_changes:
                text += f"""
IP Address: {change['ip_address']}
"""
                if change['new_ports']:
                    text += f"  New Open Ports: {', '.join(map(str, change['new_ports']))}\n"
                
                if change['closed_ports']:
                    text += f"  Closed Ports: {', '.join(map(str, change['closed_ports']))}\n"
                
                text += f"  All Current Open Ports: {', '.join(map(str, change['latest_ports'])) if change['latest_ports'] else 'None'}\n"
        else:
            text += "No port changes detected in the last 24 hours.\n"
        
        text += """

This is an automated report from your Network Monitoring Tool.
You can manage your scan targets and settings by logging into your account.
"""
        
        return text
    
    def _send_email(self, to_email: str, subject: str, text_content: str, 
                   html_content: str) -> bool:
        """Send email using SMTP"""
        try:
            # Check if SendGrid API key is available
            sendgrid_key = os.environ.get('SENDGRID_API_KEY')
            if sendgrid_key:
                return self._send_with_sendgrid(to_email, subject, text_content, html_content)
            else:
                # Use SMTP as fallback
                return self._send_with_smtp(to_email, subject, text_content, html_content)
                
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def _send_with_sendgrid(self, to_email: str, subject: str, 
                           text_content: str, html_content: str) -> bool:
        """Send email using SendGrid API"""
        try:
            import sendgrid
            from sendgrid.helpers.mail import Mail, Email, To, Content
            
            sg = sendgrid.SendGridAPIClient(api_key=os.environ.get('SENDGRID_API_KEY'))
            
            from_email = Email("noreply@networkmonitor.app")
            to_email = To(to_email)
            
            message = Mail(
                from_email=from_email,
                to_emails=to_email,
                subject=subject,
                html_content=html_content
            )
            
            response = sg.send(message)
            logger.info(f"SendGrid email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"SendGrid email failed: {e}")
            return False
    
    def _send_with_smtp(self, to_email: str, subject: str, 
                       text_content: str, html_content: str) -> bool:
        """Send email using SMTP (fallback method)"""
        try:
            # SMTP configuration from environment variables
            smtp_server = os.environ.get('SMTP_SERVER', 'localhost')
            smtp_port = int(os.environ.get('SMTP_PORT', '587'))
            smtp_username = os.environ.get('SMTP_USERNAME')
            smtp_password = os.environ.get('SMTP_PASSWORD')
            from_email = os.environ.get('FROM_EMAIL', 'noreply@networkmonitor.app')
            
            # Create message
            msg = MimeMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = from_email
            msg['To'] = to_email
            
            # Attach text and HTML parts
            text_part = MimeText(text_content, 'plain')
            html_part = MimeText(html_content, 'html')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if smtp_username and smtp_password:
                    server.starttls()
                    server.login(smtp_username, smtp_password)
                
                server.send_message(msg)
            
            logger.info(f"SMTP email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"SMTP email failed: {e}")
            return False
    
    def _log_notification(self, user_id: int, email_type: str, subject: str, 
                         content: str, success: bool):
        """Log notification in database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO email_notifications 
                (user_id, email_type, subject, content, success)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, email_type, subject, content, success))
            
            self.conn.commit()
            
        except Exception as e:
            logger.error(f"Failed to log notification: {e}")
            self.conn.rollback()
    
    def get_users_for_daily_digest(self) -> List[Dict[str, Any]]:
        """Get users who should receive daily digest"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT DISTINCT u.id, u.email
                FROM users u
                JOIN user_scan_targets ust ON u.id = ust.user_id
                WHERE u.is_active = TRUE 
                AND u.email_notifications = TRUE
                AND ust.is_active = TRUE
            """)
            
            users = []
            for row in cursor.fetchall():
                users.append({
                    'id': row[0],
                    'email': row[1]
                })
            
            return users
            
        except Exception as e:
            logger.error(f"Failed to get users for digest: {e}")
            return []
    
    def get_user_scan_summary(self, user_id: int) -> Dict[str, Any]:
        """Get scan summary for user in last 24 hours"""
        try:
            cursor = self.conn.cursor()
            
            # Get total targets
            cursor.execute("""
                SELECT COUNT(*) FROM user_scan_targets
                WHERE user_id = %s AND is_active = TRUE
            """, (user_id,))
            total_targets = cursor.fetchone()[0]
            
            # Get scan results from last 24 hours
            cursor.execute("""
                SELECT success, COUNT(*)
                FROM user_scan_results
                WHERE user_id = %s 
                AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
                GROUP BY success
            """, (user_id,))
            
            successful_scans = 0
            failed_scans = 0
            
            for row in cursor.fetchall():
                if row[0]:  # success = True
                    successful_scans = row[1]
                else:  # success = False
                    failed_scans = row[1]
            
            return {
                'total_targets': total_targets,
                'successful_scans': successful_scans,
                'failed_scans': failed_scans
            }
            
        except Exception as e:
            logger.error(f"Failed to get scan summary: {e}")
            return {
                'total_targets': 0,
                'successful_scans': 0,
                'failed_scans': 0
            }
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()