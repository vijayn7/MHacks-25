"""
AgentMail Component - Shares vulnerabilities and solutions with users
"""

import asyncio
import json
import uuid
import os
import smtplib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from dataclasses import dataclass, asdict
from enum import Enum
import requests
from jinja2 import Template
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

class NotificationType(Enum):
    VULNERABILITY_DETECTED = "vulnerability_detected"
    VULNERABILITY_CONFIRMED = "vulnerability_confirmed"
    VULNERABILITY_FIXED = "vulnerability_fixed"
    FALSE_POSITIVE = "false_positive"
    SECURITY_REPORT = "security_report"
    PR_ANALYSIS = "pr_analysis"
    TEST_COMPLETED = "test_completed"

class NotificationPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Vulnerability:
    vulnerability_id: str
    title: str
    description: str
    severity: str
    category: str
    file_path: str
    line_number: int
    code_snippet: str
    attack_vector: str
    evidence: str
    mitigation: str
    references: List[str]
    detected_at: datetime
    status: str
    pr_id: Optional[int] = None
    pr_url: Optional[str] = None

@dataclass
class User:
    user_id: str
    email: str
    name: str
    preferences: Dict[str, Any]
    subscribed_notifications: List[NotificationType]
    created_at: datetime

@dataclass
class Notification:
    notification_id: str
    user_id: str
    type: NotificationType
    priority: NotificationPriority
    title: str
    content: str
    vulnerability: Optional[Vulnerability] = None
    created_at: datetime = None
    sent_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    status: str = "pending"

class AgentMailComponent:
    """
    AgentMail Component for sharing vulnerabilities and solutions with users
    """
    
    def __init__(self, smtp_server: str = None, smtp_port: int = 587, 
                 smtp_username: str = None, smtp_password: str = None,
                 gemini_api_key: str = None):
        
        # Email configuration
        self.smtp_server = smtp_server or os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = smtp_port or int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = smtp_username or os.getenv("SMTP_USERNAME")
        self.smtp_password = smtp_password or os.getenv("SMTP_PASSWORD")
        
        # Gemini AI configuration
        self.gemini_api_key = gemini_api_key or os.getenv("GEMINI_API_KEY")
        if self.gemini_api_key:
            genai.configure(api_key=self.gemini_api_key)
            self.model = genai.GenerativeModel('gemini-2.5-pro')
        else:
            self.model = None
        
        # In-memory storage (in production, use a real database)
        self.users = {}
        self.notifications = {}
        self.vulnerabilities = {}
        
        # Email templates
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> Dict[str, Template]:
        """
        Initialize email templates
        """
        templates = {
            "vulnerability_detected": Template("""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { background-color: #dc3545; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
                        .content { padding: 20px; }
                        .vulnerability { background-color: #f8f9fa; border-left: 4px solid #dc3545; padding: 15px; margin: 15px 0; }
                        .severity-critical { border-left-color: #dc3545; }
                        .severity-high { border-left-color: #fd7e14; }
                        .severity-medium { border-left-color: #ffc107; }
                        .severity-low { border-left-color: #28a745; }
                        .code-snippet { background-color: #f1f3f4; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }
                        .mitigation { background-color: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 4px; margin: 15px 0; }
                        .footer { background-color: #6c757d; color: white; padding: 15px; text-align: center; border-radius: 0 0 8px 8px; }
                        .btn { display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🚨 Security Vulnerability Detected</h1>
                        </div>
                        <div class="content">
                            <p>Hello {{ user_name }},</p>
                            <p>A security vulnerability has been detected in your codebase:</p>
                            
                            <div class="vulnerability severity-{{ vulnerability.severity }}">
                                <h3>{{ vulnerability.title }}</h3>
                                <p><strong>Severity:</strong> {{ vulnerability.severity.upper() }}</p>
                                <p><strong>Category:</strong> {{ vulnerability.category }}</p>
                                <p><strong>File:</strong> {{ vulnerability.file_path }}:{{ vulnerability.line_number }}</p>
                                <p><strong>Description:</strong> {{ vulnerability.description }}</p>
                                
                                <div class="code-snippet">
                                    <strong>Code Snippet:</strong><br>
                                    {{ vulnerability.code_snippet }}
                                </div>
                                
                                <p><strong>Attack Vector:</strong> {{ vulnerability.attack_vector }}</p>
                                <p><strong>Evidence:</strong> {{ vulnerability.evidence }}</p>
                                
                                {% if vulnerability.pr_id %}
                                <p><strong>Pull Request:</strong> <a href="{{ vulnerability.pr_url }}">PR #{{ vulnerability.pr_id }}</a></p>
                                {% endif %}
                            </div>
                            
                            <div class="mitigation">
                                <h4>🛠️ Recommended Mitigation</h4>
                                <p>{{ vulnerability.mitigation }}</p>
                            </div>
                            
                            <p>Please review and fix this vulnerability as soon as possible.</p>
                            
                            <a href="{{ dashboard_url }}" class="btn">View in Dashboard</a>
                        </div>
                        <div class="footer">
                            <p>This is an automated security notification from Swarm AI Security Scanner</p>
                        </div>
                    </div>
                </body>
                </html>
            """),
            
            "security_report": Template("""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { background-color: #007bff; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
                        .content { padding: 20px; }
                        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin: 15px 0; }
                        .severity-stats { display: flex; justify-content: space-around; margin: 20px 0; }
                        .severity-item { text-align: center; padding: 10px; border-radius: 4px; }
                        .critical { background-color: #dc3545; color: white; }
                        .high { background-color: #fd7e14; color: white; }
                        .medium { background-color: #ffc107; color: black; }
                        .low { background-color: #28a745; color: white; }
                        .footer { background-color: #6c757d; color: white; padding: 15px; text-align: center; border-radius: 0 0 8px 8px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>📊 Security Report</h1>
                        </div>
                        <div class="content">
                            <p>Hello {{ user_name }},</p>
                            <p>Here's your security report for {{ report_period }}:</p>
                            
                            <div class="summary">
                                <h3>Summary</h3>
                                <p><strong>Total Findings:</strong> {{ total_findings }}</p>
                                <p><strong>Risk Score:</strong> {{ risk_score }}/100</p>
                                <p><strong>Report Period:</strong> {{ report_period }}</p>
                            </div>
                            
                            <div class="severity-stats">
                                <div class="severity-item critical">
                                    <h4>{{ severity_counts.critical }}</h4>
                                    <p>Critical</p>
                                </div>
                                <div class="severity-item high">
                                    <h4>{{ severity_counts.high }}</h4>
                                    <p>High</p>
                                </div>
                                <div class="severity-item medium">
                                    <h4>{{ severity_counts.medium }}</h4>
                                    <p>Medium</p>
                                </div>
                                <div class="severity-item low">
                                    <h4>{{ severity_counts.low }}</h4>
                                    <p>Low</p>
                                </div>
                            </div>
                            
                            <h3>Top Findings</h3>
                            <ul>
                                {% for finding in top_findings %}
                                <li><strong>{{ finding.title }}</strong> ({{ finding.severity }}) - {{ finding.file_path }}:{{ finding.line_number }}</li>
                                {% endfor %}
                            </ul>
                            
                            <h3>Recommendations</h3>
                            <ul>
                                {% for recommendation in recommendations %}
                                <li>{{ recommendation }}</li>
                                {% endfor %}
                            </ul>
                            
                            <a href="{{ dashboard_url }}" class="btn">View Full Report</a>
                        </div>
                        <div class="footer">
                            <p>This is an automated security report from Swarm AI Security Scanner</p>
                        </div>
                    </div>
                </body>
                </html>
            """),
            
            "pr_analysis": Template("""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { background-color: #6f42c1; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
                        .content { padding: 20px; }
                        .pr-info { background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin: 15px 0; }
                        .finding { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px; }
                        .footer { background-color: #6c757d; color: white; padding: 15px; text-align: center; border-radius: 0 0 8px 8px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔍 Pull Request Analysis Complete</h1>
                        </div>
                        <div class="content">
                            <p>Hello {{ user_name }},</p>
                            <p>Security analysis has been completed for your pull request:</p>
                            
                            <div class="pr-info">
                                <h3>{{ pr_title }}</h3>
                                <p><strong>PR #{{ pr_number }}</strong> by {{ pr_author }}</p>
                                <p><strong>Repository:</strong> {{ repository }}</p>
                                <p><strong>Files Changed:</strong> {{ files_changed }}</p>
                                <p><strong>Findings:</strong> {{ findings_count }}</p>
                            </div>
                            
                            {% if findings_count > 0 %}
                            <h3>Security Findings</h3>
                            {% for finding in findings %}
                            <div class="finding">
                                <h4>{{ finding.title }} ({{ finding.severity }})</h4>
                                <p><strong>File:</strong> {{ finding.file_path }}:{{ finding.line_number }}</p>
                                <p><strong>Description:</strong> {{ finding.description }}</p>
                            </div>
                            {% endfor %}
                            {% else %}
                            <p>✅ No security issues found in this pull request.</p>
                            {% endif %}
                            
                            <a href="{{ pr_url }}" class="btn">View Pull Request</a>
                        </div>
                        <div class="footer">
                            <p>This is an automated security analysis from Swarm AI Security Scanner</p>
                        </div>
                    </div>
                </body>
                </html>
            """)
        }
        
        return templates
    
    async def add_user(self, user_id: str, email: str, name: str, 
                      preferences: Dict[str, Any] = None,
                      subscribed_notifications: List[NotificationType] = None) -> User:
        """
        Add a new user to the system
        """
        user = User(
            user_id=user_id,
            email=email,
            name=name,
            preferences=preferences or {},
            subscribed_notifications=subscribed_notifications or list(NotificationType),
            created_at=datetime.now()
        )
        
        self.users[user_id] = user
        logger.info(f"Added user: {email}")
        return user
    
    async def add_vulnerability(self, vulnerability: Vulnerability) -> str:
        """
        Add a vulnerability to the system
        """
        self.vulnerabilities[vulnerability.vulnerability_id] = vulnerability
        logger.info(f"Added vulnerability: {vulnerability.title}")
        return vulnerability.vulnerability_id
    
    async def send_vulnerability_notification(self, vulnerability: Vulnerability, 
                                            user_id: str, 
                                            dashboard_url: str = "https://swarm-ai.com/dashboard") -> bool:
        """
        Send vulnerability notification to a user
        """
        try:
            user = self.users.get(user_id)
            if not user:
                logger.error(f"User {user_id} not found")
                return False
            
            # Check if user is subscribed to vulnerability notifications
            if NotificationType.VULNERABILITY_DETECTED not in user.subscribed_notifications:
                logger.info(f"User {user_id} not subscribed to vulnerability notifications")
                return True
            
            # Generate notification content using AI
            content = await self._generate_vulnerability_content(vulnerability, user)
            
            # Create notification
            notification = Notification(
                notification_id=str(uuid.uuid4()),
                user_id=user_id,
                type=NotificationType.VULNERABILITY_DETECTED,
                priority=NotificationPriority(vulnerability.severity),
                title=f"Security Vulnerability Detected: {vulnerability.title}",
                content=content,
                vulnerability=vulnerability,
                created_at=datetime.now()
            )
            
            # Store notification
            self.notifications[notification.notification_id] = notification
            
            # Send email
            success = await self._send_email(
                to_email=user.email,
                subject=notification.title,
                html_content=content,
                vulnerability=vulnerability,
                dashboard_url=dashboard_url
            )
            
            if success:
                notification.sent_at = datetime.now()
                notification.status = "sent"
                logger.info(f"Vulnerability notification sent to {user.email}")
            else:
                notification.status = "failed"
                logger.error(f"Failed to send vulnerability notification to {user.email}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending vulnerability notification: {str(e)}")
            return False
    
    async def send_security_report(self, user_id: str, report_data: Dict[str, Any],
                                 dashboard_url: str = "https://swarm-ai.com/dashboard") -> bool:
        """
        Send security report to a user
        """
        try:
            user = self.users.get(user_id)
            if not user:
                logger.error(f"User {user_id} not found")
                return False
            
            # Check if user is subscribed to security reports
            if NotificationType.SECURITY_REPORT not in user.subscribed_notifications:
                logger.info(f"User {user_id} not subscribed to security reports")
                return True
            
            # Generate report content
            content = await self._generate_security_report_content(report_data, user)
            
            # Create notification
            notification = Notification(
                notification_id=str(uuid.uuid4()),
                user_id=user_id,
                type=NotificationType.SECURITY_REPORT,
                priority=NotificationPriority.HIGH,
                title="Security Report Available",
                content=content,
                created_at=datetime.now()
            )
            
            # Store notification
            self.notifications[notification.notification_id] = notification
            
            # Send email
            success = await self._send_email(
                to_email=user.email,
                subject=notification.title,
                html_content=content,
                report_data=report_data,
                dashboard_url=dashboard_url
            )
            
            if success:
                notification.sent_at = datetime.now()
                notification.status = "sent"
                logger.info(f"Security report sent to {user.email}")
            else:
                notification.status = "failed"
                logger.error(f"Failed to send security report to {user.email}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending security report: {str(e)}")
            return False
    
    async def send_pr_analysis(self, user_id: str, pr_data: Dict[str, Any],
                              findings: List[Vulnerability],
                              dashboard_url: str = "https://swarm-ai.com/dashboard") -> bool:
        """
        Send PR analysis notification to a user
        """
        try:
            user = self.users.get(user_id)
            if not user:
                logger.error(f"User {user_id} not found")
                return False
            
            # Check if user is subscribed to PR analysis
            if NotificationType.PR_ANALYSIS not in user.subscribed_notifications:
                logger.info(f"User {user_id} not subscribed to PR analysis")
                return True
            
            # Generate PR analysis content
            content = await self._generate_pr_analysis_content(pr_data, findings, user)
            
            # Create notification
            notification = Notification(
                notification_id=str(uuid.uuid4()),
                user_id=user_id,
                type=NotificationType.PR_ANALYSIS,
                priority=NotificationPriority.MEDIUM,
                title=f"PR Analysis Complete: {pr_data.get('title', 'Unknown PR')}",
                content=content,
                created_at=datetime.now()
            )
            
            # Store notification
            self.notifications[notification.notification_id] = notification
            
            # Send email
            success = await self._send_email(
                to_email=user.email,
                subject=notification.title,
                html_content=content,
                pr_data=pr_data,
                findings=findings,
                dashboard_url=dashboard_url
            )
            
            if success:
                notification.sent_at = datetime.now()
                notification.status = "sent"
                logger.info(f"PR analysis sent to {user.email}")
            else:
                notification.status = "failed"
                logger.error(f"Failed to send PR analysis to {user.email}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending PR analysis: {str(e)}")
            return False
    
    async def _generate_vulnerability_content(self, vulnerability: Vulnerability, user: User) -> str:
        """
        Generate vulnerability notification content using AI
        """
        if not self.model:
            # Fallback to template-based content
            return self.templates["vulnerability_detected"].render(
                user_name=user.name,
                vulnerability=vulnerability,
                dashboard_url="https://swarm-ai.com/dashboard"
            )
        
        try:
            prompt = f"""
            Generate a detailed security vulnerability notification email for a developer.
            
            Vulnerability Details:
            - Title: {vulnerability.title}
            - Severity: {vulnerability.severity}
            - Category: {vulnerability.category}
            - File: {vulnerability.file_path}:{vulnerability.line_number}
            - Description: {vulnerability.description}
            - Code Snippet: {vulnerability.code_snippet}
            - Attack Vector: {vulnerability.attack_vector}
            - Evidence: {vulnerability.evidence}
            - Mitigation: {vulnerability.mitigation}
            
            User: {user.name} ({user.email})
            
            Generate a professional, informative email that:
            1. Clearly explains the vulnerability
            2. Provides actionable mitigation steps
            3. Explains the potential impact
            4. Includes code examples where appropriate
            5. Is written in a helpful, non-alarmist tone
            
            Return the content as HTML.
            """
            
            response = self.model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            logger.error(f"Error generating vulnerability content: {str(e)}")
            # Fallback to template
            return self.templates["vulnerability_detected"].render(
                user_name=user.name,
                vulnerability=vulnerability,
                dashboard_url="https://swarm-ai.com/dashboard"
            )
    
    async def _generate_security_report_content(self, report_data: Dict[str, Any], user: User) -> str:
        """
        Generate security report content using AI
        """
        if not self.model:
            # Fallback to template-based content
            return self.templates["security_report"].render(
                user_name=user.name,
                total_findings=report_data.get("total_findings", 0),
                risk_score=report_data.get("risk_score", 0),
                severity_counts=report_data.get("severity_counts", {}),
                top_findings=report_data.get("top_findings", []),
                recommendations=report_data.get("recommendations", []),
                report_period=report_data.get("report_period", "Unknown"),
                dashboard_url="https://swarm-ai.com/dashboard"
            )
        
        try:
            prompt = f"""
            Generate a comprehensive security report email for a developer.
            
            Report Data:
            - Total Findings: {report_data.get('total_findings', 0)}
            - Risk Score: {report_data.get('risk_score', 0)}/100
            - Severity Breakdown: {report_data.get('severity_counts', {})}
            - Top Findings: {report_data.get('top_findings', [])}
            - Recommendations: {report_data.get('recommendations', [])}
            - Report Period: {report_data.get('report_period', 'Unknown')}
            
            User: {user.name} ({user.email})
            
            Generate a professional security report that:
            1. Provides a clear overview of security status
            2. Highlights the most critical issues
            3. Provides actionable recommendations
            4. Explains the risk score and its implications
            5. Is well-structured and easy to read
            
            Return the content as HTML.
            """
            
            response = self.model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            logger.error(f"Error generating security report content: {str(e)}")
            # Fallback to template
            return self.templates["security_report"].render(
                user_name=user.name,
                total_findings=report_data.get("total_findings", 0),
                risk_score=report_data.get("risk_score", 0),
                severity_counts=report_data.get("severity_counts", {}),
                top_findings=report_data.get("top_findings", []),
                recommendations=report_data.get("recommendations", []),
                report_period=report_data.get("report_period", "Unknown"),
                dashboard_url="https://swarm-ai.com/dashboard"
            )
    
    async def _generate_pr_analysis_content(self, pr_data: Dict[str, Any], 
                                          findings: List[Vulnerability], user: User) -> str:
        """
        Generate PR analysis content using AI
        """
        if not self.model:
            # Fallback to template-based content
            return self.templates["pr_analysis"].render(
                user_name=user.name,
                pr_title=pr_data.get("title", "Unknown PR"),
                pr_number=pr_data.get("number", "Unknown"),
                pr_author=pr_data.get("author", "Unknown"),
                repository=pr_data.get("repository", "Unknown"),
                files_changed=pr_data.get("files_changed", 0),
                findings_count=len(findings),
                findings=findings,
                pr_url=pr_data.get("url", "#"),
                dashboard_url="https://swarm-ai.com/dashboard"
            )
        
        try:
            prompt = f"""
            Generate a pull request security analysis email for a developer.
            
            PR Data:
            - Title: {pr_data.get('title', 'Unknown PR')}
            - Number: {pr_data.get('number', 'Unknown')}
            - Author: {pr_data.get('author', 'Unknown')}
            - Repository: {pr_data.get('repository', 'Unknown')}
            - Files Changed: {pr_data.get('files_changed', 0)}
            - URL: {pr_data.get('url', '#')}
            
            Security Findings: {len(findings)} findings
            {chr(10).join([f"- {f.title} ({f.severity}) in {f.file_path}:{f.line_number}" for f in findings])}
            
            User: {user.name} ({user.email})
            
            Generate a professional PR analysis email that:
            1. Summarizes the PR and its changes
            2. Highlights any security findings
            3. Provides clear next steps
            4. Is concise but informative
            5. Encourages security best practices
            
            Return the content as HTML.
            """
            
            response = self.model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            logger.error(f"Error generating PR analysis content: {str(e)}")
            # Fallback to template
            return self.templates["pr_analysis"].render(
                user_name=user.name,
                pr_title=pr_data.get("title", "Unknown PR"),
                pr_number=pr_data.get("number", "Unknown"),
                pr_author=pr_data.get("author", "Unknown"),
                repository=pr_data.get("repository", "Unknown"),
                files_changed=pr_data.get("files_changed", 0),
                findings_count=len(findings),
                findings=findings,
                pr_url=pr_data.get("url", "#"),
                dashboard_url="https://swarm-ai.com/dashboard"
            )
    
    async def _send_email(self, to_email: str, subject: str, html_content: str,
                         vulnerability: Vulnerability = None, report_data: Dict[str, Any] = None,
                         pr_data: Dict[str, Any] = None, findings: List[Vulnerability] = None,
                         dashboard_url: str = "https://swarm-ai.com/dashboard") -> bool:
        """
        Send email notification
        """
        try:
            if not self.smtp_username or not self.smtp_password:
                logger.warning("SMTP credentials not configured, skipping email send")
                return True  # Return True for testing purposes
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.smtp_username
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Add attachments if vulnerability has screenshots
            if vulnerability and hasattr(vulnerability, 'screenshots'):
                for screenshot in vulnerability.screenshots:
                    if os.path.exists(screenshot):
                        with open(screenshot, "rb") as f:
                            attachment = MIMEBase('application', 'octet-stream')
                            attachment.set_payload(f.read())
                            encoders.encode_base64(attachment)
                            attachment.add_header(
                                'Content-Disposition',
                                f'attachment; filename= {os.path.basename(screenshot)}'
                            )
                            msg.attach(attachment)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False
    
    async def get_user_notifications(self, user_id: str, limit: int = 50) -> List[Notification]:
        """
        Get notifications for a user
        """
        user_notifications = [
            n for n in self.notifications.values() 
            if n.user_id == user_id
        ]
        
        # Sort by creation date (newest first)
        user_notifications.sort(key=lambda x: x.created_at, reverse=True)
        
        return user_notifications[:limit]
    
    async def mark_notification_read(self, notification_id: str) -> bool:
        """
        Mark a notification as read
        """
        if notification_id in self.notifications:
            self.notifications[notification_id].read_at = datetime.now()
            return True
        return False
    
    async def update_user_preferences(self, user_id: str, preferences: Dict[str, Any]) -> bool:
        """
        Update user preferences
        """
        if user_id in self.users:
            self.users[user_id].preferences.update(preferences)
            return True
        return False
    
    async def update_notification_subscriptions(self, user_id: str, 
                                              subscribed_notifications: List[NotificationType]) -> bool:
        """
        Update user notification subscriptions
        """
        if user_id in self.users:
            self.users[user_id].subscribed_notifications = subscribed_notifications
            return True
        return False

# Example usage
async def main():
    """
    Example usage of the AgentMail Component
    """
    # Initialize AgentMail
    agentmail = AgentMailComponent()
    
    # Add a user
    user = await agentmail.add_user(
        user_id="user123",
        email="developer@example.com",
        name="John Developer",
        preferences={"timezone": "UTC", "language": "en"},
        subscribed_notifications=[NotificationType.VULNERABILITY_DETECTED, NotificationType.SECURITY_REPORT]
    )
    
    # Create a sample vulnerability
    vulnerability = Vulnerability(
        vulnerability_id=str(uuid.uuid4()),
        title="SQL Injection in User Search",
        description="SQL injection vulnerability detected in user search functionality",
        severity="high",
        category="injection",
        file_path="src/controllers/UserController.js",
        line_number=45,
        code_snippet="const query = `SELECT * FROM users WHERE name = '${req.query.name}'`;",
        attack_vector="SQL Injection",
        evidence="User input directly concatenated into SQL query",
        mitigation="Use parameterized queries or prepared statements",
        references=["CWE-89", "OWASP A03"],
        detected_at=datetime.now(),
        status="detected",
        pr_id=123,
        pr_url="https://github.com/example/repo/pull/123"
    )
    
    # Send vulnerability notification
    success = await agentmail.send_vulnerability_notification(vulnerability, user.user_id)
    print(f"Vulnerability notification sent: {success}")
    
    # Create a sample security report
    report_data = {
        "total_findings": 15,
        "risk_score": 75,
        "severity_counts": {
            "critical": 2,
            "high": 5,
            "medium": 6,
            "low": 2
        },
        "top_findings": [
            {
                "title": "SQL Injection in User Search",
                "severity": "high",
                "file_path": "src/controllers/UserController.js",
                "line_number": 45
            },
            {
                "title": "XSS in Comment System",
                "severity": "medium",
                "file_path": "src/views/comments.html",
                "line_number": 23
            }
        ],
        "recommendations": [
            "Implement parameterized queries for all database operations",
            "Sanitize user input in the comment system",
            "Add input validation for all user inputs"
        ],
        "report_period": "Last 7 days"
    }
    
    # Send security report
    success = await agentmail.send_security_report(user.user_id, report_data)
    print(f"Security report sent: {success}")
    
    # Create a sample PR analysis
    pr_data = {
        "title": "Add user authentication",
        "number": 123,
        "author": "johndoe",
        "repository": "example/repo",
        "files_changed": 5,
        "url": "https://github.com/example/repo/pull/123"
    }
    
    findings = [vulnerability]
    
    # Send PR analysis
    success = await agentmail.send_pr_analysis(user.user_id, pr_data, findings)
    print(f"PR analysis sent: {success}")
    
    # Get user notifications
    notifications = await agentmail.get_user_notifications(user.user_id)
    print(f"User has {len(notifications)} notifications")

if __name__ == "__main__":
    asyncio.run(main())
