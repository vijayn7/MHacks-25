"""
Swarm Database - Monitors GitHub PRs for attack vectors
"""

import asyncio
import json
import uuid
import os
import re
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import requests
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import base64

logger = logging.getLogger(__name__)

class PRStatus(Enum):
    OPEN = "open"
    CLOSED = "closed"
    MERGED = "merged"
    DRAFT = "draft"

class VulnerabilityStatus(Enum):
    DETECTED = "detected"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    IGNORED = "ignored"

@dataclass
class GitHubPR:
    pr_id: int
    title: str
    description: str
    author: str
    status: PRStatus
    created_at: datetime
    updated_at: datetime
    base_branch: str
    head_branch: str
    files_changed: List[str]
    additions: int
    deletions: int
    url: str
    repository: str

@dataclass
class VulnerabilityFinding:
    finding_id: str
    pr_id: int
    file_path: str
    line_number: int
    vulnerability_type: str
    severity: str
    description: str
    code_snippet: str
    attack_vector: str
    status: VulnerabilityStatus
    detected_at: datetime
    confirmed_at: Optional[datetime] = None
    fixed_at: Optional[datetime] = None
    false_positive_reason: Optional[str] = None

@dataclass
class AttackVector:
    vector_id: str
    name: str
    description: str
    patterns: List[str]
    severity: str
    category: str
    mitigation: str
    created_at: datetime

class SwarmDatabase:
    """
    Swarm Database for monitoring GitHub PRs and detecting attack vectors
    """
    
    def __init__(self, github_token: str, webhook_secret: str = None):
        self.github_token = github_token
        self.webhook_secret = webhook_secret
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Swarm-Security-Scanner/1.0"
        }
        
        # In-memory storage (in production, use a real database)
        self.prs = {}
        self.findings = {}
        self.attack_vectors = {}
        self.repositories = set()
        
        # Initialize attack vectors
        self._initialize_attack_vectors()
    
    def _initialize_attack_vectors(self):
        """
        Initialize common attack vectors to look for in PRs
        """
        attack_vectors = [
            {
                "name": "SQL Injection",
                "description": "SQL injection vulnerabilities in database queries",
                "patterns": [
                    r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\$\{.*\}",
                    r"INSERT\s+INTO\s+.*\s+VALUES\s*\(.*\$\{.*\}\)",
                    r"UPDATE\s+.*\s+SET\s+.*\s+WHERE\s+.*\$\{.*\}",
                    r"DELETE\s+FROM\s+.*\s+WHERE\s+.*\$\{.*\}",
                    r"query\s*\(\s*[\"'].*\$.*[\"']",
                    r"execute\s*\(\s*[\"'].*\$.*[\"']",
                    r"\.query\s*\(\s*`.*\$\{.*\}`",
                    r"\.execute\s*\(\s*`.*\$\{.*\}`"
                ],
                "severity": "high",
                "category": "injection",
                "mitigation": "Use parameterized queries or prepared statements"
            },
            {
                "name": "XSS (Cross-Site Scripting)",
                "description": "XSS vulnerabilities in web applications",
                "patterns": [
                    r"innerHTML\s*=\s*.*\$\{.*\}",
                    r"outerHTML\s*=\s*.*\$\{.*\}",
                    r"document\.write\s*\(\s*.*\$\{.*\}\)",
                    r"eval\s*\(\s*.*\$\{.*\}\)",
                    r"setTimeout\s*\(\s*.*\$\{.*\}",
                    r"setInterval\s*\(\s*.*\$\{.*\}",
                    r"dangerouslySetInnerHTML.*\$\{.*\}",
                    r"v-html.*\$\{.*\}"
                ],
                "severity": "high",
                "category": "injection",
                "mitigation": "Sanitize user input and use proper output encoding"
            },
            {
                "name": "Command Injection",
                "description": "Command injection vulnerabilities",
                "patterns": [
                    r"exec\s*\(\s*.*\$\{.*\}\)",
                    r"system\s*\(\s*.*\$\{.*\}\)",
                    r"shell_exec\s*\(\s*.*\$\{.*\}\)",
                    r"passthru\s*\(\s*.*\$\{.*\}\)",
                    r"proc_open\s*\(\s*.*\$\{.*\}\)",
                    r"child_process\.exec\s*\(\s*.*\$\{.*\}\)",
                    r"child_process\.spawn\s*\(\s*.*\$\{.*\}\)",
                    r"Runtime\.getRuntime\(\)\.exec\s*\(\s*.*\$\{.*\}\)"
                ],
                "severity": "critical",
                "category": "injection",
                "mitigation": "Avoid executing user input as commands, use safe APIs"
            },
            {
                "name": "Path Traversal",
                "description": "Path traversal vulnerabilities",
                "patterns": [
                    r"file_get_contents\s*\(\s*.*\$\{.*\}\)",
                    r"fopen\s*\(\s*.*\$\{.*\}\)",
                    r"include\s*\(\s*.*\$\{.*\}\)",
                    r"require\s*\(\s*.*\$\{.*\}\)",
                    r"readFile\s*\(\s*.*\$\{.*\}\)",
                    r"fs\.readFile\s*\(\s*.*\$\{.*\}\)",
                    r"new File\s*\(\s*.*\$\{.*\}\)",
                    r"Files\.readAllBytes\s*\(\s*.*\$\{.*\}\)"
                ],
                "severity": "high",
                "category": "injection",
                "mitigation": "Validate and sanitize file paths, use allowlists"
            },
            {
                "name": "Hardcoded Secrets",
                "description": "Hardcoded secrets in code",
                "patterns": [
                    r"password\s*=\s*[\"'][^\"']{8,}[\"']",
                    r"api_key\s*=\s*[\"'][^\"']{8,}[\"']",
                    r"secret\s*=\s*[\"'][^\"']{8,}[\"']",
                    r"token\s*=\s*[\"'][^\"']{8,}[\"']",
                    r"private_key\s*=\s*[\"'][^\"']{8,}[\"']",
                    r"access_token\s*=\s*[\"'][^\"']{8,}[\"']",
                    r"auth_token\s*=\s*[\"'][^\"']{8,}[\"']",
                    r"jwt_secret\s*=\s*[\"'][^\"']{8,}[\"']"
                ],
                "severity": "critical",
                "category": "secrets",
                "mitigation": "Use environment variables or secure secret management"
            },
            {
                "name": "Weak Cryptography",
                "description": "Weak cryptographic implementations",
                "patterns": [
                    r"MD5\s*\(",
                    r"SHA1\s*\(",
                    r"DES\s*\(",
                    r"RC4\s*\(",
                    r"crypto\.createHash\s*\(\s*[\"']md5[\"']",
                    r"crypto\.createHash\s*\(\s*[\"']sha1[\"']",
                    r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']",
                    r"MessageDigest\.getInstance\s*\(\s*[\"']SHA1[\"']"
                ],
                "severity": "medium",
                "category": "cryptography",
                "mitigation": "Use strong cryptographic algorithms like SHA-256, AES-256"
            },
            {
                "name": "Insecure Random",
                "description": "Insecure random number generation",
                "patterns": [
                    r"Math\.random\s*\(",
                    r"new Random\s*\(\s*\)",
                    r"Random\s*\(\s*\)",
                    r"rand\s*\(",
                    r"mt_rand\s*\(",
                    r"random\.random\s*\(",
                    r"crypto\.randomBytes\s*\(\s*1\s*\)"
                ],
                "severity": "medium",
                "category": "cryptography",
                "mitigation": "Use cryptographically secure random number generators"
            },
            {
                "name": "Missing Authentication",
                "description": "Missing authentication checks",
                "patterns": [
                    r"@RequestMapping.*\n(?!.*@PreAuthorize)",
                    r"@GetMapping.*\n(?!.*@PreAuthorize)",
                    r"@PostMapping.*\n(?!.*@PreAuthorize)",
                    r"@PutMapping.*\n(?!.*@PreAuthorize)",
                    r"@DeleteMapping.*\n(?!.*@PreAuthorize)",
                    r"app\.get\s*\(\s*[\"'][^\"']*[\"']\s*,\s*\(.*\)\s*=>",
                    r"app\.post\s*\(\s*[\"'][^\"']*[\"']\s*,\s*\(.*\)\s*=>",
                    r"router\.get\s*\(\s*[\"'][^\"']*[\"']\s*,\s*\(.*\)\s*=>"
                ],
                "severity": "high",
                "category": "authentication",
                "mitigation": "Add proper authentication and authorization checks"
            },
            {
                "name": "Insecure Direct Object Reference",
                "description": "Insecure direct object reference vulnerabilities",
                "patterns": [
                    r"findById\s*\(\s*.*\$\{.*\}\)",
                    r"findBy.*\s*\(\s*.*\$\{.*\}\)",
                    r"get.*\s*\(\s*.*\$\{.*\}\)",
                    r"select.*\s*where\s+id\s*=\s*.*\$\{.*\}",
                    r"WHERE\s+id\s*=\s*.*\$\{.*\}",
                    r"filter\s*\(\s*.*\$\{.*\}\)",
                    r"query\s*\(\s*.*\$\{.*\}\)"
                ],
                "severity": "high",
                "category": "authorization",
                "mitigation": "Implement proper authorization checks for object access"
            },
            {
                "name": "CORS Misconfiguration",
                "description": "CORS misconfiguration vulnerabilities",
                "patterns": [
                    r"Access-Control-Allow-Origin\s*:\s*[\"']\*[\"']",
                    r"Access-Control-Allow-Credentials\s*:\s*true",
                    r"cors\s*\(\s*\{\s*origin\s*:\s*[\"']\*[\"']",
                    r"cors\s*\(\s*\{\s*credentials\s*:\s*true",
                    r"@CrossOrigin\s*\(\s*origin\s*=\s*[\"']\*[\"']"
                ],
                "severity": "medium",
                "category": "configuration",
                "mitigation": "Configure CORS properly with specific origins and credentials"
            }
        ]
        
        for i, vector in enumerate(attack_vectors):
            attack_vector = AttackVector(
                vector_id=str(uuid.uuid4()),
                name=vector["name"],
                description=vector["description"],
                patterns=vector["patterns"],
                severity=vector["severity"],
                category=vector["category"],
                mitigation=vector["mitigation"],
                created_at=datetime.now()
            )
            self.attack_vectors[attack_vector.vector_id] = attack_vector
    
    async def monitor_repository(self, owner: str, repo: str) -> bool:
        """
        Start monitoring a GitHub repository for PRs
        """
        try:
            self.repositories.add(f"{owner}/{repo}")
            logger.info(f"Started monitoring repository: {owner}/{repo}")
            
            # Fetch recent PRs
            await self._fetch_recent_prs(owner, repo)
            
            return True
        except Exception as e:
            logger.error(f"Failed to start monitoring repository {owner}/{repo}: {str(e)}")
            return False
    
    async def _fetch_recent_prs(self, owner: str, repo: str) -> List[GitHubPR]:
        """
        Fetch recent PRs from a repository
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/pulls"
            params = {
                "state": "all",
                "sort": "updated",
                "direction": "desc",
                "per_page": 50
            }
            
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            prs_data = response.json()
            prs = []
            
            for pr_data in prs_data:
                pr = GitHubPR(
                    pr_id=pr_data["number"],
                    title=pr_data["title"],
                    description=pr_data.get("body", ""),
                    author=pr_data["user"]["login"],
                    status=PRStatus(pr_data["state"]),
                    created_at=datetime.fromisoformat(pr_data["created_at"].replace("Z", "+00:00")),
                    updated_at=datetime.fromisoformat(pr_data["updated_at"].replace("Z", "+00:00")),
                    base_branch=pr_data["base"]["ref"],
                    head_branch=pr_data["head"]["ref"],
                    files_changed=[],  # Will be fetched separately
                    additions=pr_data["additions"],
                    deletions=pr_data["deletions"],
                    url=pr_data["html_url"],
                    repository=f"{owner}/{repo}"
                )
                
                # Fetch files changed
                pr.files_changed = await self._fetch_pr_files(owner, repo, pr.pr_id)
                
                prs.append(pr)
                self.prs[pr.pr_id] = pr
            
            logger.info(f"Fetched {len(prs)} PRs from {owner}/{repo}")
            return prs
            
        except Exception as e:
            logger.error(f"Failed to fetch PRs from {owner}/{repo}: {str(e)}")
            return []
    
    async def _fetch_pr_files(self, owner: str, repo: str, pr_id: int) -> List[str]:
        """
        Fetch files changed in a PR
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_id}/files"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            files_data = response.json()
            return [file_data["filename"] for file_data in files_data]
            
        except Exception as e:
            logger.error(f"Failed to fetch files for PR {pr_id}: {str(e)}")
            return []
    
    async def analyze_pr(self, pr_id: int) -> List[VulnerabilityFinding]:
        """
        Analyze a PR for security vulnerabilities
        """
        if pr_id not in self.prs:
            logger.warning(f"PR {pr_id} not found in database")
            return []
        
        pr = self.prs[pr_id]
        findings = []
        
        try:
            # Fetch PR diff
            diff = await self._fetch_pr_diff(pr.repository, pr_id)
            
            # Analyze diff for vulnerabilities
            for file_path, file_diff in diff.items():
                file_findings = await self._analyze_file_diff(file_path, file_diff, pr_id)
                findings.extend(file_findings)
            
            # Store findings
            for finding in findings:
                self.findings[finding.finding_id] = finding
            
            logger.info(f"Analyzed PR {pr_id}, found {len(findings)} potential vulnerabilities")
            return findings
            
        except Exception as e:
            logger.error(f"Failed to analyze PR {pr_id}: {str(e)}")
            return []
    
    async def _fetch_pr_diff(self, repository: str, pr_id: int) -> Dict[str, str]:
        """
        Fetch PR diff
        """
        try:
            url = f"{self.base_url}/repos/{repository}/pulls/{pr_id}"
            headers = {
                **self.headers,
                "Accept": "application/vnd.github.v3.diff"
            }
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            diff_content = response.text
            
            # Parse diff into files
            files = {}
            current_file = None
            current_diff = []
            
            for line in diff_content.split('\n'):
                if line.startswith('diff --git'):
                    if current_file and current_diff:
                        files[current_file] = '\n'.join(current_diff)
                    current_file = line.split(' ')[-1]
                    current_diff = [line]
                elif current_file:
                    current_diff.append(line)
            
            if current_file and current_diff:
                files[current_file] = '\n'.join(current_diff)
            
            return files
            
        except Exception as e:
            logger.error(f"Failed to fetch diff for PR {pr_id}: {str(e)}")
            return {}
    
    async def _analyze_file_diff(self, file_path: str, file_diff: str, pr_id: int) -> List[VulnerabilityFinding]:
        """
        Analyze a file diff for security vulnerabilities
        """
        findings = []
        
        try:
            # Split diff into lines
            lines = file_diff.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # Skip diff headers and context lines
                if line.startswith('@@') or line.startswith('---') or line.startswith('+++'):
                    continue
                
                # Only analyze added lines
                if not line.startswith('+'):
                    continue
                
                # Remove the '+' prefix
                code_line = line[1:]
                
                # Check against all attack vectors
                for vector_id, vector in self.attack_vectors.items():
                    for pattern in vector.patterns:
                        if re.search(pattern, code_line, re.IGNORECASE | re.MULTILINE):
                            finding = VulnerabilityFinding(
                                finding_id=str(uuid.uuid4()),
                                pr_id=pr_id,
                                file_path=file_path,
                                line_number=line_num,
                                vulnerability_type=vector.name,
                                severity=vector.severity,
                                description=f"{vector.description} detected in {file_path}",
                                code_snippet=code_line.strip(),
                                attack_vector=vector.name,
                                status=VulnerabilityStatus.DETECTED,
                                detected_at=datetime.now()
                            )
                            findings.append(finding)
                            
                            # Log the finding
                            logger.warning(f"Security vulnerability detected: {vector.name} in {file_path}:{line_num}")
        
        except Exception as e:
            logger.error(f"Failed to analyze file diff for {file_path}: {str(e)}")
        
        return findings
    
    async def get_pr_findings(self, pr_id: int) -> List[VulnerabilityFinding]:
        """
        Get all findings for a specific PR
        """
        return [finding for finding in self.findings.values() if finding.pr_id == pr_id]
    
    async def get_findings_by_severity(self, severity: str) -> List[VulnerabilityFinding]:
        """
        Get all findings by severity level
        """
        return [finding for finding in self.findings.values() if finding.severity == severity]
    
    async def get_findings_by_type(self, vulnerability_type: str) -> List[VulnerabilityFinding]:
        """
        Get all findings by vulnerability type
        """
        return [finding for finding in self.findings.values() if finding.vulnerability_type == vulnerability_type]
    
    async def update_finding_status(self, finding_id: str, status: VulnerabilityStatus, reason: str = None) -> bool:
        """
        Update the status of a finding
        """
        if finding_id not in self.findings:
            return False
        
        finding = self.findings[finding_id]
        finding.status = status
        
        if status == VulnerabilityStatus.CONFIRMED:
            finding.confirmed_at = datetime.now()
        elif status == VulnerabilityStatus.FIXED:
            finding.fixed_at = datetime.now()
        elif status == VulnerabilityStatus.FALSE_POSITIVE:
            finding.false_positive_reason = reason
        
        return True
    
    async def generate_security_report(self, pr_id: int = None) -> Dict[str, Any]:
        """
        Generate a security report for a PR or all PRs
        """
        if pr_id:
            findings = await self.get_pr_findings(pr_id)
            pr = self.prs.get(pr_id)
            title = f"Security Report for PR #{pr_id}" if pr else f"Security Report for PR #{pr_id} (Not Found)"
        else:
            findings = list(self.findings.values())
            title = "Security Report for All PRs"
        
        # Categorize findings
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        type_counts = {}
        status_counts = {
            "detected": 0,
            "confirmed": 0,
            "false_positive": 0,
            "fixed": 0,
            "ignored": 0
        }
        
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            type_counts[finding.vulnerability_type] = type_counts.get(finding.vulnerability_type, 0) + 1
            status_counts[finding.status.value] = status_counts.get(finding.status.value, 0) + 1
        
        # Calculate risk score
        risk_score = (
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 7 +
            severity_counts["medium"] * 4 +
            severity_counts["low"] * 1
        )
        
        # Get top findings
        top_findings = sorted(findings, key=lambda x: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4),
            x.detected_at
        ))[:10]
        
        report = {
            "title": title,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_findings": len(findings),
                "risk_score": risk_score,
                "severity_breakdown": severity_counts,
                "type_breakdown": type_counts,
                "status_breakdown": status_counts
            },
            "top_findings": [
                {
                    "finding_id": f.finding_id,
                    "pr_id": f.pr_id,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "vulnerability_type": f.vulnerability_type,
                    "severity": f.severity,
                    "description": f.description,
                    "status": f.status.value,
                    "detected_at": f.detected_at.isoformat()
                }
                for f in top_findings
            ],
            "recommendations": self._generate_recommendations(findings)
        }
        
        return report
    
    def _generate_recommendations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        """
        Generate security recommendations based on findings
        """
        recommendations = []
        
        # Count vulnerability types
        type_counts = {}
        for finding in findings:
            type_counts[finding.vulnerability_type] = type_counts.get(finding.vulnerability_type, 0) + 1
        
        # Generate recommendations based on most common issues
        if type_counts.get("SQL Injection", 0) > 0:
            recommendations.append("Implement parameterized queries or prepared statements to prevent SQL injection")
        
        if type_counts.get("XSS (Cross-Site Scripting)", 0) > 0:
            recommendations.append("Sanitize user input and use proper output encoding to prevent XSS")
        
        if type_counts.get("Hardcoded Secrets", 0) > 0:
            recommendations.append("Move hardcoded secrets to environment variables or secure secret management")
        
        if type_counts.get("Missing Authentication", 0) > 0:
            recommendations.append("Add proper authentication and authorization checks to all endpoints")
        
        if type_counts.get("Insecure Direct Object Reference", 0) > 0:
            recommendations.append("Implement proper authorization checks for object access")
        
        if type_counts.get("Weak Cryptography", 0) > 0:
            recommendations.append("Use strong cryptographic algorithms like SHA-256 and AES-256")
        
        if type_counts.get("CORS Misconfiguration", 0) > 0:
            recommendations.append("Configure CORS properly with specific origins and credentials")
        
        return recommendations
    
    async def webhook_handler(self, payload: Dict[str, Any], signature: str = None) -> bool:
        """
        Handle GitHub webhook events
        """
        try:
            # Verify webhook signature if secret is provided
            if self.webhook_secret and signature:
                if not self._verify_webhook_signature(payload, signature):
                    logger.warning("Invalid webhook signature")
                    return False
            
            # Handle different event types
            event_type = payload.get("action")
            
            if event_type == "opened":
                await self._handle_pr_opened(payload)
            elif event_type == "synchronize":
                await self._handle_pr_updated(payload)
            elif event_type == "closed":
                await self._handle_pr_closed(payload)
            elif event_type == "merged":
                await self._handle_pr_merged(payload)
            
            return True
            
        except Exception as e:
            logger.error(f"Webhook handler error: {str(e)}")
            return False
    
    def _verify_webhook_signature(self, payload: Dict[str, Any], signature: str) -> bool:
        """
        Verify GitHub webhook signature
        """
        try:
            import hmac
            import hashlib
            
            # GitHub sends the signature as "sha256=hash"
            if not signature.startswith("sha256="):
                return False
            
            expected_signature = signature[7:]  # Remove "sha256=" prefix
            
            # Create HMAC signature
            payload_str = json.dumps(payload, separators=(',', ':'))
            computed_signature = hmac.new(
                self.webhook_secret.encode('utf-8'),
                payload_str.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(expected_signature, computed_signature)
            
        except Exception as e:
            logger.error(f"Signature verification error: {str(e)}")
            return False
    
    async def _handle_pr_opened(self, payload: Dict[str, Any]):
        """
        Handle PR opened event
        """
        try:
            pr_data = payload["pull_request"]
            pr_id = pr_data["number"]
            
            # Create PR object
            pr = GitHubPR(
                pr_id=pr_id,
                title=pr_data["title"],
                description=pr_data.get("body", ""),
                author=pr_data["user"]["login"],
                status=PRStatus(pr_data["state"]),
                created_at=datetime.fromisoformat(pr_data["created_at"].replace("Z", "+00:00")),
                updated_at=datetime.fromisoformat(pr_data["updated_at"].replace("Z", "+00:00")),
                base_branch=pr_data["base"]["ref"],
                head_branch=pr_data["head"]["ref"],
                files_changed=[],  # Will be fetched separately
                additions=pr_data["additions"],
                deletions=pr_data["deletions"],
                url=pr_data["html_url"],
                repository=pr_data["base"]["repo"]["full_name"]
            )
            
            # Store PR
            self.prs[pr_id] = pr
            
            # Analyze PR for vulnerabilities
            findings = await self.analyze_pr(pr_id)
            
            logger.info(f"PR #{pr_id} opened, found {len(findings)} potential vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error handling PR opened event: {str(e)}")
    
    async def _handle_pr_updated(self, payload: Dict[str, Any]):
        """
        Handle PR updated event
        """
        try:
            pr_data = payload["pull_request"]
            pr_id = pr_data["number"]
            
            if pr_id in self.prs:
                # Update PR
                self.prs[pr_id].updated_at = datetime.fromisoformat(pr_data["updated_at"].replace("Z", "+00:00"))
                
                # Re-analyze PR
                findings = await self.analyze_pr(pr_id)
                
                logger.info(f"PR #{pr_id} updated, found {len(findings)} potential vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error handling PR updated event: {str(e)}")
    
    async def _handle_pr_closed(self, payload: Dict[str, Any]):
        """
        Handle PR closed event
        """
        try:
            pr_data = payload["pull_request"]
            pr_id = pr_data["number"]
            
            if pr_id in self.prs:
                self.prs[pr_id].status = PRStatus.CLOSED
                logger.info(f"PR #{pr_id} closed")
            
        except Exception as e:
            logger.error(f"Error handling PR closed event: {str(e)}")
    
    async def _handle_pr_merged(self, payload: Dict[str, Any]):
        """
        Handle PR merged event
        """
        try:
            pr_data = payload["pull_request"]
            pr_id = pr_data["number"]
            
            if pr_id in self.prs:
                self.prs[pr_id].status = PRStatus.MERGED
                logger.info(f"PR #{pr_id} merged")
            
        except Exception as e:
            logger.error(f"Error handling PR merged event: {str(e)}")

# Example usage
async def main():
    """
    Example usage of the Swarm Database
    """
    # Initialize the database
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("Please set GITHUB_TOKEN environment variable")
        return
    
    swarm_db = SwarmDatabase(github_token)
    
    # Monitor a repository
    owner = "octocat"
    repo = "Hello-World"
    
    print(f"🔍 Starting monitoring for {owner}/{repo}")
    
    # Start monitoring
    success = await swarm_db.monitor_repository(owner, repo)
    
    if success:
        print(f"✅ Successfully started monitoring {owner}/{repo}")
        
        # Get recent PRs
        prs = list(swarm_db.prs.values())
        print(f"📋 Found {len(prs)} PRs")
        
        # Analyze each PR
        for pr in prs[:5]:  # Analyze first 5 PRs
            print(f"\n🔍 Analyzing PR #{pr.pr_id}: {pr.title}")
            findings = await swarm_db.analyze_pr(pr.pr_id)
            print(f"   Found {len(findings)} potential vulnerabilities")
            
            for finding in findings:
                print(f"   - {finding.vulnerability_type} ({finding.severity}) in {finding.file_path}:{finding.line_number}")
        
        # Generate security report
        report = await swarm_db.generate_security_report()
        print(f"\n📊 Security Report Summary:")
        print(f"   Total Findings: {report['summary']['total_findings']}")
        print(f"   Risk Score: {report['summary']['risk_score']}")
        print(f"   Critical: {report['summary']['severity_breakdown']['critical']}")
        print(f"   High: {report['summary']['severity_breakdown']['high']}")
        print(f"   Medium: {report['summary']['severity_breakdown']['medium']}")
        print(f"   Low: {report['summary']['severity_breakdown']['low']}")
        
        # Save report
        with open("swarm_security_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n📄 Report saved to swarm_security_report.json")
    
    else:
        print(f"❌ Failed to start monitoring {owner}/{repo}")

if __name__ == "__main__":
    asyncio.run(main())
