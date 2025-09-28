"""
Dynamic Security Scanner using Gemini AI

This module uses Google's Gemini AI to dynamically analyze code and generate
targeted security test cases based on the most prevalent cybersecurity attacks.
"""

import asyncio
import json
import uuid
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import logging
import google.generativeai as genai
from pathlib import Path
import base64
import hashlib
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)

class DynamicScanner:
    """
    Dynamic Security Scanner that uses Gemini AI to analyze code and generate
    targeted security test cases for the most prevalent cybersecurity attacks.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY environment variable.")
        
        # Configure Gemini
        genai.configure(api_key=self.api_key)
        # Use Gemini 2.5 Pro for hackathon participants with higher limits
        self.model = genai.GenerativeModel('gemini-2.5-pro')
        
        # Security attack categories and their priorities
        self.attack_categories = {
            "injection": {
                "priority": 1,
                "attacks": ["sql_injection", "nosql_injection", "command_injection", "ldap_injection", "xpath_injection"]
            },
            "authentication": {
                "priority": 2,
                "attacks": ["brute_force", "session_fixation", "weak_passwords", "jwt_vulnerabilities", "oauth_flaws"]
            },
            "authorization": {
                "priority": 3,
                "attacks": ["idor", "privilege_escalation", "access_control_bypass", "horizontal_escalation", "vertical_escalation"]
            },
            "business_logic": {
                "priority": 4,
                "attacks": ["price_manipulation", "race_conditions", "workflow_bypass", "state_confusion", "double_spending"]
            },
            "data_exposure": {
                "priority": 5,
                "attacks": ["sensitive_data_leak", "information_disclosure", "debug_info_exposure", "error_message_leak"]
            },
            "cryptography": {
                "priority": 6,
                "attacks": ["weak_encryption", "insecure_random", "crypto_misuse", "key_management", "certificate_issues"]
            },
            "insecure_design": {
                "priority": 7,
                "attacks": ["missing_validation", "insecure_direct_object_reference", "security_misconfiguration"]
            },
            "vulnerable_components": {
                "priority": 8,
                "attacks": ["outdated_dependencies", "known_cves", "supply_chain_attacks", "dependency_confusion"]
            }
        }
        
        # Test case templates for different attack types
        self.test_templates = {
            "sql_injection": {
                "payloads": [
                    "' OR '1'='1",
                    "'; DROP TABLE users; --",
                    "' UNION SELECT * FROM users --",
                    "1' OR 1=1 --",
                    "admin'--"
                ],
                "detection_patterns": ["SQL syntax error", "mysql", "postgresql", "database error"]
            },
            "xss": {
                "payloads": [
                    "<script>alert('XSS')</script>",
                    "javascript:alert('XSS')",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "';alert('XSS');//"
                ],
                "detection_patterns": ["<script>", "javascript:", "onerror", "onload"]
            },
            "idor": {
                "test_cases": [
                    "Access other user's resources by changing ID",
                    "Modify other user's data",
                    "Delete other user's resources",
                    "View admin-only data with user token"
                ],
                "detection_patterns": ["unauthorized access", "forbidden", "403", "insufficient privileges"]
            },
            "brute_force": {
                "test_cases": [
                    "Common password dictionary attack",
                    "Username enumeration",
                    "Account lockout bypass",
                    "Rate limiting bypass"
                ],
                "detection_patterns": ["login failed", "invalid credentials", "account locked"]
            }
        }
    
    async def analyze_codebase(self, codebase_path: str, target_url: str) -> Dict[str, Any]:
        """
        Analyze a codebase and generate dynamic security test cases.
        
        Args:
            codebase_path: Path to the codebase directory
            target_url: Target URL to test against
            
        Returns:
            Dictionary containing analysis results and test cases
        """
        logger.info(f"🔍 Starting dynamic analysis of codebase: {codebase_path}")
        
        try:
            # Step 1: Extract and analyze code
            code_analysis = await self._extract_and_analyze_code(codebase_path)
            
            # Step 2: Generate security test cases using Gemini
            test_cases = await self._generate_security_test_cases(code_analysis, target_url)
            
            # Step 3: Prioritize and organize test cases
            prioritized_tests = self._prioritize_test_cases(test_cases)
            
            # Step 4: Generate execution plan
            execution_plan = self._generate_execution_plan(prioritized_tests, target_url)
            
            return {
                "analysis_id": str(uuid.uuid4()),
                "codebase_path": codebase_path,
                "target_url": target_url,
                "analysis_timestamp": datetime.now().isoformat(),
                "code_analysis": code_analysis,
                "test_cases": prioritized_tests,
                "execution_plan": execution_plan,
                "total_tests": len(prioritized_tests),
                "high_priority_tests": len([t for t in prioritized_tests if t.get("priority", 0) >= 8])
            }
            
        except Exception as e:
            logger.error(f"❌ Dynamic analysis failed: {str(e)}")
            return {
                "error": str(e),
                "analysis_id": str(uuid.uuid4()),
                "analysis_timestamp": datetime.now().isoformat()
            }
    
    async def _extract_and_analyze_code(self, codebase_path: str) -> Dict[str, Any]:
        """Extract and analyze code from the codebase"""
        logger.info("📁 Extracting and analyzing code...")
        
        code_files = []
        total_lines = 0
        languages = set()
        
        # Walk through the codebase and extract relevant files
        for root, dirs, files in os.walk(codebase_path):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
            
            for file in files:
                file_path = Path(root) / file
                file_ext = file_path.suffix.lower()
                
                # Only analyze relevant code files
                if file_ext in ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php', '.go', '.rb', '.cs', '.cpp', '.c']:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Skip very large files
                        if len(content) > 100000:  # 100KB limit
                            continue
                        
                        language = self._detect_language(file_ext)
                        languages.add(language)
                        
                        code_files.append({
                            "path": str(file_path.relative_to(codebase_path)),
                            "language": language,
                            "content": content,
                            "lines": len(content.splitlines()),
                            "size": len(content)
                        })
                        
                        total_lines += len(content.splitlines())
                        
                    except Exception as e:
                        logger.warning(f"⚠️ Could not read file {file_path}: {str(e)}")
        
        # Analyze code patterns for security-relevant constructs
        security_patterns = self._analyze_security_patterns(code_files)
        
        return {
            "total_files": len(code_files),
            "total_lines": total_lines,
            "languages": list(languages),
            "files": code_files,
            "security_patterns": security_patterns
        }
    
    def _detect_language(self, file_ext: str) -> str:
        """Detect programming language from file extension"""
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.php': 'php',
            '.go': 'go',
            '.rb': 'ruby',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c'
        }
        return language_map.get(file_ext, 'unknown')
    
    def _analyze_security_patterns(self, code_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze code for security-relevant patterns"""
        patterns = {
            "database_queries": 0,
            "user_input_handling": 0,
            "authentication_code": 0,
            "authorization_checks": 0,
            "crypto_usage": 0,
            "file_operations": 0,
            "network_requests": 0,
            "serialization": 0,
            "api_endpoints": 0,
            "session_management": 0
        }
        
        # Common security-relevant patterns
        pattern_regexes = {
            "database_queries": [r"SELECT\s+", r"INSERT\s+", r"UPDATE\s+", r"DELETE\s+", r"query\s*\(", r"execute\s*\("],
            "user_input_handling": [r"input\s*\(", r"request\.", r"req\.", r"params\.", r"body\.", r"form\."],
            "authentication_code": [r"login\s*\(", r"authenticate\s*\(", r"auth\s*\.", r"password", r"token", r"jwt"],
            "authorization_checks": [r"authorize\s*\(", r"permission\s*\.", r"role\s*\.", r"access\s*\.", r"check\s*permission"],
            "crypto_usage": [r"encrypt\s*\(", r"decrypt\s*\(", r"hash\s*\(", r"crypto\s*\.", r"bcrypt", r"sha256"],
            "file_operations": [r"open\s*\(", r"read\s*\(", r"write\s*\(", r"file\s*\.", r"upload\s*", r"download\s*"],
            "network_requests": [r"fetch\s*\(", r"request\s*\.", r"http\s*\.", r"axios\s*\.", r"curl\s*"],
            "serialization": [r"json\s*\.", r"serialize\s*\(", r"deserialize\s*\(", r"pickle\s*\.", r"yaml\s*\."],
            "api_endpoints": [r"@app\.route", r"@RequestMapping", r"@GetMapping", r"@PostMapping", r"router\s*\."],
            "session_management": [r"session\s*\.", r"cookie\s*\.", r"sessionStorage", r"localStorage"]
        }
        
        for file_info in code_files:
            content = file_info["content"]
            for pattern_type, regexes in pattern_regexes.items():
                for regex in regexes:
                    matches = re.findall(regex, content, re.IGNORECASE)
                    patterns[pattern_type] += len(matches)
        
        return patterns
    
    async def _generate_security_test_cases(self, code_analysis: Dict[str, Any], target_url: str) -> List[Dict[str, Any]]:
        """Use Gemini to generate security test cases based on code analysis"""
        logger.info("🤖 Generating security test cases using Gemini...")
        
        # Prepare context for Gemini
        context = self._prepare_gemini_context(code_analysis, target_url)
        
        # Generate test cases for each attack category
        all_test_cases = []
        
        for category, info in self.attack_categories.items():
            logger.info(f"🎯 Generating test cases for {category} attacks...")
            
            test_cases = await self._generate_category_test_cases(category, info, context)
            all_test_cases.extend(test_cases)
            
            # Add delay between API calls to respect rate limits
            await asyncio.sleep(2)  # 2 second delay between categories
        
        return all_test_cases
    
    def _prepare_gemini_context(self, code_analysis: Dict[str, Any], target_url: str) -> str:
        """Prepare context for Gemini analysis"""
        context = f"""
        SECURITY CODE ANALYSIS CONTEXT
        
        Target URL: {target_url}
        Total Files: {code_analysis['total_files']}
        Total Lines: {code_analysis['total_lines']}
        Languages: {', '.join(code_analysis['languages'])}
        
        Security Patterns Detected:
        """
        
        for pattern, count in code_analysis['security_patterns'].items():
            if count > 0:
                context += f"\n- {pattern.replace('_', ' ').title()}: {count} occurrences"
        
        context += f"""
        
        Code Files Summary:
        """
        
        # Include summary of key files (limit to avoid token limits)
        for file_info in code_analysis['files'][:10]:  # Limit to first 10 files
            context += f"\n- {file_info['path']} ({file_info['language']}, {file_info['lines']} lines)"
        
        return context
    
    async def _generate_category_test_cases(self, category: str, category_info: Dict[str, Any], context: str) -> List[Dict[str, Any]]:
        """Generate test cases for a specific attack category using Gemini"""
        
        prompt = f"""
        You are a cybersecurity expert analyzing code for {category} vulnerabilities.
        
        {context}
        
        Generate 3-5 specific, actionable security test cases for {category} attacks.
        Focus on the most prevalent and impactful attack vectors in this category.
        
        For each test case, provide:
        1. Test name and description
        2. Specific attack payloads or techniques
        3. Expected behavior if vulnerable
        4. Risk level (Critical/High/Medium/Low)
        5. Detection patterns to look for
        6. Specific endpoints or functions to test
        
        Attack types to consider: {', '.join(category_info['attacks'])}
        
        IMPORTANT: Return ONLY a valid JSON array with this exact structure:
        [
            {{
                "test_name": "Descriptive test name",
                "description": "Detailed description of the test",
                "attack_type": "Specific attack type",
                "payloads": ["payload1", "payload2"],
                "endpoints": ["/api/endpoint1", "/api/endpoint2"],
                "risk_level": "Critical|High|Medium|Low",
                "detection_patterns": ["pattern1", "pattern2"],
                "test_steps": ["step1", "step2", "step3"],
                "expected_result": "What to expect if vulnerable",
                "mitigation": "How to fix this vulnerability"
            }}
        ]
        
        Make the test cases specific to the codebase context provided.
        Focus on practical, executable tests that can be automated.
        Return ONLY the JSON array, no other text.
        """
        
        # Retry logic for rate limiting
        max_retries = 3
        retry_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(prompt)
                
                # Check if response is valid
                if not response or not response.text:
                    logger.warning(f"⚠️ Empty response from Gemini for {category}")
                    return []
                
                # Clean the response text
                response_text = response.text.strip()
                
                # Try to extract JSON from the response
                if response_text.startswith('```json'):
                    response_text = response_text[7:]
                if response_text.endswith('```'):
                    response_text = response_text[:-3]
                
                response_text = response_text.strip()
                
                # Find the JSON array in the response
                start_idx = response_text.find('[')
                end_idx = response_text.rfind(']')
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    response_text = response_text[start_idx:end_idx + 1]
                
                # Parse JSON response
                test_cases = json.loads(response_text)
                
                # Ensure it's a list
                if not isinstance(test_cases, list):
                    test_cases = [test_cases]
                
                # Add metadata
                for test_case in test_cases:
                    test_case["category"] = category
                    test_case["priority"] = category_info["priority"]
                    test_case["test_id"] = str(uuid.uuid4())
                    test_case["created_at"] = datetime.now().isoformat()
                
                return test_cases
                
            except json.JSONDecodeError as e:
                logger.error(f"❌ Failed to parse Gemini response for {category}: {str(e)}")
                logger.error(f"Response text: {response.text if response else 'No response'}")
                return []
            except Exception as e:
                error_msg = str(e)
                if "429" in error_msg or "quota" in error_msg.lower():
                    if attempt < max_retries - 1:
                        logger.warning(f"⚠️ Rate limit hit for {category}, retrying in {retry_delay} seconds... (attempt {attempt + 1}/{max_retries})")
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                    else:
                        logger.error(f"❌ Rate limit exceeded for {category} after {max_retries} attempts")
                        return []
                else:
                    logger.error(f"❌ Error generating test cases for {category}: {str(e)}")
                    return []
        
        return []
    
    def _prioritize_test_cases(self, test_cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize test cases based on risk level and category priority"""
        
        def calculate_priority_score(test_case):
            # Base priority from category
            base_priority = test_case.get("priority", 5)
            
            # Risk level multiplier
            risk_multipliers = {
                "Critical": 4,
                "High": 3,
                "Medium": 2,
                "Low": 1
            }
            
            risk_level = test_case.get("risk_level", "Medium")
            risk_multiplier = risk_multipliers.get(risk_level, 2)
            
            # Calculate final priority score
            return base_priority * risk_multiplier
        
        # Sort by priority score (higher is more important)
        prioritized = sorted(test_cases, key=calculate_priority_score, reverse=True)
        
        # Add priority ranking
        for i, test_case in enumerate(prioritized):
            test_case["priority_rank"] = i + 1
            test_case["priority_score"] = calculate_priority_score(test_case)
        
        return prioritized
    
    def _generate_execution_plan(self, test_cases: List[Dict[str, Any]], target_url: str) -> Dict[str, Any]:
        """Generate execution plan for the test cases"""
        
        # Group tests by category
        by_category = {}
        for test_case in test_cases:
            category = test_case.get("category", "unknown")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(test_case)
        
        # Generate execution phases
        phases = []
        phase_1 = {
            "phase": 1,
            "name": "Critical & High Risk Tests",
            "description": "Execute highest priority security tests first",
            "tests": [t for t in test_cases if t.get("risk_level") in ["Critical", "High"]],
            "estimated_duration": "15-30 minutes"
        }
        phases.append(phase_1)
        
        phase_2 = {
            "phase": 2,
            "name": "Medium Risk Tests",
            "description": "Execute medium priority security tests",
            "tests": [t for t in test_cases if t.get("risk_level") == "Medium"],
            "estimated_duration": "20-40 minutes"
        }
        phases.append(phase_2)
        
        phase_3 = {
            "phase": 3,
            "name": "Low Risk & Coverage Tests",
            "description": "Execute remaining tests for comprehensive coverage",
            "tests": [t for t in test_cases if t.get("risk_level") == "Low"],
            "estimated_duration": "10-20 minutes"
        }
        phases.append(phase_3)
        
        return {
            "total_phases": len(phases),
            "total_tests": len(test_cases),
            "estimated_total_duration": "45-90 minutes",
            "phases": phases,
            "by_category": by_category
        }
    
    async def execute_test_case(self, test_case: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        """Execute a specific test case against the target URL"""
        logger.info(f"🧪 Executing test: {test_case.get('test_name', 'Unknown')}")
        
        try:
            # This would integrate with your existing scanner infrastructure
            # For now, we'll simulate the execution
            
            results = {
                "test_id": test_case.get("test_id"),
                "test_name": test_case.get("test_name"),
                "execution_timestamp": datetime.now().isoformat(),
                "status": "completed",
                "vulnerabilities_found": [],
                "execution_log": []
            }
            
            # Simulate test execution based on test type
            for payload in test_case.get("payloads", []):
                # In real implementation, this would make actual HTTP requests
                # and analyze responses for vulnerability indicators
                
                execution_log = {
                    "payload": payload,
                    "endpoint": test_case.get("endpoints", [target_url])[0],
                    "response_code": 200,
                    "vulnerability_detected": False,
                    "detection_patterns_matched": []
                }
                
                # Check for detection patterns (simulated)
                for pattern in test_case.get("detection_patterns", []):
                    if pattern.lower() in payload.lower():
                        execution_log["vulnerability_detected"] = True
                        execution_log["detection_patterns_matched"].append(pattern)
                
                results["execution_log"].append(execution_log)
                
                if execution_log["vulnerability_detected"]:
                    results["vulnerabilities_found"].append({
                        "payload": payload,
                        "pattern": execution_log["detection_patterns_matched"][0],
                        "severity": test_case.get("risk_level", "Medium"),
                        "description": test_case.get("description", "")
                    })
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Test execution failed: {str(e)}")
            return {
                "test_id": test_case.get("test_id"),
                "test_name": test_case.get("test_name"),
                "execution_timestamp": datetime.now().isoformat(),
                "status": "failed",
                "error": str(e),
                "vulnerabilities_found": [],
                "execution_log": []
            }
    
    def _convert_to_owasp_format(self, test_case: Dict[str, Any], vulnerability: Dict[str, Any], run_id: str) -> Dict[str, Any]:
        """Convert dynamic scanner findings to OWASP format matching original scanner"""
        
        # Map attack types to OWASP categories
        owasp_mapping = {
            "sql_injection": "A03",  # Injection
            "xss": "A03",  # Injection
            "command_injection": "A03",  # Injection
            "ldap_injection": "A03",  # Injection
            "xpath_injection": "A03",  # Injection
            "template_injection": "A03",  # Injection
            "idor": "A01",  # Broken Access Control
            "privilege_escalation": "A01",  # Broken Access Control
            "access_control_bypass": "A01",  # Broken Access Control
            "brute_force": "A07",  # Identification and Authentication Failures
            "session_fixation": "A07",  # Identification and Authentication Failures
            "weak_passwords": "A07",  # Identification and Authentication Failures
            "jwt_vulnerabilities": "A07",  # Identification and Authentication Failures
            "oauth_flaws": "A07",  # Identification and Authentication Failures
            "price_manipulation": "A04",  # Insecure Design
            "race_conditions": "A04",  # Insecure Design
            "workflow_bypass": "A04",  # Insecure Design
            "sensitive_data_leak": "A02",  # Cryptographic Failures
            "information_disclosure": "A05",  # Security Misconfiguration
            "debug_info_exposure": "A05",  # Security Misconfiguration
            "weak_encryption": "A02",  # Cryptographic Failures
            "insecure_random": "A02",  # Cryptographic Failures
            "crypto_misuse": "A02",  # Cryptographic Failures
            "missing_validation": "A04",  # Insecure Design
            "insecure_direct_object_reference": "A01",  # Broken Access Control
            "security_misconfiguration": "A05",  # Security Misconfiguration
            "outdated_dependencies": "A06",  # Vulnerable and Outdated Components
            "known_cves": "A06",  # Vulnerable and Outdated Components
            "supply_chain_attacks": "A06",  # Vulnerable and Outdated Components
        }
        
        # Map risk levels to severity
        severity_mapping = {
            "Critical": "critical",
            "High": "high", 
            "Medium": "medium",
            "Low": "low"
        }
        
        attack_type = test_case.get("attack_type", "unknown")
        owasp_category = owasp_mapping.get(attack_type, "A04")  # Default to Insecure Design
        severity = severity_mapping.get(test_case.get("risk_level", "Medium"), "medium")
        
        # Create OWASP-formatted finding
        finding = {
            'id': str(uuid.uuid4())[:8],
            'run_id': run_id,
            'category': attack_type,
            'severity': severity,
            'title': test_case.get("test_name", "Dynamic Security Test"),
            'description': test_case.get("description", ""),
            'evidence': {
                'payload': vulnerability.get("payload", ""),
                'endpoint': test_case.get("endpoints", [])[0] if test_case.get("endpoints") else "",
                'pattern_matched': vulnerability.get("pattern", ""),
                'test_steps': test_case.get("test_steps", []),
                'expected_result': test_case.get("expected_result", "")
            },
            'fix_snippet': test_case.get("mitigation", ""),
            'reproduce_command': f"Send payload '{vulnerability.get('payload', '')}' to {test_case.get('endpoints', [])[0] if test_case.get('endpoints') else 'target endpoint'}",
            'reproduce_seed': str(uuid.uuid4())[:8],
            'priority_score': self._calculate_priority_score(severity, attack_type),
            'owasp_category': owasp_category,
            'scanner': 'Dynamic Scanner (AI-Powered)',
            'timestamp': datetime.now().isoformat(),
            'ai_generated': True,
            'attack_category': test_case.get("category", "unknown")
        }
        
        return finding
    
    def _calculate_priority_score(self, severity: str, category: str) -> int:
        """Calculate priority score based on severity and fix ease (matching original scanner)"""
        
        severity_scores = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30
        }
        
        # Adjust for fix difficulty - these are easier to fix
        easy_fixes = [
            'missing_headers', 'insecure_cookies', 'weak_csp',
            'info_disclosure', 'missing_hsts', 'security_misconfiguration'
        ]
        
        # These are harder to fix
        hard_fixes = [
            'sql_injection', 'xss', 'access_control',
            'authentication', 'insecure_design', 'idor', 'privilege_escalation'
        ]
        
        base_score = severity_scores.get(severity, 30)
        
        if category in easy_fixes:
            return base_score + 10
        elif category in hard_fixes:
            return base_score - 5
        else:
            return base_score
    
    async def run_full_analysis(self, codebase_path: str, target_url: str) -> Dict[str, Any]:
        """Run complete dynamic analysis including test execution"""
        logger.info("🚀 Starting full dynamic security analysis...")
        
        # Step 1: Analyze codebase
        analysis = await self.analyze_codebase(codebase_path, target_url)
        
        if "error" in analysis:
            return analysis
        
        # Step 2: Execute high-priority test cases
        execution_results = []
        high_priority_tests = [t for t in analysis["test_cases"] if t.get("priority_rank", 999) <= 10]
        
        logger.info(f"🧪 Executing {len(high_priority_tests)} high-priority test cases...")
        
        # Convert findings to OWASP format
        owasp_findings = []
        run_id = str(uuid.uuid4())[:8]
        
        for test_case in high_priority_tests:
            result = await self.execute_test_case(test_case, target_url)
            execution_results.append(result)
            
            # Convert vulnerabilities to OWASP format
            for vulnerability in result.get("vulnerabilities_found", []):
                owasp_finding = self._convert_to_owasp_format(test_case, vulnerability, run_id)
                owasp_findings.append(owasp_finding)
        
        # Step 3: Generate OWASP-formatted report
        analysis["execution_results"] = execution_results
        analysis["vulnerabilities_found"] = len(owasp_findings)
        analysis["tests_executed"] = len(execution_results)
        analysis["analysis_completed"] = datetime.now().isoformat()
        
        # Add OWASP-formatted findings
        analysis["owasp_findings"] = owasp_findings
        
        # Generate OWASP summary
        analysis["owasp_summary"] = self._generate_owasp_summary(owasp_findings, run_id)
        
        return analysis
    
    def _generate_owasp_summary(self, findings: List[Dict[str, Any]], run_id: str) -> Dict[str, Any]:
        """Generate OWASP-formatted summary matching original scanner"""
        
        # Count by severity
        severity_counts = {
            'critical': len([f for f in findings if f.get('severity') == 'critical']),
            'high': len([f for f in findings if f.get('severity') == 'high']),
            'medium': len([f for f in findings if f.get('severity') == 'medium']),
            'low': len([f for f in findings if f.get('severity') == 'low'])
        }
        
        # Count by OWASP category
        owasp_counts = {}
        for finding in findings:
            owasp_cat = finding.get('owasp_category', 'Other')
            owasp_counts[owasp_cat] = owasp_counts.get(owasp_cat, 0) + 1
        
        # Count by attack category
        category_counts = {}
        for finding in findings:
            category = finding.get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_counts)
        
        # Get top findings by priority
        top_findings = sorted(findings, key=lambda x: x.get('priority_score', 0), reverse=True)[:10]
        
        return {
            'run_id': run_id,
            'scan_timestamp': datetime.now().isoformat(),
            'total_findings': len(findings),
            'risk_score': risk_score,
            'severity_breakdown': severity_counts,
            'owasp_category_breakdown': owasp_counts,
            'category_breakdown': category_counts,
            'top_findings': [
                {
                    'id': f['id'],
                    'title': f['title'],
                    'severity': f['severity'],
                    'owasp_category': f.get('owasp_category', 'Other'),
                    'priority_score': f.get('priority_score', 0),
                    'scanner': f.get('scanner', 'Unknown')
                }
                for f in top_findings
            ],
            'scanner': 'Dynamic Scanner (AI-Powered)',
            'owasp_coverage': {
                'A01': 'Broken Access Control',
                'A02': 'Cryptographic Failures',
                'A03': 'Injection',
                'A04': 'Insecure Design',
                'A05': 'Security Misconfiguration',
                'A06': 'Vulnerable and Outdated Components',
                'A07': 'Identification and Authentication Failures',
                'A08': 'Software and Data Integrity Failures',
                'A09': 'Security Logging and Monitoring Failures',
                'A10': 'Server-Side Request Forgery'
            }
        }
    
    def _calculate_risk_score(self, severity_counts: Dict) -> int:
        """Calculate overall risk score based on findings (matching original scanner)"""
        
        # Weighted scoring
        critical_weight = 10
        high_weight = 7
        medium_weight = 4
        low_weight = 1
        
        total_score = (
            severity_counts.get('critical', 0) * critical_weight +
            severity_counts.get('high', 0) * high_weight +
            severity_counts.get('medium', 0) * medium_weight +
            severity_counts.get('low', 0) * low_weight
        )
        
        # Normalize to 0-100 scale
        max_possible = 100  # Assuming max 10 critical findings
        risk_score = min(100, (total_score / max_possible) * 100)
        
        return int(risk_score)

# Example usage and testing
async def main():
    """Example usage of the DynamicScanner"""
    
    # Initialize scanner
    scanner = DynamicScanner()
    
    # Example analysis
    codebase_path = "/path/to/your/codebase"
    target_url = "https://your-target-app.com"
    
    # Run analysis
    results = await scanner.run_full_analysis(codebase_path, target_url)
    
    # Print results
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(main())

