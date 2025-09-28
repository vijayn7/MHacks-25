"""
Test Runner - Executes generated test cases against target applications
"""

import asyncio
import json
import uuid
import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import requests
from playwright.async_api import async_playwright
import subprocess
import tempfile

logger = logging.getLogger(__name__)

class TestStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class TestResult:
    test_id: str
    test_name: str
    status: TestStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    findings: List[Dict[str, Any]] = None
    error: Optional[str] = None
    evidence: List[Dict[str, Any]] = None
    screenshots: List[str] = None
    logs: List[str] = None

class TestRunner:
    """
    Executes security test cases against target applications
    """
    
    def __init__(self, headless: bool = True, timeout: int = 30):
        self.headless = headless
        self.timeout = timeout
        self.results = []
        self.screenshots_dir = "test_screenshots"
        
        # Create screenshots directory
        os.makedirs(self.screenshots_dir, exist_ok=True)
    
    async def run_test_cases(self, test_cases: List[Dict[str, Any]], target_url: str) -> List[TestResult]:
        """
        Run a list of test cases against a target URL
        """
        logger.info(f"🚀 Starting execution of {len(test_cases)} test cases")
        
        results = []
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            
            try:
                for i, test_case in enumerate(test_cases):
                    logger.info(f"🧪 Executing test {i+1}/{len(test_cases)}: {test_case.get('name', 'Unknown')}")
                    
                    result = await self._execute_single_test(browser, test_case, target_url)
                    results.append(result)
                    
                    # Add delay between tests
                    if i < len(test_cases) - 1:
                        await asyncio.sleep(1)
            
            finally:
                await browser.close()
        
        self.results = results
        return results
    
    async def _execute_single_test(self, browser, test_case: Dict[str, Any], target_url: str) -> TestResult:
        """
        Execute a single test case
        """
        test_id = test_case.get("test_id", str(uuid.uuid4()))
        test_name = test_case.get("name", "Unknown Test")
        start_time = datetime.now()
        
        result = TestResult(
            test_id=test_id,
            test_name=test_name,
            status=TestStatus.PENDING,
            start_time=start_time,
            findings=[],
            evidence=[],
            screenshots=[],
            logs=[]
        )
        
        try:
            result.status = TestStatus.RUNNING
            
            # Create new page for this test
            page = await browser.new_page()
            
            # Set up page event listeners
            await self._setup_page_listeners(page, result)
            
            # Execute the test based on its type
            attack_type = test_case.get("attack_type", "general")
            
            if attack_type == "sql_injection":
                await self._execute_sql_injection_test(page, test_case, target_url, result)
            elif attack_type == "xss":
                await self._execute_xss_test(page, test_case, target_url, result)
            elif attack_type == "authentication":
                await self._execute_authentication_test(page, test_case, target_url, result)
            elif attack_type == "authorization":
                await self._execute_authorization_test(page, test_case, target_url, result)
            elif attack_type == "command_injection":
                await self._execute_command_injection_test(page, test_case, target_url, result)
            elif attack_type == "path_traversal":
                await self._execute_path_traversal_test(page, test_case, target_url, result)
            else:
                await self._execute_general_test(page, test_case, target_url, result)
            
            result.status = TestStatus.COMPLETED
            
        except Exception as e:
            logger.error(f"Test execution failed: {str(e)}")
            result.status = TestStatus.FAILED
            result.error = str(e)
        
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
            
            if 'page' in locals():
                await page.close()
        
        return result
    
    async def _setup_page_listeners(self, page, result: TestResult):
        """
        Set up page event listeners for logging and evidence collection
        """
        # Log console messages
        page.on("console", lambda msg: result.logs.append(f"Console: {msg.text}"))
        
        # Log page errors
        page.on("pageerror", lambda error: result.logs.append(f"Page Error: {error}"))
        
        # Log network requests
        page.on("request", lambda request: result.logs.append(f"Request: {request.method} {request.url}"))
        
        # Log network responses
        page.on("response", lambda response: result.logs.append(f"Response: {response.status} {response.url}"))
    
    async def _execute_sql_injection_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute SQL injection test
        """
        payloads = test_case.get("payloads", [])
        target_function = test_case.get("target_function", "")
        
        # Look for forms or input fields
        await page.goto(target_url)
        
        # Find input fields
        input_fields = await page.query_selector_all('input[type="text"], input[type="search"], textarea, input[name*="search"], input[name*="query"]')
        
        for input_field in input_fields:
            for payload in payloads:
                try:
                    # Clear and fill the input
                    await input_field.clear()
                    await input_field.fill(payload)
                    
                    # Submit the form
                    form = await input_field.query_selector('xpath=ancestor::form')
                    if form:
                        submit_button = await form.query_selector('button[type="submit"], input[type="submit"]')
                        if submit_button:
                            await submit_button.click()
                            
                            # Wait for response
                            await page.wait_for_timeout(2000)
                            
                            # Check for SQL injection indicators
                            content = await page.content()
                            
                            # Look for SQL error patterns
                            sql_error_patterns = [
                                "sql syntax", "mysql error", "postgresql error",
                                "sqlite error", "oracle error", "sql server error",
                                "database error", "query failed", "syntax error"
                            ]
                            
                            for pattern in sql_error_patterns:
                                if pattern.lower() in content.lower():
                                    finding = {
                                        "type": "sql_injection",
                                        "severity": "high",
                                        "description": f"SQL injection detected with payload: {payload}",
                                        "evidence": f"SQL error pattern '{pattern}' found in response",
                                        "payload": payload,
                                        "target_function": target_function,
                                        "code_snippet": test_case.get("code_snippet", "")
                                    }
                                    result.findings.append(finding)
                                    
                                    # Take screenshot
                                    screenshot_path = await self._take_screenshot(page, result.test_id, f"sql_injection_{len(result.findings)}")
                                    result.screenshots.append(screenshot_path)
                                    
                                    # Add evidence
                                    result.evidence.append({
                                        "type": "response_content",
                                        "content": content[:1000],
                                        "pattern_matched": pattern
                                    })
                                    break
                
                except Exception as e:
                    result.logs.append(f"SQL injection test error: {str(e)}")
    
    async def _execute_xss_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute XSS test
        """
        payloads = test_case.get("payloads", [])
        
        await page.goto(target_url)
        
        # Find input fields
        input_fields = await page.query_selector_all('input[type="text"], input[type="search"], textarea, input[name*="comment"], input[name*="message"]')
        
        for input_field in input_fields:
            for payload in payloads:
                try:
                    # Clear and fill the input
                    await input_field.clear()
                    await input_field.fill(payload)
                    
                    # Submit the form
                    form = await input_field.query_selector('xpath=ancestor::form')
                    if form:
                        submit_button = await form.query_selector('button[type="submit"], input[type="submit"]')
                        if submit_button:
                            await submit_button.click()
                            
                            # Wait for response
                            await page.wait_for_timeout(2000)
                            
                            # Check for XSS indicators
                            content = await page.content()
                            
                            # Look for XSS patterns
                            if "<script>" in content or "javascript:" in content or "onerror=" in content:
                                finding = {
                                    "type": "xss",
                                    "severity": "high",
                                    "description": f"XSS vulnerability detected with payload: {payload}",
                                    "evidence": f"XSS payload found in response",
                                    "payload": payload,
                                    "target_function": test_case.get("target_function", ""),
                                    "code_snippet": test_case.get("code_snippet", "")
                                }
                                result.findings.append(finding)
                                
                                # Take screenshot
                                screenshot_path = await self._take_screenshot(page, result.test_id, f"xss_{len(result.findings)}")
                                result.screenshots.append(screenshot_path)
                                
                                # Add evidence
                                result.evidence.append({
                                    "type": "response_content",
                                    "content": content[:1000],
                                    "payload_executed": payload
                                })
                
                except Exception as e:
                    result.logs.append(f"XSS test error: {str(e)}")
    
    async def _execute_authentication_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute authentication bypass test
        """
        payloads = test_case.get("payloads", [])
        
        # Navigate to login page
        login_url = f"{target_url}/login"
        await page.goto(login_url)
        
        # Find login form
        username_field = await page.query_selector('input[name="username"], input[name="email"], input[type="email"]')
        password_field = await page.query_selector('input[name="password"], input[type="password"]')
        
        if username_field and password_field:
            for payload in payloads:
                try:
                    # Fill username with payload
                    await username_field.clear()
                    await username_field.fill(payload)
                    
                    # Fill password with payload
                    await password_field.clear()
                    await password_field.fill(payload)
                    
                    # Submit form
                    submit_button = await page.query_selector('button[type="submit"], input[type="submit"]')
                    if submit_button:
                        await submit_button.click()
                        
                        # Wait for response
                        await page.wait_for_timeout(3000)
                        
                        # Check if login was successful
                        current_url = page.url
                        content = await page.content()
                        
                        # Look for success indicators
                        success_indicators = ["dashboard", "welcome", "profile", "admin", "success"]
                        
                        for indicator in success_indicators:
                            if indicator in current_url.lower() or indicator in content.lower():
                                finding = {
                                    "type": "authentication_bypass",
                                    "severity": "critical",
                                    "description": f"Authentication bypass detected with payload: {payload}",
                                    "evidence": f"Successfully logged in with payload, redirected to: {current_url}",
                                    "payload": payload,
                                    "target_function": test_case.get("target_function", ""),
                                    "code_snippet": test_case.get("code_snippet", "")
                                }
                                result.findings.append(finding)
                                
                                # Take screenshot
                                screenshot_path = await self._take_screenshot(page, result.test_id, f"auth_bypass_{len(result.findings)}")
                                result.screenshots.append(screenshot_path)
                                
                                # Add evidence
                                result.evidence.append({
                                    "type": "authentication_success",
                                    "payload": payload,
                                    "redirect_url": current_url,
                                    "content_preview": content[:500]
                                })
                                break
                
                except Exception as e:
                    result.logs.append(f"Authentication test error: {str(e)}")
    
    async def _execute_authorization_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute authorization bypass test
        """
        # Navigate to the target URL
        await page.goto(target_url)
        
        # Look for admin or protected functionality
        admin_links = await page.query_selector_all('a[href*="admin"], a[href*="manage"], a[href*="delete"], a[href*="edit"]')
        
        for link in admin_links:
            try:
                # Click the admin link
                await link.click()
                
                # Wait for response
                await page.wait_for_timeout(2000)
                
                # Check if we can access admin functionality
                current_url = page.url
                content = await page.content()
                
                # Look for access denied indicators
                access_denied_indicators = ["unauthorized", "forbidden", "access denied", "403", "401"]
                
                access_denied = any(indicator in content.lower() for indicator in access_denied_indicators)
                
                if not access_denied:
                    finding = {
                        "type": "authorization_bypass",
                        "severity": "high",
                        "description": f"Authorization bypass detected - able to access admin functionality",
                        "evidence": f"Successfully accessed admin link: {await link.get_attribute('href')}",
                        "target_function": test_case.get("target_function", ""),
                        "code_snippet": test_case.get("code_snippet", "")
                    }
                    result.findings.append(finding)
                    
                    # Take screenshot
                    screenshot_path = await self._take_screenshot(page, result.test_id, f"authz_bypass_{len(result.findings)}")
                    result.screenshots.append(screenshot_path)
                    
                    # Add evidence
                    result.evidence.append({
                        "type": "admin_access",
                        "admin_link": await link.get_attribute('href'),
                        "current_url": current_url,
                        "content_preview": content[:500]
                    })
            
            except Exception as e:
                result.logs.append(f"Authorization test error: {str(e)}")
    
    async def _execute_command_injection_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute command injection test
        """
        payloads = test_case.get("payloads", [])
        
        await page.goto(target_url)
        
        # Find input fields that might be vulnerable to command injection
        input_fields = await page.query_selector_all('input[type="text"], input[type="search"], textarea')
        
        for input_field in input_fields:
            for payload in payloads:
                try:
                    # Clear and fill the input
                    await input_field.clear()
                    await input_field.fill(payload)
                    
                    # Submit the form
                    form = await input_field.query_selector('xpath=ancestor::form')
                    if form:
                        submit_button = await form.query_selector('button[type="submit"], input[type="submit"]')
                        if submit_button:
                            await submit_button.click()
                            
                            # Wait for response
                            await page.wait_for_timeout(2000)
                            
                            # Check for command injection indicators
                            content = await page.content()
                            
                            # Look for command execution patterns
                            command_patterns = [
                                "command not found", "permission denied", "no such file",
                                "syntax error", "command failed", "execution error"
                            ]
                            
                            for pattern in command_patterns:
                                if pattern.lower() in content.lower():
                                    finding = {
                                        "type": "command_injection",
                                        "severity": "critical",
                                        "description": f"Command injection detected with payload: {payload}",
                                        "evidence": f"Command execution pattern '{pattern}' found in response",
                                        "payload": payload,
                                        "target_function": test_case.get("target_function", ""),
                                        "code_snippet": test_case.get("code_snippet", "")
                                    }
                                    result.findings.append(finding)
                                    
                                    # Take screenshot
                                    screenshot_path = await self._take_screenshot(page, result.test_id, f"cmd_injection_{len(result.findings)}")
                                    result.screenshots.append(screenshot_path)
                                    
                                    # Add evidence
                                    result.evidence.append({
                                        "type": "response_content",
                                        "content": content[:1000],
                                        "pattern_matched": pattern
                                    })
                                    break
                
                except Exception as e:
                    result.logs.append(f"Command injection test error: {str(e)}")
    
    async def _execute_path_traversal_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute path traversal test
        """
        payloads = test_case.get("payloads", [])
        
        # Test common path traversal endpoints
        endpoints = [
            f"{target_url}/file",
            f"{target_url}/download",
            f"{target_url}/view",
            f"{target_url}/read",
            f"{target_url}/api/file"
        ]
        
        for endpoint in endpoints:
            for payload in payloads:
                try:
                    # Try to access the file with payload
                    test_url = f"{endpoint}?file={payload}"
                    response = await page.goto(test_url)
                    
                    if response and response.status == 200:
                        content = await page.content()
                        
                        # Look for file content indicators
                        file_indicators = [
                            "root:", "etc/passwd", "boot.ini", "windows/system32",
                            "file not found", "access denied", "permission denied"
                        ]
                        
                        for indicator in file_indicators:
                            if indicator.lower() in content.lower():
                                finding = {
                                    "type": "path_traversal",
                                    "severity": "high",
                                    "description": f"Path traversal detected with payload: {payload}",
                                    "evidence": f"File system indicator '{indicator}' found in response",
                                    "payload": payload,
                                    "target_function": test_case.get("target_function", ""),
                                    "code_snippet": test_case.get("code_snippet", "")
                                }
                                result.findings.append(finding)
                                
                                # Take screenshot
                                screenshot_path = await self._take_screenshot(page, result.test_id, f"path_traversal_{len(result.findings)}")
                                result.screenshots.append(screenshot_path)
                                
                                # Add evidence
                                result.evidence.append({
                                    "type": "response_content",
                                    "content": content[:1000],
                                    "pattern_matched": indicator
                                })
                                break
                
                except Exception as e:
                    result.logs.append(f"Path traversal test error: {str(e)}")
    
    async def _execute_general_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute general security test
        """
        try:
            # Navigate to target
            await page.goto(target_url)
            
            # Check for common security issues
            await self._check_security_headers(page, result)
            await self._check_sensitive_data_exposure(page, result)
            await self._check_error_messages(page, result)
        
        except Exception as e:
            result.logs.append(f"General test error: {str(e)}")
    
    async def _check_security_headers(self, page, result: TestResult):
        """
        Check for missing security headers
        """
        try:
            response = await page.goto(page.url)
            headers = response.headers if response else {}
            
            required_headers = {
                'X-Frame-Options': 'Prevents clickjacking',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'X-XSS-Protection': 'Enables XSS filtering',
                'Strict-Transport-Security': 'Enforces HTTPS',
                'Content-Security-Policy': 'Prevents XSS and data injection'
            }
            
            for header, description in required_headers.items():
                if header not in headers:
                    finding = {
                        "type": "missing_security_header",
                        "severity": "medium",
                        "description": f"Missing {header} header",
                        "evidence": f"{header} header not present in response",
                        "recommendation": f"Add {header} header: {description}"
                    }
                    result.findings.append(finding)
        
        except Exception as e:
            result.logs.append(f"Security header check error: {str(e)}")
    
    async def _check_sensitive_data_exposure(self, page, result: TestResult):
        """
        Check for sensitive data exposure
        """
        try:
            content = await page.content()
            
            sensitive_patterns = [
                r'password["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'secret["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'token["\']?\s*[:=]\s*["\'][^"\']+["\']'
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    finding = {
                        "type": "sensitive_data_exposure",
                        "severity": "high",
                        "description": "Sensitive data exposed in page content",
                        "evidence": f"Pattern '{pattern}' found in response",
                        "recommendation": "Remove or mask sensitive data in client-side code"
                    }
                    result.findings.append(finding)
        
        except Exception as e:
            result.logs.append(f"Sensitive data exposure check error: {str(e)}")
    
    async def _check_error_messages(self, page, result: TestResult):
        """
        Check for information disclosure in error messages
        """
        try:
            # Try to trigger error conditions
            error_urls = [
                f"{page.url}/nonexistent",
                f"{page.url}/api/invalid",
                f"{page.url}/admin/forbidden"
            ]
            
            for error_url in error_urls:
                try:
                    response = await page.goto(error_url)
                    if response and response.status >= 400:
                        content = await page.content()
                        
                        # Check for sensitive information in error messages
                        sensitive_patterns = [
                            "stack trace", "file path", "database error",
                            "sql error", "password", "secret", "key"
                        ]
                        
                        for pattern in sensitive_patterns:
                            if pattern.lower() in content.lower():
                                finding = {
                                    "type": "information_disclosure",
                                    "severity": "low",
                                    "description": "Sensitive information in error message",
                                    "evidence": f"Error message contains: {pattern}",
                                    "url": error_url
                                }
                                result.findings.append(finding)
                
                except Exception as e:
                    result.logs.append(f"Error message check error for {error_url}: {str(e)}")
    
    async def _take_screenshot(self, page, test_id: str, name: str) -> str:
        """
        Take a screenshot of the current page
        """
        try:
            screenshot_path = f"{self.screenshots_dir}/{test_id}_{name}.png"
            await page.screenshot(path=screenshot_path)
            return screenshot_path
        except Exception as e:
            logger.warning(f"Screenshot failed: {str(e)}")
            return ""
    
    def generate_report(self, results: List[TestResult]) -> Dict[str, Any]:
        """
        Generate a comprehensive test report
        """
        total_tests = len(results)
        completed_tests = len([r for r in results if r.status == TestStatus.COMPLETED])
        failed_tests = len([r for r in results if r.status == TestStatus.FAILED])
        total_findings = sum(len(r.findings) for r in results)
        
        # Categorize findings by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for result in results:
            for finding in result.findings:
                severity = finding.get("severity", "medium")
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Calculate risk score
        risk_score = (
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 7 +
            severity_counts["medium"] * 4 +
            severity_counts["low"] * 1
        )
        
        # Get top findings
        all_findings = []
        for result in results:
            for finding in result.findings:
                finding["test_name"] = result.test_name
                finding["test_id"] = result.test_id
                all_findings.append(finding)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "medium"), 2))
        
        report = {
            "summary": {
                "total_tests": total_tests,
                "completed_tests": completed_tests,
                "failed_tests": failed_tests,
                "success_rate": f"{(completed_tests / total_tests * 100):.1f}%" if total_tests > 0 else "0%",
                "total_findings": total_findings,
                "risk_score": risk_score
            },
            "severity_breakdown": severity_counts,
            "top_findings": all_findings[:10],  # Top 10 findings
            "test_results": [
                {
                    "test_id": r.test_id,
                    "test_name": r.test_name,
                    "status": r.status.value,
                    "duration": r.duration,
                    "findings_count": len(r.findings),
                    "error": r.error
                }
                for r in results
            ],
            "generated_at": datetime.now().isoformat()
        }
        
        return report

# Example usage
async def main():
    """
    Example usage of the Test Runner
    """
    # Sample test cases
    test_cases = [
        {
            "test_id": "test_1",
            "name": "SQL Injection Test",
            "attack_type": "sql_injection",
            "payloads": ["' OR '1'='1", "'; DROP TABLE users; --"],
            "target_function": "search_users",
            "target_file": "src/controllers/UserController.js"
        },
        {
            "test_id": "test_2",
            "name": "XSS Test",
            "attack_type": "xss",
            "payloads": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
            "target_function": "add_comment",
            "target_file": "src/controllers/CommentController.js"
        }
    ]
    
    # Initialize the test runner
    runner = TestRunner(headless=True)
    
    # Run tests
    print("🚀 Starting test execution...")
    results = await runner.run_test_cases(test_cases, "https://httpbin.org")
    
    # Generate report
    report = runner.generate_report(results)
    
    # Print summary
    print(f"\n📊 Test Execution Summary")
    print(f"Total Tests: {report['summary']['total_tests']}")
    print(f"Completed: {report['summary']['completed_tests']}")
    print(f"Failed: {report['summary']['failed_tests']}")
    print(f"Success Rate: {report['summary']['success_rate']}")
    print(f"Total Findings: {report['summary']['total_findings']}")
    print(f"Risk Score: {report['summary']['risk_score']}")
    
    # Print findings
    if report['top_findings']:
        print(f"\n🔍 Top Findings:")
        for i, finding in enumerate(report['top_findings'], 1):
            print(f"  {i}. {finding['description']} (Severity: {finding['severity']})")
    
    # Save report
    with open("test_execution_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n📄 Report saved to test_execution_report.json")

if __name__ == "__main__":
    asyncio.run(main())
