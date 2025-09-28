"""
Configuration for Dynamic Scanner

This module contains configuration settings for the Gemini-powered dynamic scanner.
"""

import os
from typing import Dict, List, Any

class DynamicScannerConfig:
    """Configuration class for the dynamic scanner"""
    
    # Gemini API Configuration
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    GEMINI_MODEL = "gemini-2.5-pro"  # Using Pro version for hackathon participants
    MAX_TOKENS = 2000000  # 2M token limit for Gemini
    
    # File Analysis Configuration
    MAX_FILE_SIZE = 100000  # 100KB limit per file
    MAX_FILES_PER_ANALYSIS = 50  # Limit files to avoid token limits
    SUPPORTED_EXTENSIONS = ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php', '.go', '.rb', '.cs', '.cpp', '.c']
    EXCLUDED_DIRS = ['.git', 'node_modules', '__pycache__', '.venv', 'venv', 'build', 'dist', 'target']
    
    # Test Generation Configuration
    MAX_TESTS_PER_CATEGORY = 5
    MAX_TOTAL_TESTS = 50
    HIGH_PRIORITY_TEST_LIMIT = 10
    
    # Security Pattern Detection
    SECURITY_PATTERNS = {
        "database_queries": [
            r"SELECT\s+", r"INSERT\s+", r"UPDATE\s+", r"DELETE\s+", 
            r"query\s*\(", r"execute\s*\(", r"raw\s*query", r"sql\s*query"
        ],
        "user_input_handling": [
            r"input\s*\(", r"request\.", r"req\.", r"params\.", 
            r"body\.", r"form\.", r"getParameter", r"getAttribute"
        ],
        "authentication_code": [
            r"login\s*\(", r"authenticate\s*\(", r"auth\s*\.", 
            r"password", r"token", r"jwt", r"session", r"credential"
        ],
        "authorization_checks": [
            r"authorize\s*\(", r"permission\s*\.", r"role\s*\.", 
            r"access\s*\.", r"check\s*permission", r"isAuthorized"
        ],
        "crypto_usage": [
            r"encrypt\s*\(", r"decrypt\s*\(", r"hash\s*\(", 
            r"crypto\s*\.", r"bcrypt", r"sha256", r"md5", r"aes"
        ],
        "file_operations": [
            r"open\s*\(", r"read\s*\(", r"write\s*\(", r"file\s*\.", 
            r"upload\s*", r"download\s*", r"FileInputStream", r"FileOutputStream"
        ],
        "network_requests": [
            r"fetch\s*\(", r"request\s*\.", r"http\s*\.", r"axios\s*\.", 
            r"curl\s*", r"HttpClient", r"RestTemplate"
        ],
        "serialization": [
            r"json\s*\.", r"serialize\s*\(", r"deserialize\s*\(", 
            r"pickle\s*\.", r"yaml\s*\.", r"ObjectMapper", r"Gson"
        ],
        "api_endpoints": [
            r"@app\.route", r"@RequestMapping", r"@GetMapping", 
            r"@PostMapping", r"router\s*\.", r"@RestController"
        ],
        "session_management": [
            r"session\s*\.", r"cookie\s*\.", r"sessionStorage", 
            r"localStorage", r"HttpSession", r"SessionManager"
        ]
    }
    
    # Attack Categories and Priorities
    ATTACK_CATEGORIES = {
        "injection": {
            "priority": 1,
            "description": "Code injection vulnerabilities",
            "attacks": [
                "sql_injection", "nosql_injection", "command_injection", 
                "ldap_injection", "xpath_injection", "template_injection"
            ]
        },
        "authentication": {
            "priority": 2,
            "description": "Authentication bypass and weaknesses",
            "attacks": [
                "brute_force", "session_fixation", "weak_passwords", 
                "jwt_vulnerabilities", "oauth_flaws", "multi_factor_bypass"
            ]
        },
        "authorization": {
            "priority": 3,
            "description": "Authorization and access control issues",
            "attacks": [
                "idor", "privilege_escalation", "access_control_bypass", 
                "horizontal_escalation", "vertical_escalation", "role_confusion"
            ]
        },
        "business_logic": {
            "priority": 4,
            "description": "Business logic vulnerabilities",
            "attacks": [
                "price_manipulation", "race_conditions", "workflow_bypass", 
                "state_confusion", "double_spending", "time_of_check_time_of_use"
            ]
        },
        "data_exposure": {
            "priority": 5,
            "description": "Sensitive data exposure",
            "attacks": [
                "sensitive_data_leak", "information_disclosure", 
                "debug_info_exposure", "error_message_leak", "stack_trace_leak"
            ]
        },
        "cryptography": {
            "priority": 6,
            "description": "Cryptographic weaknesses",
            "attacks": [
                "weak_encryption", "insecure_random", "crypto_misuse", 
                "key_management", "certificate_issues", "padding_oracle"
            ]
        },
        "insecure_design": {
            "priority": 7,
            "description": "Insecure design patterns",
            "attacks": [
                "missing_validation", "insecure_direct_object_reference", 
                "security_misconfiguration", "default_credentials"
            ]
        },
        "vulnerable_components": {
            "priority": 8,
            "description": "Vulnerable dependencies and components",
            "attacks": [
                "outdated_dependencies", "known_cves", "supply_chain_attacks", 
                "dependency_confusion", "typosquatting"
            ]
        }
    }
    
    # Risk Level Configuration
    RISK_LEVELS = {
        "Critical": {
            "score": 4,
            "color": "#FF0000",
            "description": "Immediate action required"
        },
        "High": {
            "score": 3,
            "color": "#FF8C00",
            "description": "Address within 24 hours"
        },
        "Medium": {
            "score": 2,
            "color": "#FFD700",
            "description": "Address within 1 week"
        },
        "Low": {
            "score": 1,
            "color": "#32CD32",
            "description": "Address when possible"
        }
    }
    
    # Test Execution Configuration
    EXECUTION_CONFIG = {
        "max_concurrent_tests": 5,
        "test_timeout": 30,  # seconds
        "retry_attempts": 3,
        "delay_between_tests": 1,  # seconds
        "rate_limit_delay": 0.5  # seconds between requests
    }
    
    # Output Configuration
    OUTPUT_CONFIG = {
        "include_code_snippets": True,
        "include_payloads": True,
        "include_mitigation": True,
        "max_report_size": 1000000,  # 1MB
        "export_formats": ["json", "html", "pdf"]
    }
    
    @classmethod
    def get_gemini_prompt_template(cls, category: str) -> str:
        """Get the prompt template for a specific attack category"""
        
        base_prompt = f"""
        You are a cybersecurity expert analyzing code for {category} vulnerabilities.
        
        Based on the provided codebase analysis, generate specific, actionable security test cases.
        Focus on the most prevalent and impactful attack vectors in the {category} category.
        
        For each test case, provide:
        1. Test name and description
        2. Specific attack payloads or techniques
        3. Expected behavior if vulnerable
        4. Risk level (Critical/High/Medium/Low)
        5. Detection patterns to look for
        6. Specific endpoints or functions to test
        7. Step-by-step test execution plan
        8. Mitigation recommendations
        
        Attack types to consider: {', '.join(cls.ATTACK_CATEGORIES[category]['attacks'])}
        
        Return the response as a JSON array with this structure:
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
                "mitigation": "How to fix this vulnerability",
                "references": ["CWE-XXX", "OWASP-XXX"]
            }}
        ]
        
        Make the test cases specific to the codebase context provided.
        Focus on practical, executable tests that can be automated.
        Ensure test cases are safe and non-destructive.
        """
        
        return base_prompt
    
    @classmethod
    def validate_config(cls) -> bool:
        """Validate the configuration"""
        if not cls.GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY environment variable is required")
        
        if cls.MAX_TOTAL_TESTS > 100:
            raise ValueError("MAX_TOTAL_TESTS should not exceed 100")
        
        return True

