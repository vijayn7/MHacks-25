"""
AI Prompt System - Dynamic prompt generation for test case creation
"""

import asyncio
import json
import uuid
import os
import re
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

class PromptType(Enum):
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    TEST_CASE_GENERATION = "test_case_generation"
    CODE_REVIEW = "code_review"
    SECURITY_ASSESSMENT = "security_assessment"
    ATTACK_SIMULATION = "attack_simulation"
    MITIGATION_RECOMMENDATION = "mitigation_recommendation"

class CodeLanguage(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    PHP = "php"
    GO = "go"
    RUST = "rust"
    CPP = "cpp"
    C = "c"
    RUBY = "ruby"
    SWIFT = "swift"
    KOTLIN = "kotlin"

class SecurityCategory(Enum):
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    BUSINESS_LOGIC = "business_logic"
    DATA_EXPOSURE = "data_exposure"
    CRYPTOGRAPHY = "cryptography"
    INSECURE_DESIGN = "insecure_design"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    LOGGING_MONITORING = "logging_monitoring"

@dataclass
class CodeContext:
    language: CodeLanguage
    framework: Optional[str] = None
    libraries: List[str] = None
    patterns: List[str] = None
    architecture: Optional[str] = None
    security_requirements: List[str] = None

@dataclass
class TestRequirement:
    user_request: str
    target_url: str
    security_categories: List[SecurityCategory]
    test_depth: str  # "basic", "comprehensive", "exhaustive"
    focus_areas: List[str] = None
    constraints: List[str] = None
    business_context: Optional[str] = None

@dataclass
class GeneratedPrompt:
    prompt_id: str
    prompt_type: PromptType
    content: str
    context: Dict[str, Any]
    created_at: datetime
    effectiveness_score: Optional[float] = None

class AIPromptSystem:
    """
    Dynamic AI prompt system for generating security test cases
    """
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API key is required")
        
        # Configure Gemini
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-2.5-pro')
        
        # Prompt templates and strategies
        self.prompt_templates = self._initialize_prompt_templates()
        self.prompt_strategies = self._initialize_prompt_strategies()
        self.generated_prompts = {}
        
        # Security knowledge base
        self.security_knowledge = self._initialize_security_knowledge()
    
    def _initialize_prompt_templates(self) -> Dict[str, str]:
        """
        Initialize prompt templates for different scenarios
        """
        return {
            "vulnerability_analysis": """
                You are a cybersecurity expert analyzing code for security vulnerabilities.
                
                Code Context:
                - Language: {language}
                - Framework: {framework}
                - Libraries: {libraries}
                - Architecture: {architecture}
                
                Code to Analyze:
                {code}
                
                Focus Areas: {focus_areas}
                Security Categories: {security_categories}
                
                Analyze this code for security vulnerabilities and provide:
                1. Specific vulnerability types found
                2. Severity assessment (Critical/High/Medium/Low)
                3. Attack vectors and exploitation methods
                4. Evidence and proof of concept
                5. Impact assessment
                6. Mitigation recommendations
                
                Be specific and provide actionable insights.
            """,
            
            "test_case_generation": """
                You are a security testing expert creating comprehensive test cases.
                
                Test Requirements:
                - User Request: {user_request}
                - Target URL: {target_url}
                - Security Categories: {security_categories}
                - Test Depth: {test_depth}
                - Focus Areas: {focus_areas}
                - Business Context: {business_context}
                
                Code Context:
                - Language: {language}
                - Framework: {framework}
                - Libraries: {libraries}
                
                Generate {num_tests} specific, executable test cases that:
                1. Target the specified security categories
                2. Are appropriate for the test depth level
                3. Include specific payloads and techniques
                4. Provide clear success/failure criteria
                5. Include step-by-step execution instructions
                6. Are safe and non-destructive
                
                For each test case, provide:
                - Test name and description
                - Attack type and technique
                - Specific payloads or inputs
                - Expected behavior if vulnerable
                - Detection patterns to look for
                - Risk level and impact
                - Mitigation recommendations
                
                Return as JSON array with this structure:
                [
                    {{
                        "test_name": "Descriptive test name",
                        "description": "Detailed description",
                        "attack_type": "Specific attack type",
                        "payloads": ["payload1", "payload2"],
                        "endpoints": ["/api/endpoint1"],
                        "risk_level": "Critical|High|Medium|Low",
                        "detection_patterns": ["pattern1", "pattern2"],
                        "test_steps": ["step1", "step2", "step3"],
                        "expected_result": "What to expect if vulnerable",
                        "mitigation": "How to fix this vulnerability",
                        "references": ["CWE-XXX", "OWASP-XXX"]
                    }}
                ]
            """,
            
            "code_review": """
                You are a senior security engineer conducting a code review.
                
                Code Context:
                - Language: {language}
                - Framework: {framework}
                - Libraries: {libraries}
                - Security Requirements: {security_requirements}
                
                Code to Review:
                {code}
                
                Review this code for security issues and provide:
                1. Security vulnerabilities found
                2. Code quality issues
                3. Best practices violations
                4. Performance and scalability concerns
                5. Maintainability issues
                6. Specific recommendations for improvement
                
                Focus on:
                - Input validation and sanitization
                - Authentication and authorization
                - Data protection and encryption
                - Error handling and logging
                - API security
                - Configuration management
                
                Provide specific line-by-line feedback where applicable.
            """,
            
            "security_assessment": """
                You are a security consultant conducting a comprehensive security assessment.
                
                Application Context:
                - Target URL: {target_url}
                - Technology Stack: {technology_stack}
                - Business Domain: {business_domain}
                - Security Requirements: {security_requirements}
                
                Assessment Scope:
                - Security Categories: {security_categories}
                - Focus Areas: {focus_areas}
                - Test Depth: {test_depth}
                
                Conduct a thorough security assessment and provide:
                1. Executive summary of security posture
                2. Risk assessment and threat modeling
                3. Vulnerability analysis by category
                4. Attack surface analysis
                5. Security control effectiveness
                6. Compliance assessment
                7. Prioritized remediation roadmap
                8. Security recommendations
                
                Include specific examples and evidence for each finding.
            """,
            
            "attack_simulation": """
                You are a red team operator simulating real-world attacks.
                
                Target Context:
                - Target URL: {target_url}
                - Technology Stack: {technology_stack}
                - Business Context: {business_context}
                - Attack Categories: {attack_categories}
                
                Simulate realistic attack scenarios and provide:
                1. Reconnaissance and information gathering
                2. Attack vector identification
                3. Exploitation techniques
                4. Lateral movement strategies
                5. Persistence mechanisms
                6. Data exfiltration methods
                7. Detection evasion techniques
                8. Impact assessment
                
                Focus on:
                - Realistic attack paths
                - Common exploitation techniques
                - Business logic flaws
                - Social engineering vectors
                - Supply chain attacks
                - Insider threats
                
                Provide step-by-step attack procedures with specific commands and payloads.
            """,
            
            "mitigation_recommendation": """
                You are a security architect providing mitigation recommendations.
                
                Vulnerability Context:
                - Vulnerability Type: {vulnerability_type}
                - Severity: {severity}
                - Affected Component: {affected_component}
                - Technology Stack: {technology_stack}
                - Business Impact: {business_impact}
                
                Provide comprehensive mitigation recommendations:
                1. Immediate remediation steps
                2. Long-term security improvements
                3. Code-level fixes and patches
                4. Configuration changes
                5. Monitoring and detection
                6. Training and awareness
                7. Process improvements
                8. Tooling recommendations
                
                Include:
                - Specific code examples
                - Configuration templates
                - Implementation guidelines
                - Testing procedures
                - Rollback plans
                - Success metrics
                
                Prioritize recommendations by impact and effort required.
            """
        }
    
    def _initialize_prompt_strategies(self) -> Dict[str, Dict[str, Any]]:
        """
        Initialize prompt strategies for different scenarios
        """
        return {
            "beginner": {
                "description": "For users new to security testing",
                "characteristics": [
                    "Simple, clear explanations",
                    "Step-by-step instructions",
                    "Basic security concepts",
                    "Common vulnerability types",
                    "Safe testing practices"
                ],
                "adjustments": {
                    "complexity": "low",
                    "technical_depth": "basic",
                    "assumptions": "minimal",
                    "examples": "extensive"
                }
            },
            "intermediate": {
                "description": "For users with some security knowledge",
                "characteristics": [
                    "Moderate technical complexity",
                    "Industry best practices",
                    "Common attack patterns",
                    "Automation techniques",
                    "Risk assessment"
                ],
                "adjustments": {
                    "complexity": "medium",
                    "technical_depth": "intermediate",
                    "assumptions": "moderate",
                    "examples": "moderate"
                }
            },
            "expert": {
                "description": "For experienced security professionals",
                "characteristics": [
                    "Advanced techniques",
                    "Cutting-edge vulnerabilities",
                    "Custom attack vectors",
                    "Complex scenarios",
                    "Research-level insights"
                ],
                "adjustments": {
                    "complexity": "high",
                    "technical_depth": "advanced",
                    "assumptions": "extensive",
                    "examples": "minimal"
                }
            },
            "compliance": {
                "description": "For compliance-focused testing",
                "characteristics": [
                    "Regulatory requirements",
                    "Industry standards",
                    "Audit trails",
                    "Documentation",
                    "Risk management"
                ],
                "adjustments": {
                    "focus": "compliance",
                    "documentation": "extensive",
                    "standards": "specific",
                    "reporting": "detailed"
                }
            },
            "penetration_testing": {
                "description": "For penetration testing scenarios",
                "characteristics": [
                    "Real-world attack simulation",
                    "Exploitation techniques",
                    "Post-exploitation",
                    "Social engineering",
                    "Physical security"
                ],
                "adjustments": {
                    "realism": "high",
                    "creativity": "high",
                    "practicality": "high",
                    "documentation": "moderate"
                }
            }
        }
    
    def _initialize_security_knowledge(self) -> Dict[str, Any]:
        """
        Initialize security knowledge base
        """
        return {
            "owasp_top_10": {
                "A01": "Broken Access Control",
                "A02": "Cryptographic Failures",
                "A03": "Injection",
                "A04": "Insecure Design",
                "A05": "Security Misconfiguration",
                "A06": "Vulnerable and Outdated Components",
                "A07": "Identification and Authentication Failures",
                "A08": "Software and Data Integrity Failures",
                "A09": "Security Logging and Monitoring Failures",
                "A10": "Server-Side Request Forgery"
            },
            "cwe_top_25": {
                "CWE-79": "Cross-site Scripting",
                "CWE-89": "SQL Injection",
                "CWE-20": "Improper Input Validation",
                "CWE-200": "Information Exposure",
                "CWE-352": "Cross-Site Request Forgery",
                "CWE-22": "Path Traversal",
                "CWE-434": "Unrestricted Upload of File with Dangerous Type",
                "CWE-78": "OS Command Injection",
                "CWE-798": "Use of Hard-coded Credentials",
                "CWE-311": "Missing Encryption of Sensitive Data"
            },
            "attack_techniques": {
                "injection": [
                    "SQL Injection",
                    "NoSQL Injection",
                    "Command Injection",
                    "LDAP Injection",
                    "XPath Injection",
                    "Template Injection",
                    "Code Injection",
                    "Log Injection"
                ],
                "authentication": [
                    "Brute Force",
                    "Credential Stuffing",
                    "Session Fixation",
                    "JWT Vulnerabilities",
                    "OAuth Flaws",
                    "Multi-Factor Authentication Bypass",
                    "Password Reset Vulnerabilities"
                ],
                "authorization": [
                    "Insecure Direct Object Reference",
                    "Privilege Escalation",
                    "Access Control Bypass",
                    "Horizontal Escalation",
                    "Vertical Escalation",
                    "Role-Based Access Control Flaws"
                ],
                "business_logic": [
                    "Price Manipulation",
                    "Race Conditions",
                    "Workflow Bypass",
                    "State Confusion",
                    "Double Spending",
                    "Inventory Manipulation",
                    "Refund Abuse"
                ]
            },
            "mitigation_patterns": {
                "input_validation": [
                    "Whitelist validation",
                    "Blacklist filtering",
                    "Type checking",
                    "Length validation",
                    "Format validation",
                    "Range validation"
                ],
                "output_encoding": [
                    "HTML encoding",
                    "URL encoding",
                    "JavaScript encoding",
                    "CSS encoding",
                    "XML encoding",
                    "SQL escaping"
                ],
                "authentication": [
                    "Strong password policies",
                    "Multi-factor authentication",
                    "Session management",
                    "Account lockout",
                    "Rate limiting",
                    "CAPTCHA"
                ],
                "authorization": [
                    "Principle of least privilege",
                    "Role-based access control",
                    "Attribute-based access control",
                    "Access control lists",
                    "Permission matrices",
                    "Regular access reviews"
                ]
            }
        }
    
    async def generate_prompt(self, prompt_type: PromptType, context: Dict[str, Any],
                            strategy: str = "intermediate") -> GeneratedPrompt:
        """
        Generate a dynamic prompt based on context and strategy
        """
        try:
            # Get base template
            template = self.prompt_templates.get(prompt_type.value, "")
            if not template:
                raise ValueError(f"Unknown prompt type: {prompt_type}")
            
            # Get strategy adjustments
            strategy_config = self.prompt_strategies.get(strategy, {})
            adjustments = strategy_config.get("adjustments", {})
            
            # Enhance context with strategy-specific information
            enhanced_context = self._enhance_context(context, strategy_config)
            
            # Generate dynamic prompt
            prompt_content = self._generate_dynamic_prompt(
                template, enhanced_context, adjustments, prompt_type
            )
            
            # Create prompt object
            prompt = GeneratedPrompt(
                prompt_id=str(uuid.uuid4()),
                prompt_type=prompt_type,
                content=prompt_content,
                context=enhanced_context,
                created_at=datetime.now()
            )
            
            # Store prompt
            self.generated_prompts[prompt.prompt_id] = prompt
            
            logger.info(f"Generated prompt: {prompt_type.value} using {strategy} strategy")
            return prompt
            
        except Exception as e:
            logger.error(f"Error generating prompt: {str(e)}")
            raise
    
    def _enhance_context(self, context: Dict[str, Any], strategy_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance context with strategy-specific information
        """
        enhanced = context.copy()
        
        # Add strategy-specific enhancements
        if strategy_config.get("characteristics"):
            enhanced["strategy_characteristics"] = strategy_config["characteristics"]
        
        # Add security knowledge based on context
        if "security_categories" in context:
            enhanced["security_knowledge"] = self._get_relevant_security_knowledge(
                context["security_categories"]
            )
        
        # Add language-specific information
        if "language" in context:
            enhanced["language_specifics"] = self._get_language_specifics(
                context["language"]
            )
        
        # Add framework-specific information
        if "framework" in context:
            enhanced["framework_specifics"] = self._get_framework_specifics(
                context["framework"]
            )
        
        return enhanced
    
    def _get_relevant_security_knowledge(self, security_categories: List[str]) -> Dict[str, Any]:
        """
        Get relevant security knowledge for the given categories
        """
        relevant_knowledge = {}
        
        for category in security_categories:
            if category in self.security_knowledge["attack_techniques"]:
                relevant_knowledge[category] = {
                    "techniques": self.security_knowledge["attack_techniques"][category],
                    "mitigations": self.security_knowledge["mitigation_patterns"].get(category, [])
                }
        
        return relevant_knowledge
    
    def _get_language_specifics(self, language: str) -> Dict[str, Any]:
        """
        Get language-specific security information
        """
        language_specifics = {
            "python": {
                "common_vulnerabilities": [
                    "Pickle deserialization",
                    "Code injection via eval()",
                    "Path traversal with os.path",
                    "SQL injection with string formatting"
                ],
                "secure_practices": [
                    "Use parameterized queries",
                    "Validate input with libraries like cerberus",
                    "Use secure random for secrets",
                    "Avoid eval() and exec()"
                ],
                "libraries": [
                    "cryptography for encryption",
                    "bcrypt for password hashing",
                    "jwt for token handling",
                    "requests for HTTP calls"
                ]
            },
            "javascript": {
                "common_vulnerabilities": [
                    "Prototype pollution",
                    "XSS via innerHTML",
                    "CSRF with same-origin policy",
                    "Code injection via eval()"
                ],
                "secure_practices": [
                    "Use Content Security Policy",
                    "Validate input on both client and server",
                    "Use HTTPS for all communications",
                    "Implement proper CORS"
                ],
                "libraries": [
                    "helmet for security headers",
                    "express-rate-limit for rate limiting",
                    "bcrypt for password hashing",
                    "jsonwebtoken for JWT"
                ]
            },
            "java": {
                "common_vulnerabilities": [
                    "Deserialization vulnerabilities",
                    "SQL injection with string concatenation",
                    "Path traversal with File operations",
                    "XXE in XML processing"
                ],
                "secure_practices": [
                    "Use PreparedStatement for SQL",
                    "Validate input with Bean Validation",
                    "Use secure random for secrets",
                    "Implement proper error handling"
                ],
                "libraries": [
                    "Spring Security for authentication",
                    "OWASP Java Encoder for output encoding",
                    "Apache Commons Validator for input validation",
                    "Bouncy Castle for cryptography"
                ]
            }
        }
        
        return language_specifics.get(language, {})
    
    def _get_framework_specifics(self, framework: str) -> Dict[str, Any]:
        """
        Get framework-specific security information
        """
        framework_specifics = {
            "react": {
                "security_considerations": [
                    "XSS prevention with JSX",
                    "CSRF protection",
                    "Secure state management",
                    "Input validation"
                ],
                "best_practices": [
                    "Use dangerouslySetInnerHTML carefully",
                    "Implement proper CORS",
                    "Validate props and state",
                    "Use HTTPS in production"
                ]
            },
            "express": {
                "security_considerations": [
                    "Input validation",
                    "Output encoding",
                    "Session management",
                    "Error handling"
                ],
                "middleware": [
                    "helmet for security headers",
                    "express-rate-limit for rate limiting",
                    "cors for cross-origin requests",
                    "express-validator for input validation"
                ]
            },
            "spring": {
                "security_considerations": [
                    "Authentication and authorization",
                    "CSRF protection",
                    "Session management",
                    "Input validation"
                ],
                "annotations": [
                    "@PreAuthorize for method security",
                    "@Valid for input validation",
                    "@CrossOrigin for CORS",
                    "@Transactional for data integrity"
                ]
            }
        }
        
        return framework_specifics.get(framework, {})
    
    def _generate_dynamic_prompt(self, template: str, context: Dict[str, Any],
                               adjustments: Dict[str, Any], prompt_type: PromptType) -> str:
        """
        Generate dynamic prompt content
        """
        # Format the base template
        formatted_prompt = template.format(**context)
        
        # Apply strategy adjustments
        if adjustments.get("complexity") == "low":
            formatted_prompt += "\n\nKeep explanations simple and avoid technical jargon."
        elif adjustments.get("complexity") == "high":
            formatted_prompt += "\n\nProvide advanced technical details and cutting-edge techniques."
        
        if adjustments.get("technical_depth") == "basic":
            formatted_prompt += "\n\nFocus on fundamental security concepts and common vulnerabilities."
        elif adjustments.get("technical_depth") == "advanced":
            formatted_prompt += "\n\nInclude advanced exploitation techniques and research-level insights."
        
        if adjustments.get("focus") == "compliance":
            formatted_prompt += "\n\nEmphasize regulatory compliance and audit requirements."
        
        if adjustments.get("realism") == "high":
            formatted_prompt += "\n\nFocus on realistic attack scenarios and real-world exploitation techniques."
        
        # Add prompt type specific enhancements
        if prompt_type == PromptType.TEST_CASE_GENERATION:
            formatted_prompt += self._add_test_generation_enhancements(context)
        elif prompt_type == PromptType.VULNERABILITY_ANALYSIS:
            formatted_prompt += self._add_vulnerability_analysis_enhancements(context)
        elif prompt_type == PromptType.ATTACK_SIMULATION:
            formatted_prompt += self._add_attack_simulation_enhancements(context)
        
        return formatted_prompt
    
    def _add_test_generation_enhancements(self, context: Dict[str, Any]) -> str:
        """
        Add enhancements specific to test case generation
        """
        enhancements = "\n\nAdditional Guidelines for Test Generation:\n"
        
        # Add test depth specific guidance
        test_depth = context.get("test_depth", "comprehensive")
        if test_depth == "basic":
            enhancements += "- Focus on common, well-known vulnerabilities\n"
            enhancements += "- Provide simple, easy-to-understand test cases\n"
            enhancements += "- Include basic payloads and techniques\n"
        elif test_depth == "exhaustive":
            enhancements += "- Include edge cases and advanced techniques\n"
            enhancements += "- Cover multiple attack vectors for each vulnerability type\n"
            enhancements += "- Provide comprehensive payload variations\n"
        
        # Add security category specific guidance
        if "security_categories" in context:
            enhancements += "- Prioritize the following security categories: " + ", ".join(context["security_categories"]) + "\n"
        
        # Add business context guidance
        if "business_context" in context:
            enhancements += f"- Consider the business context: {context['business_context']}\n"
        
        return enhancements
    
    def _add_vulnerability_analysis_enhancements(self, context: Dict[str, Any]) -> str:
        """
        Add enhancements specific to vulnerability analysis
        """
        enhancements = "\n\nAdditional Guidelines for Vulnerability Analysis:\n"
        
        # Add language specific guidance
        if "language" in context:
            enhancements += f"- Focus on {context['language']}-specific security issues\n"
        
        # Add framework specific guidance
        if "framework" in context:
            enhancements += f"- Consider {context['framework']} framework security implications\n"
        
        # Add focus areas guidance
        if "focus_areas" in context:
            enhancements += f"- Pay special attention to: {', '.join(context['focus_areas'])}\n"
        
        return enhancements
    
    def _add_attack_simulation_enhancements(self, context: Dict[str, Any]) -> str:
        """
        Add enhancements specific to attack simulation
        """
        enhancements = "\n\nAdditional Guidelines for Attack Simulation:\n"
        
        # Add realism guidance
        enhancements += "- Simulate realistic attack scenarios\n"
        enhancements += "- Include social engineering techniques where applicable\n"
        enhancements += "- Consider business logic flaws and edge cases\n"
        enhancements += "- Provide step-by-step attack procedures\n"
        
        # Add target specific guidance
        if "target_url" in context:
            enhancements += f"- Target the specific URL: {context['target_url']}\n"
        
        return enhancements
    
    async def generate_test_cases(self, test_requirement: TestRequirement,
                                code_context: CodeContext = None,
                                strategy: str = "intermediate") -> List[Dict[str, Any]]:
        """
        Generate test cases using the AI prompt system
        """
        try:
            # Prepare context
            context = {
                "user_request": test_requirement.user_request,
                "target_url": test_requirement.target_url,
                "security_categories": [cat.value for cat in test_requirement.security_categories],
                "test_depth": test_requirement.test_depth,
                "focus_areas": test_requirement.focus_areas or [],
                "business_context": test_requirement.business_context or "",
                "constraints": test_requirement.constraints or [],
                "num_tests": self._calculate_num_tests(test_requirement.test_depth)
            }
            
            # Add code context if provided
            if code_context:
                context.update({
                    "language": code_context.language.value,
                    "framework": code_context.framework or "Unknown",
                    "libraries": code_context.libraries or [],
                    "architecture": code_context.architecture or "Unknown",
                    "security_requirements": code_context.security_requirements or []
                })
            
            # Generate prompt
            prompt = await self.generate_prompt(
                PromptType.TEST_CASE_GENERATION,
                context,
                strategy
            )
            
            # Generate test cases using AI
            response = self.model.generate_content(prompt.content)
            
            # Parse response
            test_cases = self._parse_test_cases_response(response.text)
            
            # Enhance test cases with additional metadata
            enhanced_test_cases = self._enhance_test_cases(test_cases, test_requirement, code_context)
            
            logger.info(f"Generated {len(enhanced_test_cases)} test cases using {strategy} strategy")
            return enhanced_test_cases
            
        except Exception as e:
            logger.error(f"Error generating test cases: {str(e)}")
            return []
    
    def _calculate_num_tests(self, test_depth: str) -> int:
        """
        Calculate number of tests based on test depth
        """
        depth_mapping = {
            "basic": 3,
            "comprehensive": 8,
            "exhaustive": 15
        }
        return depth_mapping.get(test_depth, 5)
    
    def _parse_test_cases_response(self, response_text: str) -> List[Dict[str, Any]]:
        """
        Parse test cases from AI response
        """
        try:
            # Clean the response text
            response_text = response_text.strip()
            
            # Extract JSON array from response
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            
            response_text = response_text.strip()
            
            # Find JSON array in response
            start_idx = response_text.find('[')
            end_idx = response_text.rfind(']')
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                response_text = response_text[start_idx:end_idx + 1]
            
            # Parse JSON
            test_cases = json.loads(response_text)
            
            # Ensure it's a list
            if not isinstance(test_cases, list):
                test_cases = [test_cases]
            
            return test_cases
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse test cases response: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error parsing test cases: {str(e)}")
            return []
    
    def _enhance_test_cases(self, test_cases: List[Dict[str, Any]], 
                          test_requirement: TestRequirement,
                          code_context: CodeContext = None) -> List[Dict[str, Any]]:
        """
        Enhance test cases with additional metadata
        """
        enhanced_cases = []
        
        for i, test_case in enumerate(test_cases):
            # Add metadata
            test_case["test_id"] = str(uuid.uuid4())
            test_case["created_at"] = datetime.now().isoformat()
            test_case["test_requirement_id"] = str(uuid.uuid4())
            test_case["priority"] = self._calculate_test_priority(test_case)
            test_case["complexity"] = self._calculate_test_complexity(test_case)
            test_case["estimated_duration"] = self._estimate_test_duration(test_case)
            
            # Add code context if available
            if code_context:
                test_case["language"] = code_context.language.value
                test_case["framework"] = code_context.framework
                test_case["libraries"] = code_context.libraries
            
            # Add security category mapping
            test_case["security_categories"] = self._map_security_categories(test_case)
            
            # Add execution hints
            test_case["execution_hints"] = self._generate_execution_hints(test_case)
            
            enhanced_cases.append(test_case)
        
        return enhanced_cases
    
    def _calculate_test_priority(self, test_case: Dict[str, Any]) -> int:
        """
        Calculate test priority based on risk level and other factors
        """
        risk_level = test_case.get("risk_level", "medium").lower()
        risk_scores = {"critical": 10, "high": 8, "medium": 5, "low": 2}
        
        base_priority = risk_scores.get(risk_level, 5)
        
        # Adjust based on attack type
        attack_type = test_case.get("attack_type", "").lower()
        if "injection" in attack_type:
            base_priority += 2
        elif "authentication" in attack_type or "authorization" in attack_type:
            base_priority += 1
        
        return min(10, max(1, base_priority))
    
    def _calculate_test_complexity(self, test_case: Dict[str, Any]) -> str:
        """
        Calculate test complexity
        """
        payloads = test_case.get("payloads", [])
        steps = test_case.get("test_steps", [])
        
        complexity_score = len(payloads) + len(steps)
        
        if complexity_score <= 3:
            return "low"
        elif complexity_score <= 6:
            return "medium"
        else:
            return "high"
    
    def _estimate_test_duration(self, test_case: Dict[str, Any]) -> int:
        """
        Estimate test duration in minutes
        """
        complexity = self._calculate_test_complexity(test_case)
        duration_mapping = {"low": 2, "medium": 5, "high": 10}
        return duration_mapping.get(complexity, 5)
    
    def _map_security_categories(self, test_case: Dict[str, Any]) -> List[str]:
        """
        Map test case to security categories
        """
        attack_type = test_case.get("attack_type", "").lower()
        
        category_mapping = {
            "sql injection": ["injection"],
            "xss": ["injection"],
            "command injection": ["injection"],
            "authentication": ["authentication"],
            "authorization": ["authorization"],
            "idor": ["authorization"],
            "business logic": ["business_logic"],
            "cryptography": ["cryptography"],
            "data exposure": ["data_exposure"]
        }
        
        for keyword, categories in category_mapping.items():
            if keyword in attack_type:
                return categories
        
        return ["general"]
    
    def _generate_execution_hints(self, test_case: Dict[str, Any]) -> List[str]:
        """
        Generate execution hints for the test case
        """
        hints = []
        
        attack_type = test_case.get("attack_type", "").lower()
        
        if "injection" in attack_type:
            hints.append("Monitor application logs for error messages")
            hints.append("Check for database error responses")
            hints.append("Verify input validation is working")
        
        if "authentication" in attack_type:
            hints.append("Test with valid and invalid credentials")
            hints.append("Check for account lockout mechanisms")
            hints.append("Verify session management")
        
        if "authorization" in attack_type:
            hints.append("Test with different user roles")
            hints.append("Verify access control mechanisms")
            hints.append("Check for privilege escalation")
        
        hints.append("Document all findings with evidence")
        hints.append("Take screenshots of successful exploits")
        
        return hints
    
    async def analyze_code_vulnerabilities(self, code: str, code_context: CodeContext,
                                         focus_areas: List[str] = None) -> List[Dict[str, Any]]:
        """
        Analyze code for vulnerabilities using AI
        """
        try:
            # Prepare context
            context = {
                "code": code,
                "language": code_context.language.value,
                "framework": code_context.framework or "Unknown",
                "libraries": code_context.libraries or [],
                "architecture": code_context.architecture or "Unknown",
                "focus_areas": focus_areas or [],
                "security_categories": [cat.value for cat in SecurityCategory]
            }
            
            # Generate prompt
            prompt = await self.generate_prompt(
                PromptType.VULNERABILITY_ANALYSIS,
                context,
                "expert"
            )
            
            # Analyze code using AI
            response = self.model.generate_content(prompt.content)
            
            # Parse response
            vulnerabilities = self._parse_vulnerabilities_response(response.text)
            
            logger.info(f"Analyzed code, found {len(vulnerabilities)} potential vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error analyzing code vulnerabilities: {str(e)}")
            return []
    
    def _parse_vulnerabilities_response(self, response_text: str) -> List[Dict[str, Any]]:
        """
        Parse vulnerabilities from AI response
        """
        try:
            # This is a simplified parser - in practice, you'd want more robust parsing
            vulnerabilities = []
            
            # Look for vulnerability patterns in the response
            lines = response_text.split('\n')
            current_vuln = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith('1.') or line.startswith('2.') or line.startswith('3.'):
                    if current_vuln:
                        vulnerabilities.append(current_vuln)
                    current_vuln = {
                        "title": line[3:].strip(),
                        "description": "",
                        "severity": "medium",
                        "category": "general",
                        "line_number": 0,
                        "code_snippet": "",
                        "mitigation": ""
                    }
                elif line.startswith('Severity:'):
                    current_vuln["severity"] = line.split(':', 1)[1].strip().lower()
                elif line.startswith('Category:'):
                    current_vuln["category"] = line.split(':', 1)[1].strip().lower()
                elif line.startswith('Description:'):
                    current_vuln["description"] = line.split(':', 1)[1].strip()
                elif line.startswith('Mitigation:'):
                    current_vuln["mitigation"] = line.split(':', 1)[1].strip()
                elif current_vuln and not line.startswith('**'):
                    if current_vuln["description"]:
                        current_vuln["description"] += " " + line
                    else:
                        current_vuln["description"] = line
            
            if current_vuln:
                vulnerabilities.append(current_vuln)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error parsing vulnerabilities: {str(e)}")
            return []
    
    async def get_prompt_effectiveness(self, prompt_id: str) -> float:
        """
        Get effectiveness score for a prompt (placeholder implementation)
        """
        if prompt_id in self.generated_prompts:
            # In a real implementation, this would analyze the results
            # of using the prompt and calculate an effectiveness score
            return 0.85  # Placeholder score
        return 0.0
    
    async def optimize_prompt(self, prompt_id: str, feedback: Dict[str, Any]) -> GeneratedPrompt:
        """
        Optimize a prompt based on feedback
        """
        if prompt_id not in self.generated_prompts:
            raise ValueError(f"Prompt {prompt_id} not found")
        
        original_prompt = self.generated_prompts[prompt_id]
        
        # In a real implementation, this would use the feedback to improve the prompt
        # For now, we'll just return the original prompt
        return original_prompt

# Example usage
async def main():
    """
    Example usage of the AI Prompt System
    """
    # Initialize the system
    prompt_system = AIPromptSystem()
    
    # Create test requirement
    test_requirement = TestRequirement(
        user_request="Test for SQL injection vulnerabilities in our user search functionality",
        target_url="https://example.com",
        security_categories=[SecurityCategory.INJECTION, SecurityCategory.AUTHENTICATION],
        test_depth="comprehensive",
        focus_areas=["user input validation", "database queries"],
        business_context="E-commerce application with user search"
    )
    
    # Create code context
    code_context = CodeContext(
        language=CodeLanguage.JAVASCRIPT,
        framework="Express.js",
        libraries=["mysql2", "express-validator"],
        patterns=["MVC", "REST API"],
        architecture="Microservices",
        security_requirements=["OWASP Top 10", "PCI DSS"]
    )
    
    print("🤖 Generating test cases with AI Prompt System...")
    
    # Generate test cases
    test_cases = await prompt_system.generate_test_cases(
        test_requirement,
        code_context,
        strategy="intermediate"
    )
    
    print(f"✅ Generated {len(test_cases)} test cases")
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{i}. {test_case['test_name']}")
        print(f"   Attack Type: {test_case['attack_type']}")
        print(f"   Risk Level: {test_case['risk_level']}")
        print(f"   Priority: {test_case['priority']}")
        print(f"   Complexity: {test_case['complexity']}")
        print(f"   Duration: {test_case['estimated_duration']} minutes")
    
    # Example code analysis
    sample_code = """
    app.get('/search', (req, res) => {
        const query = `SELECT * FROM users WHERE name = '${req.query.name}'`;
        db.query(query, (err, results) => {
            if (err) throw err;
            res.json(results);
        });
    });
    """
    
    print("\n🔍 Analyzing code for vulnerabilities...")
    
    vulnerabilities = await prompt_system.analyze_code_vulnerabilities(
        sample_code,
        code_context,
        focus_areas=["SQL injection", "Input validation"]
    )
    
    print(f"✅ Found {len(vulnerabilities)} potential vulnerabilities")
    
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n{i}. {vuln['title']}")
        print(f"   Severity: {vuln['severity']}")
        print(f"   Category: {vuln['category']}")
        print(f"   Description: {vuln['description']}")

if __name__ == "__main__":
    asyncio.run(main())
