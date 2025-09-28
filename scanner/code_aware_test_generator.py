"""
Code-Aware Test Generator - Analyzes actual code to create targeted test cases
"""

import asyncio
import json
import os
import re
import ast
import logging
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import google.generativeai as genai
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class CodeLanguage(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    PHP = "php"
    GO = "go"
    RUST = "rust"

@dataclass
class CodeFile:
    path: str
    language: CodeLanguage
    content: str
    functions: List[Dict[str, Any]]
    classes: List[Dict[str, Any]]
    imports: List[str]
    vulnerabilities: List[Dict[str, Any]]

@dataclass
class TestCase:
    test_id: str
    name: str
    description: str
    attack_type: str
    target_function: str
    target_file: str
    payloads: List[str]
    expected_behavior: str
    risk_level: str
    code_snippet: str
    mitigation: str

class CodeAwareTestGenerator:
    """
    Analyzes actual code to generate targeted security test cases
    """
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API key is required")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-2.5-pro')
        
        # Code analysis patterns
        self.vulnerability_patterns = {
            "sql_injection": [
                r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\$\{.*\}",
                r"INSERT\s+INTO\s+.*\s+VALUES\s*\(.*\$\{.*\}\)",
                r"query\s*\(\s*[\"'].*\$.*[\"']",
                r"execute\s*\(\s*[\"'].*\$.*[\"']"
            ],
            "xss": [
                r"innerHTML\s*=\s*.*\$\{.*\}",
                r"document\.write\s*\(\s*.*\$\{.*\}\)",
                r"dangerouslySetInnerHTML.*\$\{.*\}",
                r"v-html.*\$\{.*\}"
            ],
            "command_injection": [
                r"exec\s*\(\s*.*\$\{.*\}\)",
                r"system\s*\(\s*.*\$\{.*\}\)",
                r"child_process\.exec\s*\(\s*.*\$\{.*\}\)",
                r"Runtime\.getRuntime\(\)\.exec\s*\(\s*.*\$\{.*\}\)"
            ],
            "path_traversal": [
                r"file_get_contents\s*\(\s*.*\$\{.*\}\)",
                r"fopen\s*\(\s*.*\$\{.*\}\)",
                r"readFile\s*\(\s*.*\$\{.*\}\)",
                r"Files\.readAllBytes\s*\(\s*.*\$\{.*\}\)"
            ]
        }
    
    async def analyze_codebase(self, codebase_path: str) -> List[CodeFile]:
        """
        Analyze a codebase and extract code information
        """
        code_files = []
        
        for root, dirs, files in os.walk(codebase_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv']]
            
            for file in files:
                file_path = os.path.join(root, file)
                language = self._detect_language(file_path)
                
                if language:
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        code_file = CodeFile(
                            path=file_path,
                            language=language,
                            content=content,
                            functions=self._extract_functions(content, language),
                            classes=self._extract_classes(content, language),
                            imports=self._extract_imports(content, language),
                            vulnerabilities=self._analyze_vulnerabilities(content, language)
                        )
                        
                        code_files.append(code_file)
                        logger.info(f"Analyzed {file_path}: {len(code_file.functions)} functions, {len(code_file.vulnerabilities)} vulnerabilities")
                    
                    except Exception as e:
                        logger.warning(f"Failed to analyze {file_path}: {str(e)}")
        
        return code_files
    
    def _detect_language(self, file_path: str) -> Optional[CodeLanguage]:
        """
        Detect programming language from file extension
        """
        ext = Path(file_path).suffix.lower()
        
        language_map = {
            '.py': CodeLanguage.PYTHON,
            '.js': CodeLanguage.JAVASCRIPT,
            '.ts': CodeLanguage.TYPESCRIPT,
            '.tsx': CodeLanguage.TYPESCRIPT,
            '.jsx': CodeLanguage.JAVASCRIPT,
            '.java': CodeLanguage.JAVA,
            '.cs': CodeLanguage.CSHARP,
            '.php': CodeLanguage.PHP,
            '.go': CodeLanguage.GO,
            '.rs': CodeLanguage.RUST
        }
        
        return language_map.get(ext)
    
    def _extract_functions(self, content: str, language: CodeLanguage) -> List[Dict[str, Any]]:
        """
        Extract function definitions from code
        """
        functions = []
        
        if language == CodeLanguage.PYTHON:
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        functions.append({
                            "name": node.name,
                            "line_number": node.lineno,
                            "args": [arg.arg for arg in node.args.args],
                            "code": ast.get_source_segment(content, node)
                        })
            except:
                pass
        
        elif language in [CodeLanguage.JAVASCRIPT, CodeLanguage.TYPESCRIPT]:
            # Extract function definitions using regex
            function_patterns = [
                r'function\s+(\w+)\s*\([^)]*\)\s*\{',
                r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{',
                r'(\w+)\s*:\s*function\s*\([^)]*\)\s*\{',
                r'(\w+)\s*\([^)]*\)\s*\{'
            ]
            
            for pattern in function_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    functions.append({
                        "name": match.group(1),
                        "line_number": content[:match.start()].count('\n') + 1,
                        "code": match.group(0)
                    })
        
        return functions
    
    def _extract_classes(self, content: str, language: CodeLanguage) -> List[Dict[str, Any]]:
        """
        Extract class definitions from code
        """
        classes = []
        
        if language == CodeLanguage.PYTHON:
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        classes.append({
                            "name": node.name,
                            "line_number": node.lineno,
                            "methods": [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
                        })
            except:
                pass
        
        return classes
    
    def _extract_imports(self, content: str, language: CodeLanguage) -> List[str]:
        """
        Extract import statements from code
        """
        imports = []
        
        if language == CodeLanguage.PYTHON:
            import_pattern = r'^(?:from\s+(\S+)\s+)?import\s+(\S+)'
            matches = re.finditer(import_pattern, content, re.MULTILINE)
            for match in matches:
                if match.group(1):
                    imports.append(f"{match.group(1)}.{match.group(2)}")
                else:
                    imports.append(match.group(2))
        
        elif language in [CodeLanguage.JAVASCRIPT, CodeLanguage.TYPESCRIPT]:
            import_pattern = r'import\s+.*?from\s+[\'"]([^\'"]+)[\'"]'
            matches = re.finditer(import_pattern, content, re.MULTILINE)
            for match in matches:
                imports.append(match.group(1))
        
        return imports
    
    def _analyze_vulnerabilities(self, content: str, language: CodeLanguage) -> List[Dict[str, Any]]:
        """
        Analyze code for potential vulnerabilities
        """
        vulnerabilities = []
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    vulnerabilities.append({
                        "type": vuln_type,
                        "line_number": line_number,
                        "code_snippet": match.group(0),
                        "severity": self._get_severity(vuln_type)
                    })
        
        return vulnerabilities
    
    def _get_severity(self, vuln_type: str) -> str:
        """
        Get severity level for vulnerability type
        """
        severity_map = {
            "sql_injection": "high",
            "command_injection": "critical",
            "xss": "high",
            "path_traversal": "high"
        }
        return severity_map.get(vuln_type, "medium")
    
    async def generate_targeted_tests(self, code_files: List[CodeFile], user_request: str) -> List[TestCase]:
        """
        Generate targeted test cases based on actual code analysis
        """
        # Prepare code context for AI
        code_context = self._prepare_code_context(code_files)
        
        # Generate test cases using AI
        prompt = f"""
        Analyze the following codebase and generate specific security test cases based on the user's request.
        
        User Request: {user_request}
        
        Codebase Analysis:
        {code_context}
        
        Generate 5-10 specific test cases that:
        1. Target actual functions and endpoints found in the code
        2. Use real parameter names and data structures
        3. Exploit specific vulnerabilities identified in the code
        4. Include realistic payloads based on the code's functionality
        5. Provide specific mitigation recommendations
        
        For each test case, provide:
        - Test name and description
        - Target function/endpoint
        - Specific attack payloads
        - Expected behavior if vulnerable
        - Risk level
        - Code snippet showing the vulnerability
        - Mitigation recommendation
        
        Return as JSON array with this structure:
        [
            {{
                "test_id": "unique_id",
                "name": "Descriptive test name",
                "description": "Detailed description",
                "attack_type": "Specific attack type",
                "target_function": "function_name",
                "target_file": "file_path",
                "payloads": ["payload1", "payload2"],
                "expected_behavior": "What to expect if vulnerable",
                "risk_level": "Critical|High|Medium|Low",
                "code_snippet": "Vulnerable code snippet",
                "mitigation": "How to fix this vulnerability"
            }}
        ]
        """
        
        try:
            response = self.model.generate_content(prompt)
            test_cases = self._parse_test_cases(response.text)
            return test_cases
        except Exception as e:
            logger.error(f"Error generating targeted tests: {str(e)}")
            return []
    
    def _prepare_code_context(self, code_files: List[CodeFile]) -> str:
        """
        Prepare code context for AI analysis
        """
        context = []
        
        for file in code_files:
            file_info = {
                "path": file.path,
                "language": file.language.value,
                "functions": file.functions[:5],  # Limit to first 5 functions
                "vulnerabilities": file.vulnerabilities,
                "imports": file.imports[:10]  # Limit to first 10 imports
            }
            context.append(json.dumps(file_info, indent=2))
        
        return "\n\n".join(context)
    
    def _parse_test_cases(self, response_text: str) -> List[TestCase]:
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
            test_data = json.loads(response_text)
            
            # Convert to TestCase objects
            test_cases = []
            for data in test_data:
                test_case = TestCase(
                    test_id=data.get("test_id", ""),
                    name=data.get("name", ""),
                    description=data.get("description", ""),
                    attack_type=data.get("attack_type", ""),
                    target_function=data.get("target_function", ""),
                    target_file=data.get("target_file", ""),
                    payloads=data.get("payloads", []),
                    expected_behavior=data.get("expected_behavior", ""),
                    risk_level=data.get("risk_level", "medium"),
                    code_snippet=data.get("code_snippet", ""),
                    mitigation=data.get("mitigation", "")
                )
                test_cases.append(test_case)
            
            return test_cases
            
        except Exception as e:
            logger.error(f"Error parsing test cases: {str(e)}")
            return []

# Example usage
async def main():
    """
    Example usage of the Code-Aware Test Generator
    """
    generator = CodeAwareTestGenerator()
    
    # Analyze a codebase
    codebase_path = "/path/to/your/codebase"
    code_files = await generator.analyze_codebase(codebase_path)
    
    print(f"Analyzed {len(code_files)} files")
    
    # Generate targeted tests
    user_request = "Test for SQL injection vulnerabilities in our user authentication system"
    test_cases = await generator.generate_targeted_tests(code_files, user_request)
    
    print(f"Generated {len(test_cases)} targeted test cases")
    
    for test_case in test_cases:
        print(f"\n{test_case.name}")
        print(f"Target: {test_case.target_function} in {test_case.target_file}")
        print(f"Attack: {test_case.attack_type}")
        print(f"Risk: {test_case.risk_level}")
        print(f"Payloads: {test_case.payloads}")

if __name__ == "__main__":
    asyncio.run(main())
