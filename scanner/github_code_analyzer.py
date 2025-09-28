"""
GitHub Code Analyzer - Fetches and analyzes code from GitHub repositories
"""

import asyncio
import json
import os
import re
import ast
import logging
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import requests
import base64
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
    sha: str
    size: int

class GitHubCodeAnalyzer:
    """
    Analyzes code from GitHub repositories to generate accurate test cases
    """
    
    def __init__(self, github_token: str = None):
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        if not self.github_token:
            raise ValueError("GitHub token is required")
        
        self.headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # Code analysis patterns
        self.vulnerability_patterns = {
            "sql_injection": [
                r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\$\{.*\}",
                r"INSERT\s+INTO\s+.*\s+VALUES\s*\(.*\$\{.*\}\)",
                r"query\s*\(\s*[\"'].*\$.*[\"']",
                r"execute\s*\(\s*[\"'].*\$.*[\"']",
                r"db\.query\s*\(\s*[\"'].*\$.*[\"']",
                r"connection\.execute\s*\(\s*[\"'].*\$.*[\"']"
            ],
            "xss": [
                r"innerHTML\s*=\s*.*\$\{.*\}",
                r"document\.write\s*\(\s*.*\$\{.*\}\)",
                r"dangerouslySetInnerHTML.*\$\{.*\}",
                r"v-html.*\$\{.*\}",
                r"\.html\s*\(\s*.*\$\{.*\}\)",
                r"\.append\s*\(\s*.*\$\{.*\}\)"
            ],
            "command_injection": [
                r"exec\s*\(\s*.*\$\{.*\}\)",
                r"system\s*\(\s*.*\$\{.*\}\)",
                r"child_process\.exec\s*\(\s*.*\$\{.*\}\)",
                r"Runtime\.getRuntime\(\)\.exec\s*\(\s*.*\$\{.*\}\)",
                r"os\.system\s*\(\s*.*\$\{.*\}\)",
                r"subprocess\.run\s*\(\s*.*\$\{.*\}\)"
            ],
            "path_traversal": [
                r"file_get_contents\s*\(\s*.*\$\{.*\}\)",
                r"fopen\s*\(\s*.*\$\{.*\}\)",
                r"readFile\s*\(\s*.*\$\{.*\}\)",
                r"Files\.readAllBytes\s*\(\s*.*\$\{.*\}\)",
                r"open\s*\(\s*.*\$\{.*\}\)",
                r"Path\.readAllBytes\s*\(\s*.*\$\{.*\}\)"
            ],
            "authentication_bypass": [
                r"if\s*\(\s*username\s*==\s*[\"'].*[\"']\s*&&\s*password\s*==\s*[\"'].*[\"']\s*\)",
                r"if\s*\(\s*user\.role\s*==\s*[\"']admin[\"']\s*\)",
                r"if\s*\(\s*isAdmin\s*==\s*true\s*\)",
                r"if\s*\(\s*user\.isAdmin\s*\)"
            ],
            "authorization_bypass": [
                r"if\s*\(\s*user\.id\s*==\s*[\"'].*[\"']\s*\)",
                r"if\s*\(\s*userId\s*==\s*[\"'].*[\"']\s*\)",
                r"if\s*\(\s*currentUser\.id\s*==\s*[\"'].*[\"']\s*\)"
            ]
        }
    
    async def analyze_repository(self, repo_owner: str, repo_name: str, branch: str = "main") -> List[CodeFile]:
        """
        Analyze a GitHub repository and extract code information
        """
        logger.info(f"🔍 Analyzing repository: {repo_owner}/{repo_name}")
        
        # Get repository tree
        tree_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/trees/{branch}?recursive=1"
        
        try:
            response = requests.get(tree_url, headers=self.headers)
            response.raise_for_status()
            tree_data = response.json()
            
            # Filter for code files
            code_files = []
            for item in tree_data.get("tree", []):
                if item["type"] == "blob" and self._is_code_file(item["path"]):
                    try:
                        # Get file content
                        file_content = await self._get_file_content(repo_owner, repo_name, item["path"])
                        if file_content:
                            language = self._detect_language(item["path"])
                            if language:
                                code_file = CodeFile(
                                    path=item["path"],
                                    language=language,
                                    content=file_content,
                                    functions=self._extract_functions(file_content, language),
                                    classes=self._extract_classes(file_content, language),
                                    imports=self._extract_imports(file_content, language),
                                    vulnerabilities=self._analyze_vulnerabilities(file_content, language),
                                    sha=item["sha"],
                                    size=item["size"]
                                )
                                code_files.append(code_file)
                                logger.info(f"✅ Analyzed {item['path']}: {len(code_file.functions)} functions, {len(code_file.vulnerabilities)} vulnerabilities")
                    
                    except Exception as e:
                        logger.warning(f"Failed to analyze {item['path']}: {str(e)}")
            
            logger.info(f"🎯 Analysis complete: {len(code_files)} files analyzed")
            return code_files
            
        except Exception as e:
            logger.error(f"Failed to analyze repository: {str(e)}")
            return []
    
    async def _get_file_content(self, repo_owner: str, repo_name: str, file_path: str) -> Optional[str]:
        """
        Get file content from GitHub
        """
        try:
            url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{file_path}"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            file_data = response.json()
            if file_data.get("encoding") == "base64":
                content = base64.b64decode(file_data["content"]).decode("utf-8")
                return content
            else:
                return file_data.get("content", "")
        
        except Exception as e:
            logger.warning(f"Failed to get content for {file_path}: {str(e)}")
            return None
    
    def _is_code_file(self, file_path: str) -> bool:
        """
        Check if file is a code file
        """
        code_extensions = {
            '.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.cs', 
            '.php', '.go', '.rs', '.rb', '.cpp', '.c', '.h'
        }
        
        return Path(file_path).suffix.lower() in code_extensions
    
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
                            "code": ast.get_source_segment(content, node),
                            "docstring": ast.get_docstring(node)
                        })
            except:
                pass
        
        elif language in [CodeLanguage.JAVASCRIPT, CodeLanguage.TYPESCRIPT]:
            # Extract function definitions using regex
            function_patterns = [
                r'function\s+(\w+)\s*\([^)]*\)\s*\{',
                r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{',
                r'(\w+)\s*:\s*function\s*\([^)]*\)\s*\{',
                r'(\w+)\s*\([^)]*\)\s*\{',
                r'async\s+function\s+(\w+)\s*\([^)]*\)\s*\{',
                r'export\s+function\s+(\w+)\s*\([^)]*\)\s*\{'
            ]
            
            for pattern in function_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    functions.append({
                        "name": match.group(1),
                        "line_number": content[:match.start()].count('\n') + 1,
                        "code": match.group(0),
                        "args": self._extract_function_args(match.group(0))
                    })
        
        return functions
    
    def _extract_function_args(self, function_code: str) -> List[str]:
        """
        Extract function arguments from function code
        """
        # Simple regex to extract arguments
        args_match = re.search(r'\(([^)]*)\)', function_code)
        if args_match:
            args_str = args_match.group(1)
            if args_str.strip():
                return [arg.strip().split('=')[0].strip() for arg in args_str.split(',')]
        return []
    
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
                            "methods": [n.name for n in node.body if isinstance(n, ast.FunctionDef)],
                            "docstring": ast.get_docstring(node)
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
                        "severity": self._get_severity(vuln_type),
                        "context": self._get_context(content, line_number)
                    })
        
        return vulnerabilities
    
    def _get_context(self, content: str, line_number: int, context_lines: int = 3) -> str:
        """
        Get context around a line number
        """
        lines = content.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        return '\n'.join(lines[start:end])
    
    def _get_severity(self, vuln_type: str) -> str:
        """
        Get severity level for vulnerability type
        """
        severity_map = {
            "sql_injection": "high",
            "command_injection": "critical",
            "xss": "high",
            "path_traversal": "high",
            "authentication_bypass": "critical",
            "authorization_bypass": "high"
        }
        return severity_map.get(vuln_type, "medium")
    
    async def generate_targeted_tests(self, code_files: List[CodeFile], user_request: str) -> List[Dict[str, Any]]:
        """
        Generate targeted test cases based on actual code analysis
        """
        # Prepare code context for AI
        code_context = self._prepare_code_context(code_files)
        
        # Generate test cases using AI (you would integrate with your AI here)
        test_cases = []
        
        for file in code_files:
            for vuln in file.vulnerabilities:
                test_case = {
                    "test_id": f"test_{len(test_cases) + 1}",
                    "name": f"{vuln['type'].replace('_', ' ').title()} in {file.path}",
                    "description": f"Test for {vuln['type']} vulnerability found in {file.path} at line {vuln['line_number']}",
                    "attack_type": vuln['type'],
                    "target_function": self._find_target_function(file, vuln['line_number']),
                    "target_file": file.path,
                    "payloads": self._generate_payloads(vuln['type']),
                    "expected_behavior": f"Should handle {vuln['type']} safely",
                    "risk_level": vuln['severity'],
                    "code_snippet": vuln['code_snippet'],
                    "context": vuln['context'],
                    "mitigation": self._get_mitigation(vuln['type'])
                }
                test_cases.append(test_case)
        
        return test_cases
    
    def _find_target_function(self, file: CodeFile, line_number: int) -> str:
        """
        Find the function that contains the vulnerability
        """
        for func in file.functions:
            if func['line_number'] <= line_number:
                return func['name']
        return "unknown"
    
    def _generate_payloads(self, vuln_type: str) -> List[str]:
        """
        Generate payloads for vulnerability type
        """
        payload_map = {
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT password FROM users --",
                "admin'--",
                "admin'/*"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "; rm -rf /",
                "| nc -l 4444"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd"
            ],
            "authentication_bypass": [
                "admin'--",
                "admin' OR '1'='1",
                "admin'/*",
                "admin'#",
                "admin' OR 1=1--"
            ],
            "authorization_bypass": [
                "admin",
                "administrator",
                "root",
                "superuser",
                "1"
            ]
        }
        
        return payload_map.get(vuln_type, ["test_payload"])
    
    def _get_mitigation(self, vuln_type: str) -> str:
        """
        Get mitigation recommendation for vulnerability type
        """
        mitigation_map = {
            "sql_injection": "Use parameterized queries or prepared statements",
            "xss": "Sanitize and escape user input, use textContent instead of innerHTML",
            "command_injection": "Use parameterized commands, validate and sanitize input",
            "path_traversal": "Validate file paths, use whitelist of allowed directories",
            "authentication_bypass": "Use secure authentication mechanisms, hash passwords",
            "authorization_bypass": "Implement proper access control, validate permissions"
        }
        
        return mitigation_map.get(vuln_type, "Review and fix the vulnerability")
    
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

# Example usage
async def main():
    """
    Example usage of the GitHub Code Analyzer
    """
    analyzer = GitHubCodeAnalyzer()
    
    # Analyze a repository
    repo_owner = "your-username"
    repo_name = "your-repo"
    code_files = await analyzer.analyze_repository(repo_owner, repo_name)
    
    print(f"Analyzed {len(code_files)} files")
    
    # Generate targeted tests
    user_request = "Test for SQL injection vulnerabilities in our user authentication system"
    test_cases = await analyzer.generate_targeted_tests(code_files, user_request)
    
    print(f"Generated {len(test_cases)} targeted test cases")
    
    for test_case in test_cases:
        print(f"\n{test_case['name']}")
        print(f"Target: {test_case['target_function']} in {test_case['target_file']}")
        print(f"Attack: {test_case['attack_type']}")
        print(f"Risk: {test_case['risk_level']}")
        print(f"Payloads: {test_case['payloads']}")

if __name__ == "__main__":
    asyncio.run(main())
