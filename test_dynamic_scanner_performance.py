#!/usr/bin/env python3
"""
Performance and Stress Testing for Dynamic Scanner

This script tests the dynamic scanner's performance with large codebases,
multiple concurrent scans, and various edge cases.
"""

import asyncio
import json
import os
import sys
import tempfile
import shutil
import time
from pathlib import Path
import logging
from concurrent.futures import ThreadPoolExecutor
import psutil

# Add scanner directory to path
sys.path.append(str(Path(__file__).parent / "scanner"))

from dynamic_scanner import DynamicScanner

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PerformanceTester:
    """Performance testing class for dynamic scanner"""
    
    def __init__(self):
        self.scanner = DynamicScanner()
        self.results = []
    
    async def test_large_codebase_performance(self, file_count=100):
        """Test performance with large codebase"""
        logger.info(f"📊 Testing performance with {file_count} files...")
        
        test_dir = tempfile.mkdtemp()
        
        # Create large number of files
        for i in range(file_count):
            file_content = f'''
# File {i} - Vulnerable Python code
import sqlite3
import hashlib
import subprocess
import requests
import json
import os

class VulnerableClass{i}:
    def __init__(self):
        self.conn = sqlite3.connect('db_{i}.sqlite')
    
    def sql_injection_{i}(self, user_input):
        # SQL Injection vulnerability {i}
        query = f"SELECT * FROM table_{i} WHERE id = '{{user_input}}'"
        return self.conn.execute(query).fetchall()
    
    def xss_vulnerability_{i}(self, user_input):
        # XSS vulnerability {i}
        return f"<h1>Welcome {{user_input}}!</h1>"
    
    def command_injection_{i}(self, user_input):
        # Command injection vulnerability {i}
        return subprocess.run(f"echo {{user_input}}", shell=True, capture_output=True, text=True)
    
    def path_traversal_{i}(self, filename):
        # Path traversal vulnerability {i}
        with open(f"uploads/{{filename}}", "r") as f:
            return f.read()
    
    def weak_crypto_{i}(self, password):
        # Weak crypto vulnerability {i}
        return hashlib.md5(password.encode()).hexdigest()
    
    def idor_vulnerability_{i}(self, user_id):
        # IDOR vulnerability {i}
        query = f"SELECT * FROM users WHERE id = {{user_id}}"
        return self.conn.execute(query).fetchall()
    
    def business_logic_{i}(self, amount, user_id):
        # Business logic vulnerability {i}
        # No validation - client controls amount
        return self.charge_user(user_id, amount)
    
    def charge_user(self, user_id, amount):
        # Simulate payment processing
        return f"Charged user {{user_id}} amount {{amount}}"
'''
            (Path(test_dir) / f"vulnerable_file_{i}.py").write_text(file_content)
        
        # Create package.json for JavaScript files
        package_json = '''
{
    "name": "vulnerable-app",
    "version": "1.0.0",
    "dependencies": {
        "express": "4.16.0",
        "lodash": "4.17.4",
        "jquery": "1.9.1",
        "moment": "2.19.0"
    }
}
'''
        (Path(test_dir) / "package.json").write_text(package_json)
        
        # Create requirements.txt
        requirements = '''
Flask==2.3.3
requests==2.31.0
PyJWT==2.8.0
'''
        (Path(test_dir) / "requirements.txt").write_text(requirements)
        
        try:
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            
            results = await self.scanner.run_full_analysis(test_dir, 'http://localhost:5000')
            
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            
            duration = end_time - start_time
            memory_used = end_memory - start_memory
            
            test_result = {
                'test_name': f'Large Codebase ({file_count} files)',
                'file_count': file_count,
                'duration_seconds': duration,
                'memory_used_mb': memory_used,
                'total_files': results.get('total_files', 0),
                'total_tests': results.get('total_tests', 0),
                'vulnerabilities_found': results.get('vulnerabilities_found', 0),
                'ai_generated_findings': len(results.get('owasp_findings', [])),
                'languages': results.get('languages', []),
                'success': True
            }
            
            logger.info(f"✅ Large codebase test completed in {duration:.2f}s, {memory_used:.2f}MB memory used")
            return test_result
            
        except Exception as e:
            logger.error(f"❌ Large codebase test failed: {str(e)}")
            return {'test_name': f'Large Codebase ({file_count} files)', 'success': False, 'error': str(e)}
        finally:
            shutil.rmtree(test_dir)
    
    async def test_concurrent_scans(self, concurrent_count=5):
        """Test concurrent scan performance"""
        logger.info(f"🔄 Testing {concurrent_count} concurrent scans...")
        
        async def run_single_scan(scan_id):
            test_dir = tempfile.mkdtemp()
            
            # Create test files
            for i in range(10):
                file_content = f'''
# Scan {scan_id} - File {i}
import sqlite3
import hashlib

def vulnerable_function_{i}(user_input):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{{user_input}}'"
    conn = sqlite3.connect('db.sqlite')
    return conn.execute(query).fetchall()

def weak_hash_{i}(password):
    # Weak password hashing
    return hashlib.md5(password.encode()).hexdigest()
'''
                (Path(test_dir) / f"file_{i}.py").write_text(file_content)
            
            try:
                start_time = time.time()
                results = await self.scanner.run_full_analysis(test_dir, f'http://localhost:500{scan_id}')
                end_time = time.time()
                
                return {
                    'scan_id': scan_id,
                    'duration': end_time - start_time,
                    'vulnerabilities_found': results.get('vulnerabilities_found', 0),
                    'success': True
                }
            except Exception as e:
                return {
                    'scan_id': scan_id,
                    'success': False,
                    'error': str(e)
                }
            finally:
                shutil.rmtree(test_dir)
        
        try:
            start_time = time.time()
            
            # Run concurrent scans
            tasks = [run_single_scan(i) for i in range(concurrent_count)]
            results = await asyncio.gather(*tasks)
            
            end_time = time.time()
            total_duration = end_time - start_time
            
            successful_scans = [r for r in results if r.get('success', False)]
            failed_scans = [r for r in results if not r.get('success', False)]
            
            test_result = {
                'test_name': f'Concurrent Scans ({concurrent_count})',
                'concurrent_count': concurrent_count,
                'total_duration': total_duration,
                'successful_scans': len(successful_scans),
                'failed_scans': len(failed_scans),
                'average_duration': sum(r.get('duration', 0) for r in successful_scans) / len(successful_scans) if successful_scans else 0,
                'total_vulnerabilities': sum(r.get('vulnerabilities_found', 0) for r in successful_scans),
                'success': len(failed_scans) == 0
            }
            
            logger.info(f"✅ Concurrent scans test completed: {len(successful_scans)}/{concurrent_count} successful")
            return test_result
            
        except Exception as e:
            logger.error(f"❌ Concurrent scans test failed: {str(e)}")
            return {'test_name': f'Concurrent Scans ({concurrent_count})', 'success': False, 'error': str(e)}
    
    async def test_memory_usage(self):
        """Test memory usage with various codebase sizes"""
        logger.info("💾 Testing memory usage...")
        
        memory_tests = [
            {'files': 10, 'name': 'Small'},
            {'files': 50, 'name': 'Medium'},
            {'files': 100, 'name': 'Large'},
            {'files': 200, 'name': 'Very Large'}
        ]
        
        results = []
        
        for test_config in memory_tests:
            test_dir = tempfile.mkdtemp()
            
            # Create test files
            for i in range(test_config['files']):
                file_content = f'''
# Memory test file {i}
import sqlite3
import hashlib
import subprocess
import requests
import json
import os
import pickle
import yaml

class MemoryTestClass{i}:
    def __init__(self):
        self.data = {{}}
        for j in range(100):
            self.data[f'key_{{j}}'] = f'value_{{j}}' * 100
    
    def vulnerable_method_{i}(self, user_input):
        # Multiple vulnerabilities
        query = f"SELECT * FROM table WHERE id = '{{user_input}}'"
        conn = sqlite3.connect('db.sqlite')
        result = conn.execute(query).fetchall()
        
        # XSS
        html = f"<h1>{{user_input}}</h1>"
        
        # Command injection
        subprocess.run(f"echo {{user_input}}", shell=True)
        
        # Weak crypto
        hash_val = hashlib.md5(user_input.encode()).hexdigest()
        
        return {{
            'query_result': result,
            'html': html,
            'hash': hash_val
        }}
'''
                (Path(test_dir) / f"memory_test_{i}.py").write_text(file_content)
            
            try:
                # Measure memory before scan
                process = psutil.Process()
                memory_before = process.memory_info().rss / 1024 / 1024  # MB
                
                # Run scan
                scan_results = await self.scanner.run_full_analysis(test_dir, 'http://localhost:5000')
                
                # Measure memory after scan
                memory_after = process.memory_info().rss / 1024 / 1024  # MB
                memory_used = memory_after - memory_before
                
                result = {
                    'test_name': f"Memory Test - {test_config['name']} ({test_config['files']} files)",
                    'file_count': test_config['files'],
                    'memory_used_mb': memory_used,
                    'vulnerabilities_found': scan_results.get('vulnerabilities_found', 0),
                    'success': True
                }
                
                results.append(result)
                logger.info(f"✅ Memory test {test_config['name']}: {memory_used:.2f}MB used")
                
            except Exception as e:
                logger.error(f"❌ Memory test {test_config['name']} failed: {str(e)}")
                results.append({
                    'test_name': f"Memory Test - {test_config['name']}",
                    'success': False,
                    'error': str(e)
                })
            finally:
                shutil.rmtree(test_dir)
        
        return results
    
    async def test_edge_cases(self):
        """Test various edge cases"""
        logger.info("🔍 Testing edge cases...")
        
        edge_cases = [
            {
                'name': 'Empty Directory',
                'setup': lambda test_dir: None
            },
            {
                'name': 'Single File',
                'setup': lambda test_dir: (Path(test_dir) / "single.py").write_text("print('hello')")
            },
            {
                'name': 'Binary Files Only',
                'setup': lambda test_dir: (Path(test_dir) / "binary.bin").write_bytes(b'\x00\x01\x02\x03')
            },
            {
                'name': 'Very Large File',
                'setup': lambda test_dir: (Path(test_dir) / "large.py").write_text("# " + "x" * 1000000)
            },
            {
                'name': 'Nested Directories',
                'setup': lambda test_dir: self._create_nested_structure(test_dir)
            },
            {
                'name': 'Special Characters in Filenames',
                'setup': lambda test_dir: (Path(test_dir) / "file with spaces.py").write_text("print('test')")
            }
        ]
        
        results = []
        
        for edge_case in edge_cases:
            test_dir = tempfile.mkdtemp()
            
            try:
                edge_case['setup'](test_dir)
                
                start_time = time.time()
                scan_results = await self.scanner.run_full_analysis(test_dir, 'http://localhost:5000')
                end_time = time.time()
                
                result = {
                    'test_name': f"Edge Case - {edge_case['name']}",
                    'duration': end_time - start_time,
                    'total_files': scan_results.get('total_files', 0),
                    'vulnerabilities_found': scan_results.get('vulnerabilities_found', 0),
                    'success': True
                }
                
                results.append(result)
                logger.info(f"✅ Edge case {edge_case['name']}: {result['vulnerabilities_found']} vulnerabilities found")
                
            except Exception as e:
                logger.error(f"❌ Edge case {edge_case['name']} failed: {str(e)}")
                results.append({
                    'test_name': f"Edge Case - {edge_case['name']}",
                    'success': False,
                    'error': str(e)
                })
            finally:
                shutil.rmtree(test_dir)
        
        return results
    
    def _create_nested_structure(self, test_dir):
        """Create nested directory structure"""
        # Create nested directories
        nested_dir = Path(test_dir) / "src" / "app" / "controllers"
        nested_dir.mkdir(parents=True)
        
        # Create files in nested directories
        (nested_dir / "user_controller.py").write_text("""
import sqlite3

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect('db.sqlite')
    return conn.execute(query).fetchall()
""")
        
        (Path(test_dir) / "src" / "app" / "models.py").write_text("""
import hashlib

class User:
    def __init__(self, password):
        self.password_hash = hashlib.md5(password.encode()).hexdigest()
""")
    
    async def run_all_performance_tests(self):
        """Run all performance tests"""
        logger.info("🚀 Starting performance and stress tests...")
        
        all_results = []
        
        # Large codebase tests
        for file_count in [50, 100, 200]:
            result = await self.test_large_codebase_performance(file_count)
            all_results.append(result)
        
        # Concurrent scans test
        concurrent_result = await self.test_concurrent_scans(3)
        all_results.append(concurrent_result)
        
        # Memory usage tests
        memory_results = await self.test_memory_usage()
        all_results.extend(memory_results)
        
        # Edge cases tests
        edge_results = await self.test_edge_cases()
        all_results.extend(edge_results)
        
        # Generate summary
        self.generate_performance_summary(all_results)
        return all_results
    
    def generate_performance_summary(self, results):
        """Generate performance test summary"""
        logger.info("📊 Generating performance summary...")
        
        successful_tests = [r for r in results if r.get('success', False)]
        failed_tests = [r for r in results if not r.get('success', False)]
        
        # Calculate performance metrics
        durations = [r.get('duration', 0) for r in successful_tests if 'duration' in r]
        memory_usage = [r.get('memory_used_mb', 0) for r in successful_tests if 'memory_used_mb' in r]
        
        summary = {
            'total_tests': len(results),
            'successful_tests': len(successful_tests),
            'failed_tests': len(failed_tests),
            'performance_metrics': {
                'average_duration': sum(durations) / len(durations) if durations else 0,
                'max_duration': max(durations) if durations else 0,
                'min_duration': min(durations) if durations else 0,
                'average_memory_usage': sum(memory_usage) / len(memory_usage) if memory_usage else 0,
                'max_memory_usage': max(memory_usage) if memory_usage else 0
            },
            'test_results': results
        }
        
        # Save summary
        with open('dynamic_scanner_performance_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info("📊 Performance Summary:")
        logger.info(f"   Total Tests: {len(results)}")
        logger.info(f"   Successful: {len(successful_tests)}")
        logger.info(f"   Failed: {len(failed_tests)}")
        if durations:
            logger.info(f"   Average Duration: {summary['performance_metrics']['average_duration']:.2f}s")
            logger.info(f"   Max Duration: {summary['performance_metrics']['max_duration']:.2f}s")
        if memory_usage:
            logger.info(f"   Average Memory: {summary['performance_metrics']['average_memory_usage']:.2f}MB")
            logger.info(f"   Max Memory: {summary['performance_metrics']['max_memory_usage']:.2f}MB")
        logger.info(f"   Summary saved to: dynamic_scanner_performance_summary.json")

async def main():
    """Main performance test function"""
    print("⚡ Performance and Stress Testing for Dynamic Scanner")
    print("=" * 60)
    
    tester = PerformanceTester()
    results = await tester.run_all_performance_tests()
    
    print("\n🎉 Performance testing completed!")
    print("Check 'dynamic_scanner_performance_summary.json' for detailed results.")

if __name__ == "__main__":
    asyncio.run(main())
