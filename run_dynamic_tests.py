#!/usr/bin/env python3
"""
Quick Test Runner for Dynamic Scanner

This script provides easy commands to run different types of tests
for the dynamic scanner beyond basic test cases.
"""

import asyncio
import sys
import argparse
from pathlib import Path

# Add scanner directory to path
sys.path.append(str(Path(__file__).parent / "scanner"))

def print_banner():
    """Print test runner banner"""
    print("🧪 Dynamic Scanner Test Runner")
    print("=" * 40)
    print("Choose your testing approach:")
    print()

def run_advanced_tests():
    """Run advanced test suite"""
    print("🚀 Running Advanced Test Suite...")
    print("This includes:")
    print("  - Vulnerable Flask application")
    print("  - Multi-language codebase")
    print("  - Large codebase performance")
    print("  - Specific attack categories")
    print()
    
    import subprocess
    result = subprocess.run([sys.executable, "test_dynamic_scanner_advanced.py"], 
                          capture_output=True, text=True)
    
    print("STDOUT:")
    print(result.stdout)
    if result.stderr:
        print("STDERR:")
        print(result.stderr)
    
    return result.returncode == 0

def run_real_world_tests():
    """Run real-world application tests"""
    print("🌍 Running Real-World Application Tests...")
    print("This includes:")
    print("  - E-commerce application")
    print("  - API-only application")
    print("  - Production-like vulnerabilities")
    print()
    
    import subprocess
    result = subprocess.run([sys.executable, "test_real_world_app.py"], 
                          capture_output=True, text=True)
    
    print("STDOUT:")
    print(result.stdout)
    if result.stderr:
        print("STDERR:")
        print(result.stderr)
    
    return result.returncode == 0

def run_performance_tests():
    """Run performance and stress tests"""
    print("⚡ Running Performance and Stress Tests...")
    print("This includes:")
    print("  - Large codebase performance")
    print("  - Concurrent scan testing")
    print("  - Memory usage analysis")
    print("  - Edge case testing")
    print()
    
    import subprocess
    result = subprocess.run([sys.executable, "test_dynamic_scanner_performance.py"], 
                          capture_output=True, text=True)
    
    print("STDOUT:")
    print(result.stdout)
    if result.stderr:
        print("STDERR:")
        print(result.stderr)
    
    return result.returncode == 0

async def run_quick_test():
    """Run a quick test with a simple vulnerable app"""
    print("⚡ Running Quick Test...")
    print("Creating a simple vulnerable application for testing...")
    
    from dynamic_scanner import DynamicScanner
    import tempfile
    import shutil
    
    # Create simple vulnerable app
    test_dir = tempfile.mkdtemp()
    
    vulnerable_code = '''
from flask import Flask, request, jsonify
import sqlite3
import hashlib

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # SQL Injection vulnerability
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    
    if user:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error'})

@app.route('/user/<int:user_id>')
def get_user(user_id):
    # IDOR vulnerability
    conn = sqlite3.connect('users.db')
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user:
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2]
        })
    else:
        return jsonify({'error': 'User not found'})

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # XSS vulnerability
    return f"<h1>Search Results for: {query}</h1>"

if __name__ == '__main__':
    app.run(debug=True)
'''
    
    (Path(test_dir) / "app.py").write_text(vulnerable_code)
    
    try:
        scanner = DynamicScanner()
        results = await scanner.run_full_analysis(test_dir, 'http://localhost:5000')
        
        print(f"✅ Quick test completed!")
        print(f"   Files analyzed: {results.get('total_files', 0)}")
        print(f"   Test cases generated: {results.get('total_tests', 0)}")
        print(f"   Vulnerabilities found: {results.get('vulnerabilities_found', 0)}")
        print(f"   AI-generated findings: {len(results.get('owasp_findings', []))}")
        print(f"   Languages detected: {', '.join(results.get('languages', []))}")
        
        if results.get('owasp_findings'):
            print("\n🔍 Sample AI-Generated Findings:")
            for i, finding in enumerate(results['owasp_findings'][:3]):
                print(f"   {i+1}. {finding.get('title', 'N/A')} ({finding.get('severity', 'N/A')})")
        
        return True
        
    except Exception as e:
        print(f"❌ Quick test failed: {str(e)}")
        return False
    finally:
        shutil.rmtree(test_dir)

def show_test_results():
    """Show results from previous test runs"""
    print("📊 Test Results Summary")
    print("=" * 30)
    
    result_files = [
        "dynamic_scanner_test_summary.json",
        "real_world_app_test_summary.json", 
        "dynamic_scanner_performance_summary.json"
    ]
    
    for file_path in result_files:
        if Path(file_path).exists():
            print(f"\n📁 {file_path}:")
            try:
                import json
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                if 'total_tests' in data:
                    print(f"   Total Tests: {data['total_tests']}")
                    print(f"   Successful: {data.get('successful_tests', 0)}")
                    print(f"   Failed: {data.get('failed_tests', 0)}")
                
                if 'total_vulnerabilities_found' in data:
                    print(f"   Vulnerabilities Found: {data['total_vulnerabilities_found']}")
                
                if 'total_ai_generated_findings' in data:
                    print(f"   AI-Generated Findings: {data['total_ai_generated_findings']}")
                
                if 'performance_metrics' in data:
                    metrics = data['performance_metrics']
                    print(f"   Average Duration: {metrics.get('average_duration', 0):.2f}s")
                    print(f"   Max Memory Usage: {metrics.get('max_memory_usage', 0):.2f}MB")
                    
            except Exception as e:
                print(f"   Error reading file: {e}")
        else:
            print(f"\n📁 {file_path}: Not found")

def main():
    """Main test runner function"""
    parser = argparse.ArgumentParser(description='Dynamic Scanner Test Runner')
    parser.add_argument('--test', choices=['advanced', 'real-world', 'performance', 'quick', 'results'], 
                       help='Type of test to run')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.all:
        print("🚀 Running ALL tests...")
        print()
        
        # Run quick test first
        print("1. Quick Test")
        success = asyncio.run(run_quick_test())
        print()
        
        if success:
            # Run advanced tests
            print("2. Advanced Tests")
            run_advanced_tests()
            print()
            
            # Run real-world tests
            print("3. Real-World Tests")
            run_real_world_tests()
            print()
            
            # Run performance tests
            print("4. Performance Tests")
            run_performance_tests()
            print()
        
        print("🎉 All tests completed!")
        show_test_results()
        
    elif args.test == 'advanced':
        run_advanced_tests()
    elif args.test == 'real-world':
        run_real_world_tests()
    elif args.test == 'performance':
        run_performance_tests()
    elif args.test == 'quick':
        asyncio.run(run_quick_test())
    elif args.test == 'results':
        show_test_results()
    else:
        print("Available test types:")
        print("  --test advanced     - Run advanced test suite")
        print("  --test real-world   - Run real-world application tests")
        print("  --test performance  - Run performance and stress tests")
        print("  --test quick        - Run quick test")
        print("  --test results      - Show previous test results")
        print("  --all               - Run all tests")
        print()
        print("Examples:")
        print("  python run_dynamic_tests.py --test quick")
        print("  python run_dynamic_tests.py --test advanced")
        print("  python run_dynamic_tests.py --all")

if __name__ == "__main__":
    main()
