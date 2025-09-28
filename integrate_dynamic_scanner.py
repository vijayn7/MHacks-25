#!/usr/bin/env python3
"""
Integration script for Dynamic Scanner

This script shows how to integrate the Gemini-powered dynamic scanner
with the existing Swarm security platform.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
import logging

# Add the scanner directory to the path
sys.path.append(str(Path(__file__).parent / "scanner"))

from dynamic_scanner import DynamicScanner
from scanner_orchestrator import ScannerOrchestrator

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EnhancedScannerOrchestrator(ScannerOrchestrator):
    """
    Enhanced Scanner Orchestrator that includes the Dynamic Scanner
    """
    
    def __init__(self):
        super().__init__()
        self.dynamic_scanner = None
        
        # Initialize dynamic scanner if API key is available
        if os.getenv("GEMINI_API_KEY"):
            try:
                self.dynamic_scanner = DynamicScanner()
                logger.info("✅ Dynamic Scanner initialized successfully")
            except Exception as e:
                logger.warning(f"⚠️ Dynamic Scanner initialization failed: {str(e)}")
        else:
            logger.warning("⚠️ GEMINI_API_KEY not set - Dynamic Scanner disabled")
    
    async def run_enhanced_scan(self, target_url: str, codebase_path: str = None, max_pages: int = 10):
        """
        Run enhanced security scan with dynamic analysis
        
        Args:
            target_url: URL to scan
            codebase_path: Path to codebase for dynamic analysis
            max_pages: Maximum pages to crawl
            
        Returns:
            Enhanced scan results with dynamic analysis
        """
        logger.info(f"🚀 Starting enhanced security scan for {target_url}")
        
        # Step 1: Run traditional scan
        logger.info("📊 Running traditional security scan...")
        traditional_results = await self.run_scan(target_url, max_pages)
        
        # Step 2: Run dynamic analysis if codebase provided
        dynamic_results = None
        if codebase_path and self.dynamic_scanner:
            logger.info("🤖 Running dynamic AI-powered analysis...")
            try:
                dynamic_results = await self.dynamic_scanner.run_full_analysis(
                    codebase_path, target_url
                )
                logger.info(f"✅ Dynamic analysis completed - {dynamic_results.get('vulnerabilities_found', 0)} vulnerabilities found")
            except Exception as e:
                logger.error(f"❌ Dynamic analysis failed: {str(e)}")
                dynamic_results = {"error": str(e)}
        
        # Step 3: Merge results
        enhanced_results = self._merge_scan_results(traditional_results, dynamic_results)
        
        # Step 4: Generate enhanced report
        enhanced_report = self._generate_enhanced_report(enhanced_results)
        
        return enhanced_report
    
    def _merge_scan_results(self, traditional_results: dict, dynamic_results: dict = None) -> dict:
        """Merge traditional and dynamic scan results"""
        
        merged = {
            "scan_id": traditional_results.get("run_id", "unknown"),
            "target_url": traditional_results.get("target_url", "unknown"),
            "scan_timestamp": traditional_results.get("timestamp", "unknown"),
            "traditional_scan": traditional_results,
            "dynamic_scan": dynamic_results,
            "total_vulnerabilities": 0,
            "vulnerability_categories": {},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
        
        # Count traditional vulnerabilities
        if "findings" in traditional_results:
            for finding in traditional_results["findings"]:
                severity = finding.get("severity", "medium").lower()
                merged["risk_summary"][severity] += 1
                merged["total_vulnerabilities"] += 1
                
                # Categorize vulnerabilities
                category = finding.get("category", "unknown")
                if category not in merged["vulnerability_categories"]:
                    merged["vulnerability_categories"][category] = 0
                merged["vulnerability_categories"][category] += 1
        
        # Count dynamic vulnerabilities
        if dynamic_results and "execution_results" in dynamic_results:
            for result in dynamic_results["execution_results"]:
                for vuln in result.get("vulnerabilities_found", []):
                    severity = vuln.get("severity", "medium").lower()
                    merged["risk_summary"][severity] += 1
                    merged["total_vulnerabilities"] += 1
                    
                    # Categorize vulnerabilities
                    category = result.get("category", "unknown")
                    if category not in merged["vulnerability_categories"]:
                        merged["vulnerability_categories"][category] = 0
                    merged["vulnerability_categories"][category] += 1
        
        return merged
    
    def _generate_enhanced_report(self, results: dict) -> dict:
        """Generate enhanced security report"""
        
        report = {
            "executive_summary": {
                "total_vulnerabilities": results["total_vulnerabilities"],
                "risk_distribution": results["risk_summary"],
                "scan_coverage": "Traditional + AI-Powered Dynamic Analysis",
                "recommendations": []
            },
            "vulnerability_breakdown": results["vulnerability_categories"],
            "detailed_findings": [],
            "ai_insights": [],
            "mitigation_guidance": []
        }
        
        # Add traditional findings
        if "traditional_scan" in results and "findings" in results["traditional_scan"]:
            for finding in results["traditional_scan"]["findings"]:
                report["detailed_findings"].append({
                    "source": "Traditional Scanner",
                    "type": finding.get("type", "Unknown"),
                    "severity": finding.get("severity", "Medium"),
                    "description": finding.get("description", ""),
                    "url": finding.get("url", ""),
                    "recommendation": finding.get("recommendation", "")
                })
        
        # Add dynamic findings
        if "dynamic_scan" in results and "execution_results" in results["dynamic_scan"]:
            for result in results["dynamic_scan"]["execution_results"]:
                for vuln in result.get("vulnerabilities_found", []):
                    report["detailed_findings"].append({
                        "source": "AI-Powered Dynamic Scanner",
                        "type": result.get("test_name", "Unknown"),
                        "severity": vuln.get("severity", "Medium"),
                        "description": vuln.get("description", ""),
                        "url": result.get("endpoint", ""),
                        "recommendation": vuln.get("mitigation", ""),
                        "ai_generated": True
                    })
        
        # Add AI insights
        if "dynamic_scan" in results and "code_analysis" in results["dynamic_scan"]:
            code_analysis = results["dynamic_scan"]["code_analysis"]
            report["ai_insights"] = [
                f"Analyzed {code_analysis.get('total_files', 0)} files across {len(code_analysis.get('languages', []))} programming languages",
                f"Detected {sum(code_analysis.get('security_patterns', {}).values())} security-relevant code patterns",
                f"Generated {len(results['dynamic_scan'].get('test_cases', []))} AI-powered test cases",
                f"Executed {len(results['dynamic_scan'].get('execution_results', []))} dynamic security tests"
            ]
        
        # Generate recommendations
        if results["total_vulnerabilities"] > 0:
            report["executive_summary"]["recommendations"] = [
                "Immediate action required for Critical and High severity vulnerabilities",
                "Implement input validation and output encoding",
                "Review and update authentication mechanisms",
                "Apply security patches and updates",
                "Conduct regular security assessments"
            ]
        
        return report

async def demo_enhanced_scanner():
    """Demonstrate the enhanced scanner with dynamic analysis"""
    logger.info("🚀 Starting Enhanced Scanner Demo")
    
    # Initialize enhanced orchestrator
    orchestrator = EnhancedScannerOrchestrator()
    
    # Demo parameters
    target_url = "https://httpbin.org"  # Safe test target
    codebase_path = None  # No codebase for this demo
    
    # Check if we have a sample codebase
    sample_codebase = Path("sample_vulnerable_app")
    if sample_codebase.exists():
        codebase_path = str(sample_codebase)
        logger.info(f"📁 Using sample codebase: {codebase_path}")
    
    try:
        # Run enhanced scan
        results = await orchestrator.run_enhanced_scan(
            target_url=target_url,
            codebase_path=codebase_path,
            max_pages=5
        )
        
        # Display results
        logger.info("📊 Enhanced Scan Results:")
        logger.info(f"   Total Vulnerabilities: {results['executive_summary']['total_vulnerabilities']}")
        logger.info(f"   Risk Distribution: {results['executive_summary']['risk_distribution']}")
        logger.info(f"   Scan Coverage: {results['executive_summary']['scan_coverage']}")
        
        # Display vulnerability breakdown
        if results['vulnerability_breakdown']:
            logger.info("🔍 Vulnerability Breakdown:")
            for category, count in results['vulnerability_breakdown'].items():
                logger.info(f"   {category}: {count}")
        
        # Display AI insights
        if results['ai_insights']:
            logger.info("🤖 AI Insights:")
            for insight in results['ai_insights']:
                logger.info(f"   • {insight}")
        
        # Display detailed findings
        if results['detailed_findings']:
            logger.info("📋 Detailed Findings:")
            for finding in results['detailed_findings'][:5]:  # Show first 5
                source = finding.get('source', 'Unknown')
                severity = finding.get('severity', 'Unknown')
                finding_type = finding.get('type', 'Unknown')
                logger.info(f"   [{source}] {severity}: {finding_type}")
        
        # Save results
        output_file = "enhanced_scan_results.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"💾 Enhanced scan results saved to: {output_file}")
        
        logger.info("✅ Enhanced Scanner Demo completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Enhanced scanner demo failed: {str(e)}")
        raise

def main():
    """Main function"""
    print("🔐 Enhanced Security Scanner Demo")
    print("=" * 50)
    print()
    
    # Check for Gemini API key
    if not os.getenv("GEMINI_API_KEY"):
        print("⚠️  GEMINI_API_KEY not set - Dynamic Scanner will be disabled")
        print("   Set your API key to enable AI-powered analysis:")
        print("   export GEMINI_API_KEY='your-api-key-here'")
        print()
    
    # Run demo
    asyncio.run(demo_enhanced_scanner())

if __name__ == "__main__":
    main()

