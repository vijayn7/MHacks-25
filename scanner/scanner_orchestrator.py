import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from base_scanner import BaseScanner

# Import all scanners
from header_scanner import HeaderScanner
from injection_scanner import InjectionScanner
from access_control_scanner import AccessControlScanner
from auth_scanner import AuthScanner
from crypto_scanner import CryptoScanner
from vulnerable_components_scanner import VulnerableComponentsScanner
from integrity_logging_ssrf_design_scanner import IntegrityScanner, LoggingScanner, SSRFScanner, DesignScanner


class ScannerOrchestrator:
    """Orchestrates all security scanners for comprehensive OWASP Top 10 coverage"""

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.scanners = [
            HeaderScanner(run_id),           # A05 - Security Misconfiguration
            InjectionScanner(run_id),         # A03 - Injection
            AccessControlScanner(run_id),     # A01 - Broken Access Control
            AuthScanner(run_id),              # A07 - Identification and Authentication Failures
            CryptoScanner(run_id),            # A02 - Cryptographic Failures
            VulnerableComponentsScanner(run_id), # A06 - Vulnerable and Outdated Components
            IntegrityScanner(run_id),         # A08 - Software and Data Integrity Failures
            LoggingScanner(run_id),           # A09 - Security Logging and Monitoring Failures
            SSRFScanner(run_id),              # A10 - Server-Side Request Forgery
            DesignScanner(run_id)             # A04 - Insecure Design
        ]
        self.all_findings = []
        self.scan_summary = {}

    def scan_all(self, pages_file: Path) -> Dict:
        """Run all scanners on the provided pages data"""

        print(f"🚀 Starting comprehensive security scan for run {self.run_id}")
        print(f"📊 Running {len(self.scanners)} specialized scanners")
        print(f"📁 Input file: {pages_file}")
        print(f"📁 File exists: {pages_file.exists()}")
        
        # Check if pages file exists and is readable
        if not pages_file.exists():
            print(f"❌ ERROR: Pages file {pages_file} does not exist!")
            print(f"💡 Make sure to run the crawler first to generate pages.json")
            return {"error": "Pages file not found"}
        
        # Check file size and content
        file_size = pages_file.stat().st_size
        print(f"📏 File size: {file_size} bytes")
        
        if file_size == 0:
            print(f"❌ ERROR: Pages file is empty!")
            return {"error": "Pages file is empty"}
        
        # Try to load and validate the pages data
        try:
            with open(pages_file, 'r') as f:
                data = json.load(f)
            
            pages_count = len(data.get('pages', []))
            print(f"📄 Pages loaded: {pages_count}")
            
            if pages_count == 0:
                print(f"❌ ERROR: No pages found in the data!")
                return {"error": "No pages found"}
            
            # Show sample page data
            sample_page = data['pages'][0] if data['pages'] else {}
            print(f"🔍 Sample page URL: {sample_page.get('url', 'N/A')}")
            print(f"🔍 Sample page status: {sample_page.get('status_code', 'N/A')}")
            print(f"🔍 Sample page headers count: {len(sample_page.get('headers', {}))}")
            print(f"🔍 Sample page forms count: {len(sample_page.get('forms', []))}")
            print(f"🔍 Sample page scripts count: {len(sample_page.get('scripts', []))}")
            
        except json.JSONDecodeError as e:
            print(f"❌ ERROR: Invalid JSON in pages file: {str(e)}")
            return {"error": "Invalid JSON format"}
        except Exception as e:
            print(f"❌ ERROR: Failed to load pages file: {str(e)}")
            return {"error": "Failed to load pages file"}
        
        start_time = datetime.now()
        
        for i, scanner in enumerate(self.scanners, 1):
            print(f"\n🔍 [{i}/{len(self.scanners)}] Running {scanner.scanner_name}...")
            print(f"   📋 Scanner class: {scanner.__class__.__name__}")
            print(f"   🆔 Run ID: {scanner.run_id}")
            
            try:
                findings = scanner.scan_pages(pages_file)
                self.all_findings.extend(findings)
                print(f"   ✅ {scanner.scanner_name} completed: {len(findings)} findings")
                
                # Show sample findings
                if findings:
                    sample_finding = findings[0]
                    print(f"   📝 Sample finding: {sample_finding.get('title', 'N/A')} ({sample_finding.get('severity', 'N/A')})")
                else:
                    print(f"   ℹ️  No findings detected by {scanner.scanner_name}")
                    
            except Exception as e:
                print(f"   ❌ {scanner.scanner_name} failed: {str(e)}")
                import traceback
                print(f"   🔍 Full error traceback:")
                traceback.print_exc()
                continue

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Generate comprehensive summary
        self.scan_summary = self._generate_summary(duration)
        
        print(f"\n🎯 Scan completed in {duration:.2f} seconds")
        print(f"📈 Total findings: {len(self.all_findings)}")
        
        # Show detailed breakdown
        if self.all_findings:
            print(f"\n📊 Findings breakdown:")
            severity_counts = self.scan_summary['severity_breakdown']
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"   {severity.upper()}: {count}")
            
            print(f"\n🏷️  OWASP Categories:")
            owasp_counts = self.scan_summary['owasp_category_breakdown']
            for category, count in owasp_counts.items():
                if count > 0:
                    print(f"   {category}: {count}")
        else:
            print(f"\n✅ No security issues found!")
        
        return self.scan_summary

    def _generate_summary(self, duration: float) -> Dict:
        """Generate comprehensive scan summary"""

        # Count findings by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        # Count findings by OWASP category
        owasp_counts = {}

        # Count findings by scanner
        scanner_counts = {}

        # Count findings by category
        category_counts = {}

        for finding in self.all_findings:
            # Severity counts
            severity = finding.get('severity', 'unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1

            # OWASP category counts
            owasp_cat = finding.get('owasp_category', 'Other')
            owasp_counts[owasp_cat] = owasp_counts.get(owasp_cat, 0) + 1

            # Scanner counts
            scanner = finding.get('scanner', 'Unknown')
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

            # Category counts
            category = finding.get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1

        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_counts)

        # Get top findings by priority
        top_findings = sorted(self.all_findings, key=lambda x: x.get('priority_score', 0), reverse=True)[:10]

        return {
            'run_id': self.run_id,
            'scan_timestamp': datetime.now().isoformat(),
            'duration_seconds': round(duration, 2),
            'total_findings': len(self.all_findings),
            'risk_score': risk_score,
            'severity_breakdown': severity_counts,
            'owasp_category_breakdown': owasp_counts,
            'scanner_breakdown': scanner_counts,
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
            'scanners_run': [scanner.scanner_name for scanner in self.scanners],
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
        """Calculate overall risk score based on findings"""

        # Weighted scoring
        weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }

        total_score = 0
        for severity, count in severity_counts.items():
            total_score += count * weights.get(severity, 0)

        # Normalize to 0-100 scale
        max_possible_score = sum(severity_counts.values()) * 10
        if max_possible_score > 0:
            risk_score = min(100, int((total_score / max_possible_score) * 100))
        else:
            risk_score = 0

        return risk_score

    def save_comprehensive_report(self, output_dir: Path):
        """Save comprehensive security report"""

        output_dir.mkdir(parents=True, exist_ok=True)

        # Save individual scanner findings
        for scanner in self.scanners:
            scanner.save_findings(output_dir)

        # Save comprehensive report
        comprehensive_report = {
            'scan_summary': self.scan_summary,
            'all_findings': self.all_findings,
            'detailed_breakdown': {
                'by_scanner': {},
                'by_owasp_category': {},
                'by_severity': {}
            }
        }

        # Detailed breakdown by scanner
        for scanner in self.scanners:
            scanner_findings = [f for f in self.all_findings if f.get('scanner') == scanner.scanner_name]
            comprehensive_report['detailed_breakdown']['by_scanner'][scanner.scanner_name] = {
                'findings_count': len(scanner_findings),
                'findings': scanner_findings
            }

        # Detailed breakdown by OWASP category
        for owasp_cat in self.scan_summary['owasp_category_breakdown'].keys():
            cat_findings = [f for f in self.all_findings if f.get('owasp_category') == owasp_cat]
            comprehensive_report['detailed_breakdown']['by_owasp_category'][owasp_cat] = {
                'findings_count': len(cat_findings),
                'findings': cat_findings
            }

        # Detailed breakdown by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_findings = [f for f in self.all_findings if f.get('severity') == severity]
            comprehensive_report['detailed_breakdown']['by_severity'][severity] = {
                'findings_count': len(severity_findings),
                'findings': severity_findings
            }

        # Save comprehensive report
        report_file = output_dir / f"comprehensive_security_report_{self.run_id}.json"
        with open(report_file, 'w') as f:
            json.dump(comprehensive_report, f, indent=2)

        print(f"📄 Comprehensive report saved to {report_file}")

        # Save executive summary
        self._save_executive_summary(output_dir)

    def _save_executive_summary(self, output_dir: Path):
        """Save executive summary for stakeholders"""

        summary = {
            'executive_summary': {
                'scan_date': self.scan_summary['scan_timestamp'],
                'total_vulnerabilities': self.scan_summary['total_findings'],
                'risk_score': self.scan_summary['risk_score'],
                'risk_level': self._get_risk_level(self.scan_summary['risk_score']),
                'critical_issues': self.scan_summary['severity_breakdown']['critical'],
                'high_issues': self.scan_summary['severity_breakdown']['high'],
                'medium_issues': self.scan_summary['severity_breakdown']['medium'],
                'low_issues': self.scan_summary['severity_breakdown']['low']
            },
            'top_risks': self.scan_summary['top_findings'][:5],
            'owasp_coverage': self.scan_summary['owasp_category_breakdown'],
            'recommendations': self._generate_recommendations()
        }

        summary_file = output_dir / f"executive_summary_{self.run_id}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"📋 Executive summary saved to {summary_file}")

    def _get_risk_level(self, risk_score: int) -> str:
        """Get risk level based on score"""

        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        elif risk_score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""

        recommendations = []

        # Critical findings recommendations
        critical_count = self.scan_summary['severity_breakdown']['critical']
        if critical_count > 0:
            recommendations.append(f"🚨 URGENT: Address {critical_count} critical vulnerabilities immediately")

        # High findings recommendations
        high_count = self.scan_summary['severity_breakdown']['high']
        if high_count > 0:
            recommendations.append(f"⚠️ HIGH PRIORITY: Fix {high_count} high-severity issues within 30 days")

        # OWASP category recommendations
        owasp_counts = self.scan_summary['owasp_category_breakdown']
        
        if owasp_counts.get('A03 - Injection', 0) > 0:
            recommendations.append("🔒 Implement input validation and parameterized queries to prevent injection attacks")

        if owasp_counts.get('A01 - Broken Access Control', 0) > 0:
            recommendations.append("🛡️ Review and implement proper access control mechanisms")

        if owasp_counts.get('A02 - Cryptographic Failures', 0) > 0:
            recommendations.append("🔐 Upgrade to strong cryptographic algorithms and enforce HTTPS")

        if owasp_counts.get('A05 - Security Misconfiguration', 0) > 0:
            recommendations.append("⚙️ Review server configuration and implement security headers")

        if owasp_counts.get('A06 - Vulnerable and Outdated Components', 0) > 0:
            recommendations.append("📦 Update all dependencies and components to latest secure versions")

        # General recommendations
        recommendations.extend([
            "🔄 Implement regular security scanning and monitoring",
            "📚 Provide security training for development team",
            "🛠️ Establish secure coding practices and code review process",
            "📊 Set up continuous security monitoring and alerting"
        ])

        return recommendations

    def get_findings_by_owasp_category(self, category: str) -> List[Dict]:
        """Get findings filtered by OWASP category"""

        return [f for f in self.all_findings if f.get('owasp_category') == category]

    def get_findings_by_severity(self, severity: str) -> List[Dict]:
        """Get findings filtered by severity"""

        return [f for f in self.all_findings if f.get('severity') == severity]

    def get_findings_by_scanner(self, scanner_name: str) -> List[Dict]:
        """Get findings filtered by scanner"""

        return [f for f in self.all_findings if f.get('scanner') == scanner_name]


def main():
    """Test the scanner orchestrator"""

    orchestrator = ScannerOrchestrator("test_run")
    
    test_pages = Path("test_pages.json")
    if test_pages.exists():
        summary = orchestrator.scan_all(test_pages)
        orchestrator.save_comprehensive_report(Path("."))
        
        print(f"\n🎯 Scan Summary:")
        print(f"  Total Findings: {summary['total_findings']}")
        print(f"  Risk Score: {summary['risk_score']}/100")
        print(f"  Critical: {summary['severity_breakdown']['critical']}")
        print(f"  High: {summary['severity_breakdown']['high']}")
        print(f"  Medium: {summary['severity_breakdown']['medium']}")
        print(f"  Low: {summary['severity_breakdown']['low']}")
        
        print(f"\n📊 OWASP Coverage:")
        for category, count in summary['owasp_category_breakdown'].items():
            print(f"  {category}: {count}")
            
    else:
        print("❌ No test_pages.json found. Run crawler first.")


if __name__ == "__main__":
    main()
