"""
Quick CVE Check - Test specific CVEs in Tenable
Usage: 
  python quick_check.py CVE-2024-1234                    # Clean output
  python quick_check.py CVE-2024-1234 --debug            # Verbose debugging
  python quick_check.py CVE-2024-1234 CVE-2024-5678      # Multiple CVEs

Features:
  - Clean, executive-ready output by default
  - Detailed debugging with --debug flag
  - Multiple CVE checking in one run
  - Color-coded severity indicators
"""

import sys
import os
import json
from datetime import datetime
from dotenv import load_dotenv

# Import the checker class
from tenable_checker import TenableCVEChecker

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_header(text, color=Colors.CYAN):
    """Print a formatted header"""
    print(f"\n{color}{Colors.BOLD}{'=' * 70}{Colors.RESET}")
    print(f"{color}{Colors.BOLD}{text:^70}{Colors.RESET}")
    print(f"{color}{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

def print_subheader(text):
    """Print a formatted subheader"""
    print(f"\n{Colors.BOLD}{text}{Colors.RESET}")
    print(f"{'-' * len(text)}")

def get_severity_color(severity):
    """Get color based on severity"""
    severity_lower = str(severity).lower()
    if severity_lower == 'critical':
        return Colors.RED
    elif severity_lower == 'high':
        return Colors.YELLOW
    elif severity_lower == 'medium':
        return Colors.BLUE
    elif severity_lower == 'low':
        return Colors.GREEN
    return Colors.WHITE

def print_cve_result_clean(cve_id, result):
    """Print clean, executive-ready CVE result"""
    print(f"\n{Colors.BOLD}CVE: {cve_id}{Colors.RESET}")
    
    if result['exploitable']:
        severity_color = get_severity_color(result['severity'])
        print(f"  Status:           {Colors.RED}{Colors.BOLD}🚨 VULNERABLE{Colors.RESET}")
        print(f"  Affected Assets:  {Colors.RED}{Colors.BOLD}{result['affected_assets']}{Colors.RESET}")
        print(f"  Severity:         {severity_color}{Colors.BOLD}{result['severity'].upper()}{Colors.RESET}")
        print(f"  Details:          {result['details']}")
        print(f"  {Colors.RED}{Colors.BOLD}⚠️  ACTION REQUIRED{Colors.RESET}")
    elif result['exploitable'] is False:
        print(f"  Status:           {Colors.GREEN}✓ Not Found in Environment{Colors.RESET}")
        print(f"  Details:          {result['details']}")
    else:
        print(f"  Status:           {Colors.YELLOW}⚠ Check Failed{Colors.RESET}")
        print(f"  Details:          {result['details']}")

def print_cve_result_debug(cve_id, result, debug_info=None):
    """Print detailed debugging information"""
    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}CVE: {cve_id} (DEBUG MODE){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    
    # Result overview
    print(f"\n{Colors.BOLD}Result Overview:{Colors.RESET}")
    print(f"  Exploitable:      {result['exploitable']}")
    print(f"  Affected Assets:  {result['affected_assets']}")
    print(f"  Severity:         {result['severity']}")
    print(f"  Details:          {result['details']}")
    
    # Debug info if available
    if debug_info:
        print(f"\n{Colors.BOLD}API Debug Info:{Colors.RESET}")
        for key, value in debug_info.items():
            print(f"  {key}: {value}")

def print_summary(results):
    """Print executive summary of all checks"""
    print_subheader("Executive Summary")
    
    total = len(results)
    vulnerable = sum(1 for r in results if r['result']['exploitable'])
    not_found = sum(1 for r in results if r['result']['exploitable'] is False)
    errors = sum(1 for r in results if r['result']['exploitable'] is None)
    
    print(f"  Total CVEs Checked:     {total}")
    print(f"  {Colors.RED}🚨 Vulnerable in Environment: {vulnerable}{Colors.RESET}")
    print(f"  {Colors.GREEN}✓ Not Found:                 {not_found}{Colors.RESET}")
    print(f"  {Colors.YELLOW}⚠ Errors:                    {errors}{Colors.RESET}")
    
    if vulnerable > 0:
        print(f"\n  {Colors.RED}{Colors.BOLD}⚠️  ATTENTION: {vulnerable} CVE(s) require immediate remediation{Colors.RESET}")
        print(f"\n{Colors.BOLD}Vulnerable CVEs:{Colors.RESET}")
        for r in results:
            if r['result']['exploitable']:
                severity_color = get_severity_color(r['result']['severity'])
                print(f"    • {r['cve_id']}: {r['result']['affected_assets']} asset(s) - {severity_color}{r['result']['severity'].upper()}{Colors.RESET}")

def main():
    # Parse arguments
    args = sys.argv[1:]
    debug_mode = '--debug' in args or '-d' in args
    
    # Remove debug flags from CVE list
    cve_ids = [arg for arg in args if not arg.startswith('-')]
    
    if not cve_ids:
        print(f"{Colors.BOLD}Hyperion CTI - Quick CVE Check{Colors.RESET}")
        print("\nUsage:")
        print("  python quick_check.py CVE-2024-1234                    # Clean output")
        print("  python quick_check.py CVE-2024-1234 --debug            # Debug output")
        print("  python quick_check.py CVE-2024-1234 CVE-2024-5678      # Multiple CVEs")
        print("\nFlags:")
        print("  --debug, -d    Enable verbose debugging output")
        print("\nExamples:")
        print("  python quick_check.py CVE-2021-44228")
        print("  python quick_check.py CVE-2025-62215 --debug")
        sys.exit(1)
    
    # Header
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if debug_mode:
        print_header(f"Hyperion CTI - CVE Check (DEBUG MODE)\n{timestamp}")
    else:
        print_header(f"Hyperion CTI - Quick CVE Check\n{timestamp}")
    
    # Initialize checker
    checker = TenableCVEChecker()
    
    # Test connection (quiet mode unless debug)
    if debug_mode:
        print(f"{Colors.BOLD}Testing Tenable API connection...{Colors.RESET}")
    
    if not checker.test_tenable_connection():
        print(f"\n{Colors.RED}✗ Cannot connect to Tenable API{Colors.RESET}")
        print("  Please check your API keys in the .env file")
        sys.exit(1)
    
    if not debug_mode:
        print(f"{Colors.GREEN}✓ Connected to Tenable{Colors.RESET}")
    
    # Check CVEs
    print(f"\n{Colors.BOLD}Checking {len(cve_ids)} CVE(s)...{Colors.RESET}")
    
    results = []
    for i, cve_id in enumerate(cve_ids, 1):
        if debug_mode:
            print(f"\n{Colors.CYAN}[{i}/{len(cve_ids)}] Checking {cve_id}...{Colors.RESET}")
        else:
            print(f"  [{i}/{len(cve_ids)}] {cve_id}...", end=" ")
        
        result = checker.check_cve_in_tenable(cve_id)
        results.append({'cve_id': cve_id, 'result': result})
        
        if not debug_mode:
            if result['exploitable']:
                print(f"{Colors.RED}🚨 VULNERABLE{Colors.RESET}")
            elif result['exploitable'] is False:
                print(f"{Colors.GREEN}✓ Clear{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}⚠ Error{Colors.RESET}")
    
    # Print results
    print_subheader("Detailed Results")
    
    for item in results:
        if debug_mode:
            print_cve_result_debug(item['cve_id'], item['result'])
        else:
            print_cve_result_clean(item['cve_id'], item['result'])
    
    # Print summary
    if len(results) > 1:
        print("\n")
        print_summary(results)
    
    # Footer
    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}Check completed at {datetime.now().strftime('%H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}\n")
    
    # Exit code based on results
    if any(r['result']['exploitable'] for r in results):
        sys.exit(1)  # Exit with error code if vulnerabilities found
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()