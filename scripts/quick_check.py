"""
Quick CVE Check - Test specific CVEs in Tenable
Usage: python quick_check.py CVE-2024-1234 CVE-2024-5678
"""

import sys
import os
import json
from dotenv import load_dotenv
from tenable_checker import TenableCVEChecker

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

def main():
    if len(sys.argv) < 2:
        print("Usage: python quick_check.py CVE-2024-1234 [CVE-2024-5678 ...]")
        print("\nExample:")
        print("  python quick_check.py CVE-2021-44228")
        print("  python quick_check.py CVE-2025-62215  # Test the specific CVE")
        sys.exit(1)
    
    cve_ids = sys.argv[1:]
    
    print("=" * 60)
    print("Hyperion CTI - Quick CVE Check (Diagnostic Mode)")
    print("=" * 60)
    
    checker = TenableCVEChecker()
    
    # Test connection
    if not checker.test_tenable_connection():
        print("\n✗ Cannot connect to Tenable. Check your API keys.")
        sys.exit(1)
    
    print(f"\nChecking {len(cve_ids)} CVE(s)...\n")
    
    for cve_id in cve_ids:
        print(f"\n{'='*60}")
        print(f"Checking {cve_id}...")
        print('='*60)
        
        # Try primary method
        print("\n[Method 1: Workbenches API]")
        result1 = checker._check_via_workbenches(cve_id)
        print(f"  Exploitable: {result1['exploitable']}")
        print(f"  Assets: {result1['affected_assets']}")
        print(f"  Severity: {result1['severity']}")
        print(f"  Details: {result1['details']}")
        
        # Try alternative method
        print("\n[Method 2: Vulnerabilities Search]")
        result2 = checker._check_via_vulnerabilities(cve_id)
        print(f"  Exploitable: {result2['exploitable']}")
        print(f"  Assets: {result2['affected_assets']}")
        print(f"  Severity: {result2['severity']}")
        print(f"  Details: {result2['details']}")
        
        # Final result
        print("\n[Final Result]")
        result = checker.check_cve_in_tenable(cve_id)
        
        if result['exploitable']:
            print(f"🚨 EXPLOITABLE - {result['affected_assets']} asset(s) affected!")
            print(f"   Severity: {result['severity']}")
            print(f"   Details: {result['details']}")
        elif result['exploitable'] is False:
            print(f"✓ Not found in environment")
        else:
            print(f"⚠ Error: {result['details']}")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()