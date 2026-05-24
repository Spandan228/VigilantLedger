# ============================================================================
# PROJECT: VigilantLedger
# FILE: verify_integration.py
# DESCRIPTION: Automated integration test script for validating RLS, CLS,
#              ledger integrity, and Sentinel alert detection.
# ============================================================================

import sys
from backend.db_client import execute_query, execute_non_query, execute_as_user
from backend.verifier import generate_digest, verify_ledger
from backend.sentinel import scan_for_anomalies, get_alerts, resolve_alert

def run_tests():
    print("======================================================================")
    print("           [VIGILANTLEDGER AUTOMATED SYSTEM TESTING]")
    print("======================================================================")
    
    # 1. Test Base Database Connectivity
    print("\n[*] Test 1: Testing basic database connectivity...")
    try:
        accounts = execute_query("SELECT COUNT(*) as cnt FROM Core.Accounts;")
        print(f"[+] Connection successful! Current Account Count: {accounts[0]['cnt']}")
    except Exception as e:
        print(f"[!] Test 1 Failed: Connection error: {e}")
        sys.exit(1)
        
    # 2. Test RLS and CLS Impersonation Policies
    print("\n[*] Test 2: Validating RLS and CLS for Alice (Staff Accountant)...")
    try:
        # Alice is in the East region, so she should only see East rows, and SSN should be masked.
        alice_data = execute_as_user(
            db_user="UserAccountantEast",
            app_user="AliceAcct",
            app_role="StaffAccountant",
            app_region="East",
            query="SELECT CustomerName, SSN, Email, Region, Balance FROM Core.Accounts;"
        )
        
        print(f"[+] Alice query executed. Retrieved {len(alice_data)} records.")
        for row in alice_data:
            print(f"    - Customer: {row['CustomerName']} | Region: {row['Region']} | SSN: {row['SSN']} | Email: {row['Email']}")
            
            # Assert RLS limits rows
            if row['Region'] != 'East':
                print(f"[!] Test 2 Failed: RLS leak! Alice saw region '{row['Region']}' record.")
                sys.exit(1)
            # Assert CLS masks SSN
            if "-" in row['SSN'] and not row['SSN'].startswith("XXX-XX-"):
                print(f"[!] Test 2 Failed: CLS leak! SSN was not masked: {row['SSN']}")
                sys.exit(1)
                
        print("[+] Test 2 Passed: Row-level isolation and column masking are active.")
    except Exception as e:
        print(f"[!] Test 2 Failed: Exception occurred: {e}")
        sys.exit(1)

    # 3. Test Cryptographic Ledger Verification
    print("\n[*] Test 3: Testing database blockchain ledger verification...")
    try:
        digest = generate_digest()
        print(f"[+] Cryptographic digest generated.")
        verification = verify_ledger(digest)
        if verification['success']:
            print(f"[+] Test 3 Passed: {verification['message']}")
        else:
            print(f"[!] Test 3 Failed: verification failed: {verification['message']}")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Test 3 Failed: Exception occurred: {e}")
        sys.exit(1)

    # 4. Test Sentinel Backdoor Detection (Rogue DBA write)
    print("\n[*] Test 4: Testing Threat Sentinel OOB-Write Detection...")
    try:
        # Cache original balance of Alice
        original_data = execute_query("SELECT Balance FROM Core.Accounts WHERE CustomerName = 'Alice Vance';")
        original_balance = original_data[0]['Balance']
        
        # Inject backdoor write bypass
        print("[*] Injecting simulated backdoor update (LastUpdatedBy = 'RogueDBA')...")
        execute_non_query(
            "UPDATE Core.Accounts SET Balance = 99999.00, LastUpdatedBy = 'RogueDBA' WHERE CustomerName = 'Alice Vance';"
        )
        
        # Run Sentinel scan to catch the threat
        print("[*] Executing Sentinel rules engine scan...")
        new_alerts = scan_for_anomalies()
        print(f"[+] Sentinel scan executed. Found {len(new_alerts)} new alerts.")
        
        # Check alerts
        threat_detected = False
        for a in new_alerts:
            print(f"    - Alert: [{a['severity']}] {a['details']}")
            if a['severity'] == 'CRITICAL' and 'RogueDBA' in a['details']:
                threat_detected = True
                
        # RESTORE original database balance state
        execute_non_query(
            "UPDATE Core.Accounts SET Balance = ?, LastUpdatedBy = 'SystemProvision' WHERE CustomerName = 'Alice Vance';",
            (original_balance,)
        )
        print("[*] Database balance restored to baseline state.")
        
        if threat_detected:
            print("[+] Test 4 Passed: Threat Sentinel successfully caught and alerted on backdoor database modification!")
        else:
            print("[!] Test 4 Failed: Threat Sentinel did not flag the RogueDBA write!")
            sys.exit(1)
            
    except Exception as e:
        print(f"[!] Test 4 Failed: Exception occurred: {e}")
        sys.exit(1)

    print("\n======================================================================")
    print("   ALL VIGILANTLEDGER INTEGRATION TESTS COMPLETED SUCCESSFULLY!")
    print("======================================================================")

if __name__ == "__main__":
    run_tests()
