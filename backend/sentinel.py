# ============================================================================
# PROJECT: VigilantLedger
# FILE: sentinel.py
# DESCRIPTION: Security Sentinel engine for database anomaly detection and
#              threat intelligence.
# ============================================================================

from datetime import datetime
from backend.db_client import execute_query, execute_non_query

def scan_for_anomalies():
    """
    Scans access logs and ledger tables for security anomalies.
    Inserts newly discovered threats into Audit.SecurityAlerts.
    Returns the list of newly created alerts.
    """
    new_alerts = []
    
    # -------------------------------------------------------------------------
    # RULE 1: Detect Out-Of-Band Writes (DBA Bypassing App Servers)
    # -------------------------------------------------------------------------
    # Standard application transactions must write using 'AppPaymentProc' or 'SystemProvision'.
    # If the database user is 'sa' or if the record's LastUpdatedBy matches administrative
    # bypass patterns, this indicates a raw database write.
    direct_write_query = """
        SELECT 
            CustomerID, 
            CustomerName, 
            LastUpdatedBy, 
            LastUpdateTime,
            ledger_transaction_id
        FROM Core.Accounts_Ledger L
        JOIN sys.database_ledger_transactions T ON L.ledger_transaction_id = T.transaction_id
        WHERE L.LastUpdatedBy NOT IN ('AppPaymentProc', 'SystemProvision')
          -- Avoid double alerting by checking if this transaction was already logged as an alert
          AND NOT EXISTS (
              SELECT 1 FROM Audit.SecurityAlerts A 
              WHERE A.Details LIKE '%(LedgerTxID: ' + CAST(L.ledger_transaction_id AS VARCHAR) + ')%'
          );
    """
    try:
        anomalous_writes = execute_query(direct_write_query)
        for w in anomalous_writes:
            details = (
                f"Out-of-band database update (LedgerTxID: {w['ledger_transaction_id']}) detected on Account {w['CustomerID']} ({w['CustomerName']}) "
                f"by user/process '{w['LastUpdatedBy']}' in transaction block {w['ledger_transaction_id']}. "
                f"This bypasses application gateway API restrictions."
            )
            # Insert alert
            execute_non_query(
                """
                INSERT INTO Audit.SecurityAlerts (Severity, SourceUser, Details)
                VALUES ('CRITICAL', ?, ?);
                """,
                (w['LastUpdatedBy'], details)
            )
            new_alerts.append({
                "severity": "CRITICAL",
                "user": w['LastUpdatedBy'],
                "details": details
            })
    except Exception as e:
        print(f"Error executing Rule 1 check: {e}")

    # -------------------------------------------------------------------------
    # RULE 2: Detect Off-Hours Access
    # -------------------------------------------------------------------------
    # Access times occurring between 10 PM (22:00) and 6 AM (06:00) UTC/Server time
    # are flagged as suspicious off-hours activities.
    off_hours_query = """
        SELECT 
            LogID, 
            AccessTime, 
            UserName, 
            ActionType, 
            Details 
        FROM Audit.AccessLogs
        WHERE (DATEPART(HOUR, AccessTime) >= 22 OR DATEPART(HOUR, AccessTime) < 6)
          AND NOT EXISTS (
              SELECT 1 FROM Audit.SecurityAlerts A 
              WHERE A.Details LIKE '%(AccessLogID: ' + CAST(LogID AS VARCHAR) + ')%'
          );
    """
    try:
        off_hours_accesses = execute_query(off_hours_query)
        for a in off_hours_accesses:
            details = (
                f"Suspicious off-hours database access log (AccessLogID: {a['LogID']}) at {a['AccessTime']}. "
                f"Action: {a['ActionType']} - {a['Details']}"
            )
            execute_non_query(
                """
                INSERT INTO Audit.SecurityAlerts (Severity, SourceUser, Details)
                VALUES ('MEDIUM', ?, ?);
                """,
                (a['UserName'], details)
            )
            new_alerts.append({
                "severity": "MEDIUM",
                "user": a['UserName'],
                "details": details
            })
    except Exception as e:
        print(f"Error executing Rule 2 check: {e}")

    # -------------------------------------------------------------------------
    # RULE 3: Detect Regional Access Policy Bypass (Staff Accountant Cross-Region Query)
    # -------------------------------------------------------------------------
    # Staff Accountants are strictly isolated to their region. If their log record
    # requests a target region they do not own, they are attempting context hijacking.
    regional_bypass_query = """
        SELECT 
            L.LogID, 
            L.AccessTime, 
            L.UserName, 
            L.TargetRegion, 
            L.Details,
            R.AllowedRegion
        FROM Audit.AccessLogs L
        JOIN Core.UserRegions R ON L.UserName = R.UserName
        WHERE L.TargetRegion <> R.AllowedRegion
          AND NOT EXISTS (
              SELECT 1 FROM Audit.SecurityAlerts A 
              WHERE A.Details LIKE '%(AccessLogID: ' + CAST(L.LogID AS VARCHAR) + ')%'
          );
    """
    try:
        access_logs = execute_query(regional_bypass_query)
        for log in access_logs:
            username = log['UserName']
            region = log['TargetRegion']
            allowed_region = log['AllowedRegion']
            
            details = (
                f"Regional Access Policy Bypass Log (AccessLogID: {log['LogID']}) at {log['AccessTime']}. "
                f"Accountant '{username}' requested access to region '{region}' "
                f"which violates regional access boundaries (Allowed: '{allowed_region}')."
            )
            execute_non_query(
                """
                INSERT INTO Audit.SecurityAlerts (Severity, SourceUser, Details)
                VALUES ('HIGH', ?, ?);
                """,
                (username, details)
            )
            new_alerts.append({
                "severity": "HIGH",
                "user": username,
                "details": details
            })
    except Exception as e:
        print(f"Error executing Rule 3 check: {e}")

    # -------------------------------------------------------------------------
    # RULE 4: Detect Multi-Verification Failure Probes (Brute Force Attacks)
    # -------------------------------------------------------------------------
    # If 3 or more ledger verification failures are logged in the last 15 minutes,
    # it indicates active signature manipulation/probes.
    brute_force_query = """
        SELECT COUNT(*) as cnt 
        FROM Audit.SecurityAlerts
        WHERE Severity = 'CRITICAL'
          AND Details LIKE '%forged digest%'
          AND AlertTime >= DATEADD(MINUTE, -15, GETUTCDATE());
    """
    try:
        res = execute_query(brute_force_query)
        if res and res[0]['cnt'] >= 3:
            # Check if we already alerted on brute force in last 15 minutes
            already_alerted_query = """
                SELECT COUNT(*) as cnt 
                FROM Audit.SecurityAlerts
                WHERE Severity = 'CRITICAL'
                  AND Details LIKE '%Cryptographic Brute Force Attack%'
                  AND AlertTime >= DATEADD(MINUTE, -15, GETUTCDATE());
            """
            check_alert = execute_query(already_alerted_query)
            if check_alert and check_alert[0]['cnt'] == 0:
                details = (
                    f"Cryptographic Brute Force Attack: {res[0]['cnt']} database ledger verification "
                    f"failures detected within the last 15 minutes. High probability of active filesystem signature forging."
                )
                execute_non_query(
                    """
                    INSERT INTO Audit.SecurityAlerts (Severity, SourceUser, Details)
                    VALUES ('CRITICAL', 'SYSTEM_AUDITOR', ?);
                    """,
                    (details,)
                )
                new_alerts.append({
                    "severity": "CRITICAL",
                    "user": "SYSTEM_AUDITOR",
                    "details": details
                })
    except Exception as e:
        print(f"Error executing Rule 4 check: {e}")

    return new_alerts

def get_alerts(only_active=False):
    """
    Retrieves all alerts from Audit.SecurityAlerts.
    """
    if only_active:
        query = "SELECT * FROM Audit.SecurityAlerts WHERE IsResolved = 0 ORDER BY AlertTime DESC;"
    else:
        query = "SELECT * FROM Audit.SecurityAlerts ORDER BY AlertTime DESC;"
    return execute_query(query)

def resolve_alert(alert_id):
    """
    Marks a security alert as resolved.
    """
    query = """
        UPDATE Audit.SecurityAlerts 
        SET IsResolved = 1, ResolvedTime = GETUTCDATE() 
        WHERE AlertID = ?;
    """
    return execute_non_query(query, (alert_id,))
