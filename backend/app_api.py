# ============================================================================
# PROJECT: VigilantLedger
# FILE: app_api.py
# DESCRIPTION: FastAPI REST server for database auditing and static serving.
# ============================================================================

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os
import json
from datetime import datetime, timedelta, timezone

import threading
import time

from backend.db_client import execute_query, execute_non_query, execute_as_user
from backend.verifier import generate_digest, verify_ledger, get_ledger_blocks, get_ledger_transactions, get_accounts_ledger_history
from backend.sentinel import scan_for_anomalies, get_alerts, resolve_alert

app = FastAPI(title="VigilantLedger REST API")

def start_sentinel_scheduler():
    def run_scheduler():
        print("[*] Background Sentinel rules engine started.")
        while True:
            try:
                scan_for_anomalies()
            except Exception as e:
                print(f"[!] Background Sentinel scanner error: {e}")
            time.sleep(10) # scan every 10 seconds

    thread = threading.Thread(target=run_scheduler, daemon=True)
    thread.start()

@app.on_event("startup")
def startup_event():
    start_sentinel_scheduler()

# Mount the frontend directory to serve styles and scripts
# We check if directory exists to prevent startup failures
if not os.path.exists("frontend"):
    os.makedirs("frontend")

app.mount("/static", StaticFiles(directory="frontend"), name="static")

# In-memory storage for the active healthy digest snapshot
session_digest = {"value": None}

# Request Schemas
class VerifyRequest(BaseModel):
    digest: str = None
    corrupt: bool = False

class QueryRequest(BaseModel):
    db_user: str
    app_user: str
    app_role: str
    app_region: str

class BackdoorRequest(BaseModel):
    amount: float

class TemporalRequest(BaseModel):
    minutes_ago: int

# ============================================================================
# 1. CORE FRONTEND ROUTE
# ============================================================================
@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    """
    Serves the main dashboard user interface from frontend/index.html.
    """
    index_path = os.path.join("frontend", "index.html")
    if not os.path.exists(index_path):
        return HTMLResponse(
            content="<h3>Error: frontend/index.html not found. Awaiting file creation...</h3>",
            status_code=404
        )
    with open(index_path, "r", encoding="utf-8") as f:
        return f.read()

# ============================================================================
# 2. STATUS & VERIFICATION ENDPOINTS
# ============================================================================
@app.get("/api/status")
def get_status():
    """
    Returns general stats and security state metrics.
    """
    try:
        # Check active status of digest
        if session_digest["value"] is None:
            session_digest["value"] = generate_digest()
            
        digest_data = json.loads(session_digest["value"])
        
        # Check integrity
        verify_res = verify_ledger(session_digest["value"])
        is_secure = verify_res["success"]
        
        blocks = get_ledger_blocks()
        transactions = get_ledger_transactions()
        alerts = get_alerts()
        active_alerts_count = sum(1 for a in alerts if not a['IsResolved'])
        
        return {
            "is_secure": is_secure,
            "block_height": len(blocks),
            "transaction_count": len(transactions),
            "active_alerts": active_alerts_count,
            "total_alerts": len(alerts),
            "database_name": "VigilantLedgerDB",
            "active_digest": digest_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database status read failed: {str(e)}")

@app.post("/api/ledger/verify")
def run_ledger_verify(req: VerifyRequest):
    """
    Performs ledger cryptographic verification. Supports simulating corruption.
    """
    try:
        if req.digest:
            target_digest = req.digest
        else:
            if session_digest["value"] is None:
                session_digest["value"] = generate_digest()
            target_digest = session_digest["value"]
            
        if req.corrupt:
            digest_dict = json.loads(target_digest)
            original_hash = digest_dict["hash"]
            # Corrupt signature string
            corrupted_hash = original_hash[:8] + "F00DFACE" + original_hash[16:]
            digest_dict["hash"] = corrupted_hash
            target_digest = json.dumps(digest_dict)
            
            # Log alert immediately for corrupt verification attempt
            execute_non_query(
                """
                INSERT INTO Audit.SecurityAlerts (Severity, SourceUser, Details)
                VALUES ('CRITICAL', 'SYSTEM_AUDITOR', ?);
                """,
                (f"Database ledger verification mismatch on block {digest_dict['block_id']} using forged digest.",)
            )

        res = verify_ledger(target_digest)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cryptographic verification failed: {str(e)}")

@app.get("/api/ledger/digest")
def get_digest():
    """
    Generates and returns a fresh healthy digest, saving it in session cache.
    """
    try:
        session_digest["value"] = generate_digest()
        return json.loads(session_digest["value"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ledger/blocks")
def get_blocks():
    """
    Returns ledger blocks database metadata.
    """
    try:
        return get_ledger_blocks()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ledger/transactions")
def get_transactions():
    """
    Returns transactions database metadata.
    """
    try:
        return get_ledger_transactions()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ledger/history")
def get_history():
    """
    Returns ledger modification history from Accounts_Ledger.
    """
    try:
        return get_accounts_ledger_history()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# 3. IDENTITY GATEWAY SIMULATION (RLS/CLS)
# ============================================================================
@app.post("/api/persona/query")
def execute_persona_query(req: QueryRequest):
    """
    Runs a query under a simulated identity and logs the access entry.
    """
    # 1. Log query access to append-only log
    try:
        log_details = f"Impersonated query on Core.Accounts. AppUser={req.app_user} / AppRole={req.app_role}"
        execute_non_query(
            """
            INSERT INTO Audit.AccessLogs (UserName, ActionType, Details, TargetRegion)
            VALUES (?, 'SELECT', ?, ?);
            """,
            (req.app_user, log_details, req.app_region)
        )
    except Exception as e:
        print(f"Logging warning: {e}")
        
    # 2. Query Database under impersonation
    try:
        if req.db_user == 'sa':
            query_str = "SELECT CustomerID, CustomerName, SSN, Email, Region, Balance, LastUpdatedBy, LastUpdateTime FROM Core.Accounts;"
            results = execute_query(query_str)
        else:
            query_str = "SELECT CustomerID, CustomerName, SSN, Email, Region, Balance, LastUpdatedBy, LastUpdateTime FROM Core.Accounts;"
            results = execute_as_user(
                db_user=req.db_user,
                app_user=req.app_user,
                app_role=req.app_role,
                app_region=req.app_region,
                query=query_str
            )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")

# ============================================================================
# 4. CHRONO-TEMPORAL TRAVEL
# ============================================================================
@app.post("/api/ledger/temporal")
def run_temporal_query(req: TemporalRequest):
    """
    Queries historical accounts state using FOR SYSTEM_TIME AS OF.
    """
    try:
        target_time = datetime.now(timezone.utc) - timedelta(minutes=req.minutes_ago)
        target_time_str = target_time.strftime('%Y-%m-%d %H:%M:%S')
        
        temporal_query = """
            SELECT CustomerID, CustomerName, Region, Balance, LastUpdatedBy, LastUpdateTime
            FROM Core.Accounts
            FOR SYSTEM_TIME AS OF ?;
        """
        results = execute_query(temporal_query, (target_time_str,))
        return {
            "query_time_utc": target_time_str,
            "minutes_ago": req.minutes_ago,
            "records": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Temporal query execution failed: {str(e)}")

# ============================================================================
# 5. CYBER SANDBOX THREAT VECTORS
# ============================================================================
@app.post("/api/sandbox/backdoor")
def inject_backdoor_write(req: BackdoorRequest):
    """
    Simulates a raw DBA bypassing app gateways to modify data out-of-band.
    """
    try:
        hack_query = """
            UPDATE Core.Accounts 
            SET Balance = ?, LastUpdatedBy = 'RogueDBA', LastUpdateTime = GETUTCDATE()
            WHERE CustomerName = 'Alice Vance';
        """
        affected = execute_non_query(hack_query, (req.amount,))
        return {
            "success": True,
            "affected_rows": affected,
            "message": f"Backdoor write executed! Alice Vance's balance modified to ${req.amount:.2f} by 'sa'."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backdoor injection failed: {str(e)}")

@app.post("/api/sandbox/delete-logs")
def attempt_log_cleansing():
    """
    Attempts to delete audit log rows. Expected to be blocked by the engine.
    """
    try:
        execute_non_query("DELETE FROM Audit.AccessLogs;")
        return {
            "success": True,
            "message": "Access logs deleted successfully (tampering succeeded!)."
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "Deletion blocked! SQL Server append-only ledger tables strictly deny updates and deletes."
        }

# ============================================================================
# 6. SENTINEL THREAT ALERT REGISTRY
# ============================================================================
@app.get("/api/sentinel/alerts")
def get_sentinel_alerts():
    """
    Returns alerts list.
    """
    try:
        return get_alerts()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sentinel/scan")
def run_sentinel_scan():
    """
    Scans the database for anomalies and records newly flagged alerts.
    """
    try:
        new_alerts = scan_for_anomalies()
        return {
            "success": True,
            "new_threats_found": len(new_alerts),
            "alerts": new_alerts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sentinel/resolve")
def resolve_alerts():
    """
    Resolves and archives all active threat notifications.
    """
    try:
        active_alerts = [a for a in get_alerts() if not a['IsResolved']]
        for a in active_alerts:
            resolve_alert(a['AlertID'])
        return {
            "success": True,
            "resolved_count": len(active_alerts)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
