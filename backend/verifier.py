# ============================================================================
# PROJECT: VigilantLedger
# FILE: verifier.py
# DESCRIPTION: Cryptographic verification engine and ledger query service.
# ============================================================================

import json
from backend.db_client import get_connection, execute_query

def generate_digest():
    """
    Generates a database ledger digest representing the current state of the 
    ledger blockchain. Returns a JSON string containing the block ID and hash.
    """
    try:
        results = execute_query("EXEC sys.sp_generate_database_ledger_digest;")
        if results:
            return results[0]['latest_digest']
        raise RuntimeError("No digest returned by SQL Server.")
    except Exception as e:
        raise RuntimeError(f"Failed to generate database ledger digest: {str(e)}")

def verify_ledger(digest_json):
    """
    Validates the database integrity against a specific JSON digest.
    Returns a dict with 'success' status, a diagnostic message, and details.
    """
    conn = get_connection()
    # autocommit=True is MANDATORY for running ledger verification
    conn.autocommit = True
    cursor = conn.cursor()
    
    try:
        # sys.sp_verify_database_ledger executes verification. If it succeeds, it returns no rows.
        # If it fails, it raises an exception with error details.
        cursor.execute("EXEC sys.sp_verify_database_ledger ?;", (digest_json,))
        
        # Check for warnings or messages on connection
        message = "Database integrity verified. Cryptographic chain matches the provided digest."
        return {
            "success": True,
            "message": message,
            "digest_used": json.loads(digest_json) if isinstance(digest_json, str) else digest_json
        }
    except Exception as e:
        error_msg = str(e)
        # Parse common SQL Server ledger errors for better display
        if "tamper" in error_msg.lower() or "failed" in error_msg.lower() or "invalid" in error_msg.lower():
            diagnostic = "Ledger verification failed! Unauthorized data tampering or digest mismatch detected."
        else:
            diagnostic = f"Verification failed with system error: {error_msg}"
            
        return {
            "success": False,
            "message": diagnostic,
            "error_detail": error_msg,
            "digest_used": json.loads(digest_json) if isinstance(digest_json, str) else digest_json
        }
    finally:
        cursor.close()
        conn.close()

def get_ledger_blocks():
    """
    Retrieves all cryptographic blocks in the database ledger chain.
    """
    query = """
        SELECT 
            block_id, 
            CONVERT(VARCHAR(66), transactions_root_hash, 1) AS transactions_root_hash,
            block_size,
            ISNULL(CONVERT(VARCHAR(66), previous_block_hash, 1), 'GENESIS_BLOCK') AS previous_block_hash
        FROM sys.database_ledger_blocks
        ORDER BY block_id DESC;
    """
    return execute_query(query)

def get_ledger_transactions():
    """
    Retrieves the ledger transactions showing who committed transactions,
    into which blocks, and when.
    """
    query = """
        SELECT 
            transaction_id, 
            block_id, 
            transaction_ordinal, 
            commit_time, 
            principal_name,
            CONVERT(VARCHAR(12), table_hashes, 1) AS table_hash
        FROM sys.database_ledger_transactions
        ORDER BY commit_time DESC;
    """
    return execute_query(query)

def get_accounts_ledger_history():
    """
    Queries the ledger view to show the complete history of modifications
    to the Core.Accounts table.
    """
    query = """
        SELECT 
            CustomerID, 
            CustomerName, 
            Region, 
            Balance, 
            LastUpdatedBy, 
            LastUpdateTime,
            ledger_transaction_id, 
            ledger_sequence_number, 
            ledger_operation_type_desc
        FROM Core.Accounts_Ledger
        ORDER BY ledger_transaction_id DESC, ledger_sequence_number DESC;
    """
    return execute_query(query)
