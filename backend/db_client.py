# ============================================================================
# PROJECT: VigilantLedger
# FILE: db_client.py
# DESCRIPTION: Database connection wrapper and query executor with support
#              for context setting and user impersonation simulation.
# ============================================================================

import os
import pyodbc
from dotenv import load_dotenv

# Enforce explicit pyodbc driver-level connection pooling (active by default, made explicit here)
pyodbc.pooling = True

# Load environmental configurations
load_dotenv()

DB_DRIVER = os.getenv("DB_DRIVER", "SQL Server")
DB_SERVER = os.getenv("DB_SERVER", "localhost")
DB_PORT = os.getenv("DB_PORT", "1433")
DB_NAME = os.getenv("DB_NAME", "VigilantLedgerDB")
DB_USER = os.getenv("DB_USER", "sa")
DB_PASSWORD = os.getenv("DB_PASSWORD", "YourSecure_Password123!")

CONNECTION_STRING = f"DRIVER={{{DB_DRIVER}}};SERVER={DB_SERVER},{DB_PORT};DATABASE={DB_NAME};UID={DB_USER};PWD={DB_PASSWORD};TrustServerCertificate=yes"

def get_connection():
    """
    Establishes and returns a connection to the MS SQL Server instance.
    Configured with a 5-second timeout to prevent application hanging.
    """
    try:
        return pyodbc.connect(CONNECTION_STRING, timeout=5)
    except Exception as e:
        raise ConnectionError(f"Failed to connect to SQL Server database: {str(e)}")

def execute_query(query, params=None):
    """
    Executes a SELECT query and returns the rows as a list of dictionaries.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        if cursor.description is None:
            return []
            
        columns = [column[0] for column in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return results
    except Exception as e:
        raise RuntimeError(f"Database query execution failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()

def execute_non_query(query, params=None):
    """
    Executes an INSERT, UPDATE, or DELETE query and commits the transaction.
    Returns the number of affected rows.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        conn.commit()
        return cursor.rowcount
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Database modification failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()

def execute_as_user(db_user, app_user, app_role, app_region, query, params=None):
    """
    Executes a query within a simulated user context.
    Sets the SQL Server SESSION_CONTEXT and impersonates the specified database user
    to test Row-Level Security (RLS) and Column-Level Security/Masking (CLS).
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Start transaction block to bind context and impersonation
        conn.autocommit = False
        
        # 1. Set session context for RLS
        cursor.execute("EXEC Core.sp_SetContext ?, ?, ?", (app_user, app_role, app_region))
        
        # 2. Impersonate the database user
        cursor.execute(f"EXECUTE AS USER = ?;", (db_user,))
        
        # 3. Run the target query
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
            
        if cursor.description is None:
            results = []
        else:
            columns = [column[0] for column in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
        # 4. Revert user impersonation
        cursor.execute("REVERT;")
        conn.commit()
        
        return results
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Simulated execution as '{db_user}' failed: {str(e)}")
    finally:
        conn.autocommit = True
        cursor.close()
        conn.close()
