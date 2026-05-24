# ============================================================================
# PROJECT: VigilantLedger
# FILE: reinit_db.py
# DESCRIPTION: Automates dropping, recreating, and seeding the database.
# ============================================================================

import os
import sys
import pyodbc

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from backend.db_client import get_connection, CONNECTION_STRING

def run_sql_script(cursor, file_path):
    print(f"[*] Executing SQL Script: {file_path}")
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' does not exist.")
        sys.exit(1)
        
    with open(file_path, "r", encoding="utf-8") as f:
        sql_content = f.read()

    # Split script by GO statement (case-insensitive, on independent line)
    # Using regex split to handle GO with potential carriage returns
    import re
    statements = re.split(r'(?i)^\s*GO\s*$', sql_content, flags=re.MULTILINE)
    
    for stmt in statements:
        cleaned_stmt = stmt.strip()
        if not cleaned_stmt:
            continue
        try:
            cursor.execute(cleaned_stmt)
        except Exception as e:
            print(f"[!] Error executing statement:\n{cleaned_stmt[:200]}...\nError: {e}")
            raise e

def reinit_database():
    print("======================================================================")
    # Connect to master first to drop/create database
    master_connection_string = CONNECTION_STRING.replace("DATABASE=VigilantLedgerDB", "DATABASE=master")
    
    print("[*] Connecting to SQL Server master database...")
    try:
        conn = pyodbc.connect(master_connection_string, timeout=5)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        print("[!] Please check if the Docker container is active on port 1433.")
        sys.exit(1)

    try:
        # Recreate DB (01_schema_ledger.sql will handle USE master, DROP and CREATE)
        sql_dir = os.path.join(PROJECT_ROOT, "sql")
        
        # 1. Schema setup
        run_sql_script(cursor, os.path.join(sql_dir, "01_schema_ledger.sql"))
        
        # Now switch connection context to VigilantLedgerDB for role & seeding
        cursor.close()
        conn.close()
        
        print("[+] Reconnecting to VigilantLedgerDB context...")
        conn = get_connection()
        conn.autocommit = True
        cursor = conn.cursor()
        
        # 2. Security policies
        run_sql_script(cursor, os.path.join(sql_dir, "02_security_policies.sql"))
        
        # 3. Seed data
        run_sql_script(cursor, os.path.join(sql_dir, "03_seed_data.sql"))
        
        print("\n[+] VigilantLedger database reinitialized and seeded successfully!")
        
    except Exception as e:
        print(f"\n[!] Database recreation failed: {e}")
        sys.exit(1)
    finally:
        cursor.close()
        conn.close()
    print("======================================================================")

if __name__ == "__main__":
    reinit_database()
