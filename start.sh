#!/bin/bash
# ============================================================================
# PROJECT: VigilantLedger
# FILE: start.sh
# DESCRIPTION: Startup orchestrator that initializes SQL Server 2022, blocks
#              until database recovery is complete, runs migrations, and starts
#              the FastAPI backend service.
# ============================================================================

# Configure environment variables for Linux (using ODBC Driver 18)
export DB_DRIVER="ODBC Driver 18 for SQL Server"
export DB_SERVER="localhost"
export DB_PORT="1433"
export DB_NAME="VigilantLedgerDB"
export DB_USER="sa"
export DB_PASSWORD="YourSecure_Password123!"
export ACCEPT_EULA="Y"
export MSSQL_SA_PASSWORD="YourSecure_Password123!"

# Configure SQL Server system configuration
echo "[*] Configuring MS SQL Server credentials..."
/opt/mssql/bin/mssql-conf -n setup

# 1. Start SQL Server 2022 in the background
echo "[*] Launching MS SQL Server 2022 process..."
/opt/mssql/bin/sqlservr &

# 2. Wait for SQL Server to boot up on port 1433
echo "[*] Awaiting database listener on port 1433..."
for i in {1..30}; do
    # Try to connect via python to test connectivity
    python3 -c "
import pyodbc
try:
    # Use ODBC Driver 18 with Encrypt=no (default dev config)
    pyodbc.connect('DRIVER={ODBC Driver 18 for SQL Server};SERVER=localhost;UID=sa;PWD=YourSecure_Password123!;Encrypt=no', timeout=2)
    exit(0)
except Exception:
    exit(1)
"
    if [ $? -eq 0 ]; then
        echo "[+] SQL Server listener active!"
        break
    fi
    echo "[~] Database booting... ($i/30)"
    sleep 2
done

# 3. Apply schema updates, security policies, and seed data
echo "[*] Running database reinitialization..."
python3 backend/reinit_db.py

# 4. Start FastAPI server on port 7860 (required by Hugging Face)
echo "[+] Starting SecOps Dashboard API Gateway on port 7860..."
uvicorn backend.app_api:app --host 0.0.0.0 --port 7860
