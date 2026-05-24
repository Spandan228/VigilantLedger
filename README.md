---
title: VigilantLedger
emoji: 👁
colorFrom: red
colorTo: green
sdk: docker
pinned: false
---

# VigilantLedger: Cryptographically Verifiable Database Ledger & SecOps Engine

VigilantLedger is a security-focused, industrial-grade SQL and Python project that addresses a major enterprise database challenge: **preventing, detecting, and auditing privilege abuse and unauthorized data access in sensitive systems (e.g., Banking, Healthcare, Government).**

In standard database systems, administrators (DBAs) or compromise vector logins bypass application servers to modify tables directly via SQL (e.g., altering account balances or wiping audit records) without leaving application-level traces. 

**VigilantLedger solves this** by leveraging cutting-edge database ledger mechanics (available in Microsoft SQL Server 2022), system-versioned temporal tables, and dynamic context-based security policies (Row-Level Security and Column-Level Security). It is orchestrated through a modern, custom-styled Security Operations (SecOps) dashboard interface.

---

## 🏗️ Architectural Overview

```
                        +----------------------------------+
                        |      SecOps FastAPI Dashboard    |
                        +---+--------------------------+---+
                            |                          |
               Simulate User Personas            Cryptographic Audit
               & Dynamic RLS/CLS Checks          & Verification Check
                            |                          |
                            v                          v
+---------------------------+--------------------------+-----------------------+
|  DATABASE SYSTEM: VigilantLedgerDB (SQL Server 2022 Docker Container)         |
|                                                                               |
|  +----------------------------+      +-------------------------------------+  |
|  |  CORE DATA LAYER           |      |  SECURITY GATEWAY                   |  |
|  |                            |      |                                     |  |
|  |  * Core.Accounts           |      |  * Core.sp_SetContext               |  |
|  |    (Updatable Ledger)      |      |    (App context binder)             |  |
|  |  * Core.AccountsHistory    |      |  * Core.fn_securitypredicate        |  |
|  |    (Tamper-Proof History)  |      |    (RLS Row-level filtering)        |  |
|  |  * Core.Accounts_Ledger    |      |  * Dynamic Column Masking           |  |
|  |    (Cryptographic Ledger)  |      |    (CLS SSN/Email masking)          |  |
|  +----------------------------+      +-------------------------------------+  |
|                                                                               |
|  +----------------------------+      +-------------------------------------+  |
|  |  AUDIT LOGGING LAYER       |      |  THREAT SENTINEL SCANNER            |  |
|  |                            |      |                                     |  |
|  |  * Audit.AccessLogs        |      |  * backend/sentinel.py              |  |
|  |    (Append-Only Ledger)    |      |    - Detect OOB direct admin writes |  |
|  |  * Audit.SecurityAlerts    |      |    - Detect off-hours query access  |  |
|  |    (Incident Register)     |      |    - Flag cryptographic mismatches   |  |
|  +----------------------------+      +-------------------------------------+  |
+-------------------------------------------------------------------------------+
```

---

## ⚡ Key Capabilities Implemented

1. **Cryptographic Ledger Tables (`Core.Accounts` & `Audit.AccessLogs`):**
   - Tables are defined with `LEDGER = ON`. SQL Server maintains a cryptographically chained history of all changes (using SHA-256 Merkle trees).
   - `Audit.AccessLogs` is designated as `APPEND_ONLY = ON`. Even the system administrator (`sa`) cannot execute `DELETE` or `UPDATE` queries; the engine blocks them at the kernel level.
2. **Dynamic Policy Administration (RLS & CLS):**
   - **Row-Level Security (RLS)** restricts accountants to view records *only within their designated region* (e.g., East vs. West) based on the session's active application context.
   - **Column-Level Security (CLS)** dynamically masks sensitive fields (such as SSNs and Emails) with character overlays. Only users associated with high-level roles (`ComplianceAuditor`, `FinancialManager`) are granted `UNMASK` rights.
3. **Forensic Time Travel Engine:**
   - Leveraging temporal system versioning, auditors can query the database using the `FOR SYSTEM_TIME AS OF` syntax to reconstruct the exact state of all customer records at a precise timestamp.
4. **Threat Sentinel Alerting:**
   - A Python background scanner analyzes query logs and ledger transitions to detect anomalies (such as updates by the `sa` login, which bypasses application backend gateways, or off-hours reads).
5. **Interactive Tamper Simulation Sandbox:**
   - The user interface lets you save a cryptographically signed digest, perform an out-of-band edit to test tamper detection, attempt an illegal delete operation to prove ledger immutability, and run verification loops showing the exact block failure logs.

---

## 🚀 How to Run the Project

### Prerequisites
- **Python 3.8+** installed on the host.
- **Docker** running with the existing `secops-sql-en` container active.
- The `VigilantLedgerDB` database is already configured and seeded in your container.

### Step-by-Step Execution
1. Open a PowerShell terminal in the workspace directory: `d:\project sql`.
2. Launch the orchestration script:
   ```powershell
   ./run.ps1
   ```
3. The script will automatically verify the environment, install required libraries (`pyodbc`, `fastapi`, `uvicorn`, `pandas`, `plotly`, `python-dotenv`), and start the local FastAPI web server.
4. Open your browser and navigate to the local address displayed: **`http://localhost:8501`**.

---

## 📊 Live Demonstration Flow

Once the dashboard is loaded, follow this script to demonstrate all the features:

### 1. Cryptographic Blockchain Audit
- Navigate to the **Ledger Integrity & Blockchain** tab.
- Click **Execute Cryptographic Audit** to verify the current ledger database state against the reference block digest. Notice the green success alert.
- Examine the tables showing the **Ledger Blocks** (previous block hashes, root hashes) and **Ledger Transactions** (who committed which transaction, and when).

### 2. Role Simulation (RLS & CLS Policy Verification)
- Go to the **Role Simulation** tab.
- Select **Alice - Staff Accountant (East Region)**.
- Click **Execute Query as Persona**. Notice:
  - Rows are filtered to *only* show `Region = 'East'` records (RLS).
  - The `SSN` and `Email` fields are masked (e.g. `XXX-XX-6789`) (CLS).
- Switch the persona to **Carol - Compliance Auditor**. Click query. Notice that:
  - All rows across all regions are visible.
  - The SSN and email values are decrypted and shown unmasked.

### 3. Forensic Temporal Queries
- Open the **Forensic Time Travel** tab.
- Click **Load Full Audit Modification Ledger** to review the immutable record of inserts, updates, and deletes, showing the exact SQL Server transaction ID and timestamps.
- Adjust the slider to go back in time, and click **Fetch Historical Records** to inspect what records were in the database at that time.

### 4. Sandbox Hacking Simulation (Tampering)
- Go to the **Threat Sandbox** tab.
- Click **Attempt Audit Log Deletion**. The dashboard will display a red error message showing that SQL Server blocked the deletion request because it is an Append-Only Ledger table.
- Click **Inject Backdoor Database Write** to simulate a rogue DBA accessing the database via console and changing Alice's balance directly.
- Go to the **Sentinel Logs** tab and click **Execute Sentinel Thread Scan**. You will immediately see a **CRITICAL** severity alert flagged, identifying that user `sa` executed an out-of-band transaction, bypassing standard app channels!
- Go to the **Ledger Integrity** tab or **Sandbox** tab and trigger a verification using an altered digest. Watch the system raise a high-priority alert showing that the cryptographic signature chain is invalid!
