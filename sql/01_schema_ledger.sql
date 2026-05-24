-- ============================================================================
-- PROJECT: VigilantLedger
-- FILE: 01_schema_ledger.sql
-- DESCRIPTION: Database initialization, schema definition, and ledger tables
-- ============================================================================

USE master;
GO

-- Recreate database if it exists to ensure a clean deployment state
IF DB_ID('VigilantLedgerDB') IS NOT NULL
BEGIN
    ALTER DATABASE VigilantLedgerDB SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE VigilantLedgerDB;
END
GO

CREATE DATABASE VigilantLedgerDB;
GO

ALTER DATABASE VigilantLedgerDB SET ALLOW_SNAPSHOT_ISOLATION ON;
GO

USE VigilantLedgerDB;
GO

-- Create application schemas
CREATE SCHEMA Core;
GO
CREATE SCHEMA Audit;
GO

-- ============================================================================
-- 1. UPDATABLE LEDGER TABLE: Core.Accounts
-- ============================================================================
-- Represents sensitive customer account information. Uses SQL Server 2022
-- Ledger features to keep a cryptographically chained, tamper-evident history
-- of all record updates and deletes.
CREATE TABLE Core.Accounts
(
    CustomerID INT IDENTITY(1001, 1) PRIMARY KEY CLUSTERED,
    CustomerName NVARCHAR(100) NOT NULL,
    SSN VARCHAR(12) NOT NULL, -- To be dynamically masked
    Email NVARCHAR(100) NOT NULL, -- To be dynamically masked
    Region VARCHAR(20) NOT NULL, -- For Row-Level Security
    Balance DECIMAL(18, 2) NOT NULL,
    LastUpdatedBy VARCHAR(100) NOT NULL,
    LastUpdateTime DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    -- Hidden system versioning period columns
    SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL,
    SysEndTime DATETIME2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL,
    PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime)
)
WITH 
(
    SYSTEM_VERSIONING = ON (HISTORY_TABLE = Core.AccountsHistory),
    LEDGER = ON (LEDGER_VIEW = Core.Accounts_Ledger)
);
GO

-- ============================================================================
-- 1.5 METADATA CONFIGURATION TABLE: Core.UserRegions
-- ============================================================================
-- Maps database/application logins to their authorized regions.
-- Used by the threat sentinel rules engine to dynamically identify bypasses.
CREATE TABLE Core.UserRegions
(
    UserName NVARCHAR(100) PRIMARY KEY CLUSTERED,
    AllowedRegion VARCHAR(20) NOT NULL
);
GO


-- ============================================================================
-- 2. APPEND-ONLY LEDGER TABLE: Audit.AccessLogs
-- ============================================================================
-- Represents a write-once audit log that records read activities and other 
-- security actions. Append-only ledger tables prevent any updates or deletes 
-- even by system administrators.
CREATE TABLE Audit.AccessLogs
(
    LogID INT IDENTITY(1, 1) PRIMARY KEY CLUSTERED,
    AccessTime DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    UserName NVARCHAR(100) NOT NULL,
    ActionType NVARCHAR(50) NOT NULL, -- e.g., 'SELECT', 'POLICY_UPDATE', 'VERIFICATION'
    Details NVARCHAR(500) NOT NULL,
    TargetRegion VARCHAR(20) NULL
)
WITH 
(
    LEDGER = ON (APPEND_ONLY = ON, LEDGER_VIEW = Audit.AccessLogs_Ledger)
);
GO

-- ============================================================================
-- 3. STANDARD OPERATIONAL TABLE: Audit.SecurityAlerts
-- ============================================================================
-- Holds operational alerts raised by the Sentinel engine. It is kept as a 
-- standard table to demonstrate the co-existence of ledger and non-ledger
-- tables, as well as allowing updates to status columns (like IsResolved).
CREATE TABLE Audit.SecurityAlerts
(
    AlertID INT IDENTITY(1, 1) PRIMARY KEY CLUSTERED,
    AlertTime DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    Severity VARCHAR(20) NOT NULL, -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    SourceUser NVARCHAR(100) NOT NULL,
    Details NVARCHAR(1000) NOT NULL,
    IsResolved BIT NOT NULL DEFAULT 0,
    ResolvedTime DATETIME2 NULL
);
GO
