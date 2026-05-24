-- ============================================================================
-- PROJECT: VigilantLedger
-- FILE: 02_security_policies.sql
-- DESCRIPTION: Roles, dynamic data masking (CLS), row-level security (RLS),
--              and impersonation testing setup
-- ============================================================================

USE VigilantLedgerDB;
GO

-- Drop security policy first to remove binding references on predicate functions
DROP SECURITY POLICY IF EXISTS Core.AccountsSecurityPolicy;
GO

-- ============================================================================
-- 1. DEFINE ROLES AND PERMISSIONS
-- ============================================================================
-- Create Database Roles matching business functions (guarded to ensure idempotency)
IF DATABASE_PRINCIPAL_ID('ComplianceAuditor') IS NULL CREATE ROLE ComplianceAuditor;
IF DATABASE_PRINCIPAL_ID('FinancialManager') IS NULL CREATE ROLE FinancialManager;
IF DATABASE_PRINCIPAL_ID('StaffAccountant') IS NULL CREATE ROLE StaffAccountant;
GO

-- Grant standard DML rights to these roles
GRANT SELECT, INSERT, UPDATE, DELETE ON Core.Accounts TO ComplianceAuditor;
GRANT SELECT, INSERT, UPDATE ON Core.Accounts TO FinancialManager;
GRANT SELECT, UPDATE ON Core.Accounts TO StaffAccountant; -- Accountants cannot delete accounts

-- Grant access to log and alert tables
GRANT SELECT, INSERT ON Audit.AccessLogs TO ComplianceAuditor, FinancialManager, StaffAccountant;
GRANT SELECT, UPDATE ON Audit.SecurityAlerts TO ComplianceAuditor, FinancialManager;
GO

-- ============================================================================
-- 2. COLUMN-LEVEL SECURITY: DYNAMIC DATA MASKING (DDM)
-- ============================================================================
-- Configure data masking on highly sensitive columns in the accounts table.
-- This ensures masked data is returned to unauthorized users by default.
ALTER TABLE Core.Accounts 
ALTER COLUMN SSN ADD MASKED WITH (FUNCTION = 'partial(0, "XXX-XX-", 4)');
GO

ALTER TABLE Core.Accounts 
ALTER COLUMN Email ADD MASKED WITH (FUNCTION = 'email()');
GO

-- Grant UNMASK permission only to Auditor and Manager roles.
-- StaffAccountants will see masked values for SSN and Email.
GRANT UNMASK TO ComplianceAuditor;
GRANT UNMASK TO FinancialManager;
GO

-- ============================================================================
-- 3. ROW-LEVEL SECURITY (RLS)
-- ============================================================================
-- RLS filters database rows based on the execution context.
-- We use SESSION_CONTEXT to determine the user's role and region.

-- Drop the predicate function if it exists to allow clean redeployment (bound RLS policy dropped above)
IF OBJECT_ID('Core.fn_securitypredicate') IS NOT NULL DROP FUNCTION Core.fn_securitypredicate;
GO

-- Create the inline table-valued security predicate function
CREATE FUNCTION Core.fn_securitypredicate(@Region AS VARCHAR(20))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_securitypredicate_result
WHERE 
    -- 1. Full database administrators (sysadmin/sa) bypass context check when not simulating
    SESSION_CONTEXT(N'AppRole') IS NULL
    
    -- 2. Compliance Auditors and Financial Managers can see all regions
    OR CAST(SESSION_CONTEXT(N'AppRole') AS NVARCHAR(100)) IN ('ComplianceAuditor', 'FinancialManager')
    
    -- 3. Staff Accountants can only see rows matching their assigned context region
    OR (
        CAST(SESSION_CONTEXT(N'AppRole') AS NVARCHAR(100)) = 'StaffAccountant'
        AND @Region = CAST(SESSION_CONTEXT(N'AppRegion') AS VARCHAR(20))
    );
GO

-- Bind the security predicate to the accounts table
CREATE SECURITY POLICY Core.AccountsSecurityPolicy
ADD FILTER PREDICATE Core.fn_securitypredicate(Region) ON Core.Accounts,
ADD BLOCK PREDICATE Core.fn_securitypredicate(Region) ON Core.Accounts AFTER INSERT, -- Prevent unauthorized regional inserts (stealth inserts)
ADD BLOCK PREDICATE Core.fn_securitypredicate(Region) ON Core.Accounts AFTER UPDATE -- Block accountants from moving records out of their region
WITH (STATE = ON);
GO

-- ============================================================================
-- 4. SIMULATION USERS AND CONTEXT HELPER
-- ============================================================================
-- Users created without logins to allow simulation via 'EXECUTE AS USER' (idempotency guarded)
IF DATABASE_PRINCIPAL_ID('UserAuditor') IS NULL CREATE USER UserAuditor WITHOUT LOGIN;
IF DATABASE_PRINCIPAL_ID('UserManager') IS NULL CREATE USER UserManager WITHOUT LOGIN;
IF DATABASE_PRINCIPAL_ID('UserAccountantEast') IS NULL CREATE USER UserAccountantEast WITHOUT LOGIN;
IF DATABASE_PRINCIPAL_ID('UserAccountantWest') IS NULL CREATE USER UserAccountantWest WITHOUT LOGIN;
GO

-- Assign users to roles securely checking existing memberships
IF NOT EXISTS (
    SELECT 1 FROM sys.database_role_members rm 
    JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id 
    JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id 
    WHERE r.name = 'ComplianceAuditor' AND m.name = 'UserAuditor'
)
BEGIN
    ALTER ROLE ComplianceAuditor ADD MEMBER UserAuditor;
END

IF NOT EXISTS (
    SELECT 1 FROM sys.database_role_members rm 
    JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id 
    JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id 
    WHERE r.name = 'FinancialManager' AND m.name = 'UserManager'
)
BEGIN
    ALTER ROLE FinancialManager ADD MEMBER UserManager;
END

IF NOT EXISTS (
    SELECT 1 FROM sys.database_role_members rm 
    JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id 
    JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id 
    WHERE r.name = 'StaffAccountant' AND m.name = 'UserAccountantEast'
)
BEGIN
    ALTER ROLE StaffAccountant ADD MEMBER UserAccountantEast;
END

IF NOT EXISTS (
    SELECT 1 FROM sys.database_role_members rm 
    JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id 
    JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id 
    WHERE r.name = 'StaffAccountant' AND m.name = 'UserAccountantWest'
)
BEGIN
    ALTER ROLE StaffAccountant ADD MEMBER UserAccountantWest;
END
GO

-- Stored procedure to simplify setting context variables from Python
CREATE OR ALTER PROCEDURE Core.sp_SetContext
    @AppUser NVARCHAR(100),
    @AppRole NVARCHAR(100),
    @AppRegion VARCHAR(20)
AS
BEGIN
    EXEC sp_set_session_context @key = N'AppUser', @value = @AppUser;
    EXEC sp_set_session_context @key = N'AppRole', @value = @AppRole;
    EXEC sp_set_session_context @key = N'AppRegion', @value = @AppRegion;
END;
GO
