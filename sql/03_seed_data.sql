-- ============================================================================
-- PROJECT: VigilantLedger
-- FILE: 03_seed_data.sql
-- DESCRIPTION: Initial seed data, transactional updates/deletes to populate 
--              ledger history, and initial audit logs
-- ============================================================================

USE VigilantLedgerDB;
GO

-- Disable system validation temporarily if needed, but not required since
-- we are running as administrative context which has full RLS bypass.
PRINT 'Seeding UserRegions...';
INSERT INTO Core.UserRegions (UserName, AllowedRegion)
VALUES 
('AliceAcct', 'East'),
('DaveAcct', 'West');
GO

PRINT 'Seeding Accounts...';


INSERT INTO Core.Accounts (CustomerName, SSN, Email, Region, Balance, LastUpdatedBy, LastUpdateTime)
VALUES 
('Alice Vance',    '123-45-6789', 'alice.vance@company.com', 'East',    50000.00,  'SystemProvision', DATEADD(MINUTE, -60, GETUTCDATE())),
('Bob Smith',      '987-65-4321', 'bob.smith@company.com',   'West',    75000.00,  'SystemProvision', DATEADD(MINUTE, -55, GETUTCDATE())),
('Charlie Miller', '456-78-9012', 'charlie.m@company.com',   'East',    120000.00, 'SystemProvision', DATEADD(MINUTE, -50, GETUTCDATE())),
('Diana Prince',   '555-44-3333', 'diana.p@company.com',     'West',    95000.00,  'SystemProvision', DATEADD(MINUTE, -45, GETUTCDATE())),
('Ethan Hunt',     '777-88-9999', 'ethan.hunt@company.com',  'Central', 15000.00,  'SystemProvision', DATEADD(MINUTE, -40, GETUTCDATE()));
GO

-- Simulate some historical updates to generate transactions inside the updatable ledger
PRINT 'Simulating transaction history (updates)...';

-- Transaction 1: Alice buys something, her balance drops
UPDATE Core.Accounts
SET Balance = 48000.00, 
    LastUpdatedBy = 'AppPaymentProc',
    LastUpdateTime = DATEADD(MINUTE, -30, GETUTCDATE())
WHERE CustomerName = 'Alice Vance';
GO

-- Transaction 2: Charlie receives a transfer
UPDATE Core.Accounts
SET Balance = 122000.00, 
    LastUpdatedBy = 'AppPaymentProc',
    LastUpdateTime = DATEADD(MINUTE, -28, GETUTCDATE())
WHERE CustomerName = 'Charlie Miller';
GO

-- Transaction 3: Diana gets a credit upgrade
UPDATE Core.Accounts
SET Balance = 98000.00, 
    LastUpdatedBy = 'StaffManager',
    LastUpdateTime = DATEADD(MINUTE, -20, GETUTCDATE())
WHERE CustomerName = 'Diana Prince';
GO

-- Transaction 4: Ethan closes his account (DELETION)
PRINT 'Simulating account closure (deletion)...';
DELETE FROM Core.Accounts
WHERE CustomerName = 'Ethan Hunt';
GO

-- Seed audit access logs
PRINT 'Seeding audit logs...';
INSERT INTO Audit.AccessLogs (AccessTime, UserName, ActionType, Details, TargetRegion)
VALUES 
(DATEADD(MINUTE, -35, GETUTCDATE()), 'UserAuditor', 'SELECT', 'Full customer financial review', 'ALL'),
(DATEADD(MINUTE, -25, GETUTCDATE()), 'UserAccountantEast', 'SELECT', 'Monthly regional reconciliation', 'East'),
(DATEADD(MINUTE, -15, GETUTCDATE()), 'UserAccountantWest', 'SELECT', 'Regional balance verification', 'West');
GO

PRINT 'Seeding completed successfully!';
GO
