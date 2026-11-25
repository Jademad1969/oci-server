-- =================================================================================
-- Migration 003: Internal Messaging & Directives System, Notifications, & RBAC Reset
-- =================================================================================
BEGIN;

-- 1. Internal Messages & Directives Core Table
CREATE TABLE IF NOT EXISTS sys_messages (
    message_id          SERIAL PRIMARY KEY,
    msg_type            VARCHAR(20) NOT NULL DEFAULT 'message' CHECK (msg_type IN ('message', 'directive')),
    category            VARCHAR(30) NOT NULL DEFAULT 'general',
    priority            VARCHAR(15) NOT NULL DEFAULT 'normal' CHECK (priority IN ('normal', 'high', 'urgent')),
    subject             VARCHAR(200) NOT NULL,
    body                TEXT NOT NULL,
    sender_user_id      INTEGER NOT NULL REFERENCES sys_users(user_id) ON DELETE CASCADE,
    sender_username     VARCHAR(30) NOT NULL,
    sender_unread       BOOLEAN NOT NULL DEFAULT FALSE,
    entity_type         VARCHAR(20) CHECK (entity_type IS NULL OR entity_type IN ('so', 'cash')),
    entity_id           INTEGER,
    entity_label        VARCHAR(200),
    entity_snapshot     JSONB,
    status              VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'new', 'in_progress', 'done', 'cancelled')),
    due_date            DATE,
    completed_by        VARCHAR(30),
    completed_at        TIMESTAMP WITH TIME ZONE,
    completion_note     VARCHAR(500),
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Message Recipients (supports 1-to-1 and 1-to-many threads)
CREATE TABLE IF NOT EXISTS sys_message_recipients (
    message_id          INTEGER NOT NULL REFERENCES sys_messages(message_id) ON DELETE CASCADE,
    recipient_user_id   INTEGER NOT NULL REFERENCES sys_users(user_id) ON DELETE CASCADE,
    recipient_username  VARCHAR(30) NOT NULL,
    is_read             BOOLEAN NOT NULL DEFAULT FALSE,
    read_at             TIMESTAMP WITH TIME ZONE,
    is_archived         BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (message_id, recipient_user_id)
);

-- 3. Thread Replies & Status Change Events
CREATE TABLE IF NOT EXISTS sys_message_replies (
    reply_id            SERIAL PRIMARY KEY,
    message_id          INTEGER NOT NULL REFERENCES sys_messages(message_id) ON DELETE CASCADE,
    sender_user_id      INTEGER NOT NULL REFERENCES sys_users(user_id) ON DELETE CASCADE,
    sender_username     VARCHAR(30) NOT NULL,
    body                TEXT NOT NULL,
    is_system_event     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sys_msg_sender_upd ON sys_messages (sender_user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_sys_msg_type_status ON sys_messages (msg_type, status, due_date);
CREATE INDEX IF NOT EXISTS idx_sys_msg_recip_unread ON sys_message_recipients (recipient_user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_sys_msg_replies_msg ON sys_message_replies (message_id, created_at ASC);

-- 4. Optional Next Follow-up Date on Standing Orders Follow-up for Smart Alerts
ALTER TABLE donor_followup ADD COLUMN IF NOT EXISTS next_followup_date DATE;
CREATE INDEX IF NOT EXISTS idx_donor_followup_next_date ON donor_followup (next_followup_date) WHERE next_followup_date IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cash_followup_next_date ON cash_donor_followup (next_followup_date) WHERE next_followup_date IS NOT NULL;

-- 5. Register Internal Messages page in RBAC tree (and ensure clean UTF-8 Arabic titles)
INSERT INTO sys_pages (page_key, parent_key, node_type, title_en, title_ar, route_path, sort_order, is_active) VALUES
    ('messages',        'general',        'page', 'Internal Messages',       'المراسلات والتوجيهات الداخلية', '/messages',      2, TRUE),
    ('cash_followup',   'cash_donations', 'page', 'Cash Donor Follow-up',    'متابعة المتبرعين النقديين',     '/cash-followup', 5, TRUE),
    ('cash_reports',    'cash_donations', 'page', 'Cash Analytical Reports', 'تقارير التبرعات النقدية',       '/cash-reports',  6, TRUE),
    ('system_settings', 'admin',          'page', 'System Settings',         'إعدادات النظام',                '/settings',      2, TRUE)
ON CONFLICT (page_key) DO UPDATE SET
    parent_key = EXCLUDED.parent_key,
    node_type  = EXCLUDED.node_type,
    title_en   = EXCLUDED.title_en,
    title_ar   = EXCLUDED.title_ar,
    route_path = EXCLUDED.route_path,
    sort_order = EXCLUDED.sort_order,
    is_active  = EXCLUDED.is_active;

-- 6. Sync sequences & Create EXECUTIVE Role (Top Management - Read-Only + Dashboards + Directives)
SELECT setval(pg_get_serial_sequence('sys_roles', 'role_id'), COALESCE((SELECT MAX(role_id) FROM sys_roles), 1), TRUE);
SELECT setval(pg_get_serial_sequence('sys_users', 'user_id'), COALESCE((SELECT MAX(user_id) FROM sys_users), 1), TRUE);

INSERT INTO sys_roles (role_code, role_name_ar, role_name_en, permissions, is_active)
SELECT 'EXECUTIVE', 'الإدارة العليا', 'Executive Management',
       '{"about":"view","messages":"edit","donors":"view","audit":"view","reconcile":"view","followup":"view","so_dashboard":"view","reports":"view","reports_matrix":"view","data_views_export":"view","cash_donors":"view","voucher_receipt":"view","voucher_control":"view","cash_dashboard":"view","cash_followup":"view","cash_reports":"view","users":"none","system_settings":"none","can_edit":false}'::jsonb,
       TRUE
WHERE NOT EXISTS (SELECT 1 FROM sys_roles WHERE UPPER(role_code) = 'EXECUTIVE');

-- 7. Create DIRECTOR User (Default password: 123456)
INSERT INTO sys_users (username, password_hash, full_name_ar, full_name_en, role_id, is_active)
SELECT 'DIRECTOR',
       '07a5c7342802e4438418a469a1364783eae4031127bd5e585ca8cf3e56e1051e',
       'الإدارة العليا',
       'Executive Management',
       (SELECT role_id FROM sys_roles WHERE UPPER(role_code) = 'EXECUTIVE' LIMIT 1),
       TRUE
WHERE NOT EXISTS (SELECT 1 FROM sys_users WHERE UPPER(username) = 'DIRECTOR');

-- 8. Align User Roles cleanly (ADMIN -> ADMIN role, TAREK -> DATA_ENTRY, HASAN -> FOLLOWUP, DIRECTOR -> EXECUTIVE)
UPDATE sys_users
SET role_id = (SELECT role_id FROM sys_roles WHERE UPPER(role_code) = 'ADMIN' LIMIT 1)
WHERE UPPER(username) = 'ADMIN'
  AND EXISTS (SELECT 1 FROM sys_roles WHERE UPPER(role_code) = 'ADMIN');

UPDATE sys_users
SET role_id = (SELECT role_id FROM sys_roles WHERE UPPER(role_code) = 'DATA_ENTRY' LIMIT 1),
    full_name_en = 'Tarek (Standing Orders)',
    full_name_ar = 'طارق - الاستقطاعات البنكية'
WHERE UPPER(username) = 'TAREK'
  AND EXISTS (SELECT 1 FROM sys_roles WHERE UPPER(role_code) = 'DATA_ENTRY');

UPDATE sys_users
SET role_id = (SELECT role_id FROM sys_roles WHERE UPPER(role_code) = 'FOLLOWUP' LIMIT 1)
WHERE UPPER(username) = 'HASAN'
  AND EXISTS (SELECT 1 FROM sys_roles WHERE UPPER(role_code) = 'FOLLOWUP');

UPDATE sys_users
SET role_id = (SELECT role_id FROM sys_roles WHERE UPPER(role_code) = 'EXECUTIVE' LIMIT 1)
WHERE UPPER(username) = 'DIRECTOR'
  AND EXISTS (SELECT 1 FROM sys_roles WHERE UPPER(role_code) = 'EXECUTIVE');

-- 9. Re-apply Exact RBAC Permissions Matrix for All Core Users
-- 9a. Grant 'messages' = 'edit' to all users first
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, 'messages', 'edit', 'SYSTEM'
FROM sys_users u
ON CONFLICT (user_id, page_key) DO UPDATE SET access_level = EXCLUDED.access_level;

-- 9b. ADMIN: Full edit on every page
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, p.page_key, 'edit', 'SYSTEM'
FROM sys_users u
CROSS JOIN sys_pages p
WHERE UPPER(u.username) = 'ADMIN' AND p.node_type = 'page'
ON CONFLICT (user_id, page_key) DO UPDATE SET access_level = EXCLUDED.access_level;

-- 9c. TAREK: Standing Orders Module (edit on donors/audit/reconcile; view on followup & SO reports; no Cash/Admin)
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, p.page_key,
       CASE
           WHEN p.page_key IN ('donors', 'audit', 'reconcile', 'messages') THEN 'edit'
           WHEN p.page_key IN ('about', 'followup', 'so_dashboard', 'reports', 'reports_matrix', 'data_views_export') THEN 'view'
           ELSE 'none'
       END,
       'SYSTEM'
FROM sys_users u
CROSS JOIN sys_pages p
WHERE UPPER(u.username) = 'TAREK' AND p.node_type = 'page'
ON CONFLICT (user_id, page_key) DO UPDATE SET access_level = EXCLUDED.access_level;

-- 9d. HASAN: View on Standing Orders Module + Edit on Follow-up + View on SO Reports & Overdue
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, p.page_key,
       CASE
           WHEN p.page_key IN ('followup', 'messages') THEN 'edit'
           WHEN p.page_key IN ('about', 'donors', 'audit', 'reconcile', 'so_dashboard', 'reports', 'reports_matrix', 'data_views_export') THEN 'view'
           ELSE 'none'
       END,
       'SYSTEM'
FROM sys_users u
CROSS JOIN sys_pages p
WHERE UPPER(u.username) = 'HASAN' AND p.node_type = 'page'
ON CONFLICT (user_id, page_key) DO UPDATE SET access_level = EXCLUDED.access_level;

-- 9e. SAJJAD & IMRAN: Full Cash Donations Module (edit) + Messages (edit); no SO/Admin
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, p.page_key,
       CASE
           WHEN p.page_key IN ('cash_donors', 'voucher_receipt', 'voucher_control', 'cash_dashboard', 'cash_followup', 'cash_reports', 'messages') THEN 'edit'
           WHEN p.page_key = 'about' THEN 'view'
           ELSE 'none'
       END,
       'SYSTEM'
FROM sys_users u
CROSS JOIN sys_pages p
WHERE UPPER(u.username) IN ('SAJJAD', 'IMRAN') AND p.node_type = 'page'
ON CONFLICT (user_id, page_key) DO UPDATE SET access_level = EXCLUDED.access_level;

-- 9f. DIRECTOR (Executive Management): View-Only across all SO & Cash modules + Dashboards + Reports; Edit on Messages; no Admin
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, p.page_key,
       CASE
           WHEN p.page_key = 'messages' THEN 'edit'
           WHEN p.page_key IN ('users', 'system_settings') THEN 'none'
           ELSE 'view'
       END,
       'SYSTEM'
FROM sys_users u
CROSS JOIN sys_pages p
WHERE UPPER(u.username) = 'DIRECTOR' AND p.node_type = 'page'
ON CONFLICT (user_id, page_key) DO UPDATE SET access_level = EXCLUDED.access_level;

COMMIT;
