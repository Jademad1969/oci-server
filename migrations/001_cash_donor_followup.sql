-- =================================================================================
-- Migration 001: Cash Donor Follow-up Table, Index, Page & RBAC Permissions
-- =================================================================================
BEGIN;

CREATE TABLE IF NOT EXISTS cash_donor_followup (
    followup_id        SERIAL PRIMARY KEY,
    donor_cd           INT NOT NULL REFERENCES cash_donors(donor_cd) ON DELETE CASCADE,
    delay_reason_cd    SMALLINT NOT NULL REFERENCES lkp_delay_reasons(reason_cd),
    call_result_cd     SMALLINT NOT NULL REFERENCES lkp_follow_results(result_cd),
    call_date          DATE NOT NULL DEFAULT CURRENT_DATE,
    call_time          TIME NOT NULL DEFAULT CURRENT_TIME,
    call_by            VARCHAR(30) NOT NULL,
    contact_method     SMALLINT NOT NULL DEFAULT 1, -- 1: Phone Call, 2: WhatsApp/SMS, 3: Email, 4: Visit
    next_followup_date DATE,
    call_result_notes  VARCHAR(500),
    extra_notes        VARCHAR(500),
    delay_months_snap  SMALLINT,
    last_don_date_snap DATE,
    created_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cash_donor_followup_donor
    ON cash_donor_followup (donor_cd, call_date DESC, call_time DESC, followup_id DESC);

-- Register dedicated Cash Donor Follow-up page in RBAC tree
INSERT INTO sys_pages (page_key, parent_key, node_type, title_en, title_ar, route_path, sort_order, is_active) VALUES
    ('cash_followup', 'cash_donations', 'page', 'Cash Donor Follow-up', 'متابعة المتبرعين النقديين', '/cash-followup', 5, TRUE)
ON CONFLICT (page_key) DO UPDATE SET
    parent_key = EXCLUDED.parent_key,
    node_type  = EXCLUDED.node_type,
    title_en   = EXCLUDED.title_en,
    title_ar   = EXCLUDED.title_ar,
    route_path = EXCLUDED.route_path,
    sort_order = EXCLUDED.sort_order,
    is_active  = EXCLUDED.is_active;

-- Grant default permissions to existing users (matching Cash Donations RBAC)
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, 'cash_followup',
       CASE
           WHEN UPPER(u.username) IN ('ADMIN', 'TAREK', 'SAJJAD', 'IMRAN') OR u.role_id = 1 THEN 'edit'
           WHEN UPPER(u.username) = 'HASAN' THEN 'view'
           ELSE 'none'
       END,
       'SYSTEM'
FROM sys_users u
ON CONFLICT (user_id, page_key) DO UPDATE SET
    access_level = EXCLUDED.access_level;

COMMIT;
