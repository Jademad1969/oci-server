-- =================================================================================
-- Migration 002: Cash Analytical Reports, System Settings & Dynamic Risk Scoring Config
-- =================================================================================
BEGIN;

-- 1. Dynamic Cash Donor Risk Scoring Configuration (Singleton row id = 1)
CREATE TABLE IF NOT EXISTS cash_risk_config (
    config_id           SMALLINT PRIMARY KEY DEFAULT 1 CHECK (config_id = 1),
    weight_monetary     SMALLINT NOT NULL DEFAULT 35 CHECK (weight_monetary BETWEEN 0 AND 100),
    weight_frequency    SMALLINT NOT NULL DEFAULT 25 CHECK (weight_frequency BETWEEN 0 AND 100),
    weight_recency      SMALLINT NOT NULL DEFAULT 25 CHECK (weight_recency BETWEEN 0 AND 100),
    weight_followup     SMALLINT NOT NULL DEFAULT 15 CHECK (weight_followup BETWEEN 0 AND 100),
    tier_critical_min   SMALLINT NOT NULL DEFAULT 75 CHECK (tier_critical_min BETWEEN 1 AND 100),
    tier_high_min       SMALLINT NOT NULL DEFAULT 55 CHECK (tier_high_min BETWEEN 1 AND 100),
    tier_medium_min     SMALLINT NOT NULL DEFAULT 35 CHECK (tier_medium_min BETWEEN 1 AND 100),
    followup_stale_days SMALLINT NOT NULL DEFAULT 60 CHECK (followup_stale_days BETWEEN 1 AND 365),
    updated_by          VARCHAR(30) DEFAULT 'SYSTEM',
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO cash_risk_config (
    config_id, weight_monetary, weight_frequency, weight_recency, weight_followup,
    tier_critical_min, tier_high_min, tier_medium_min, followup_stale_days, updated_by
) VALUES (1, 35, 25, 25, 15, 75, 55, 35, 60, 'SYSTEM')
ON CONFLICT (config_id) DO NOTHING;

-- 2. Register Cash Analytical Reports & System Settings pages in RBAC tree
INSERT INTO sys_pages (page_key, parent_key, node_type, title_en, title_ar, route_path, sort_order, is_active) VALUES
    ('cash_reports',    'cash_donations', 'page', 'Cash Analytical Reports', 'تقارير التبرعات النقدية', '/cash-reports', 6, TRUE),
    ('system_settings', 'admin',          'page', 'System Settings',         'إعدادات النظام',          '/settings',     2, TRUE)
ON CONFLICT (page_key) DO UPDATE SET
    parent_key = EXCLUDED.parent_key,
    node_type  = EXCLUDED.node_type,
    title_en   = EXCLUDED.title_en,
    title_ar   = EXCLUDED.title_ar,
    route_path = EXCLUDED.route_path,
    sort_order = EXCLUDED.sort_order,
    is_active  = EXCLUDED.is_active;

-- 3. Grant default permissions
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, 'cash_reports',
       CASE
           WHEN UPPER(u.username) IN ('ADMIN', 'TAREK', 'SAJJAD', 'IMRAN') OR u.role_id = 1 THEN 'edit'
           WHEN UPPER(u.username) = 'HASAN' THEN 'view'
           ELSE 'none'
       END,
       'SYSTEM'
FROM sys_users u
ON CONFLICT (user_id, page_key) DO UPDATE SET
    access_level = EXCLUDED.access_level;

INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, 'system_settings',
       CASE
           WHEN UPPER(u.username) IN ('ADMIN', 'TAREK') OR u.role_id = 1 THEN 'edit'
           ELSE 'none'
       END,
       'SYSTEM'
FROM sys_users u
ON CONFLICT (user_id, page_key) DO UPDATE SET
    access_level = EXCLUDED.access_level;

COMMIT;
