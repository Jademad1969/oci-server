-- =================================================================================
-- Migration 005: Delayed Standing Orders Queue Page (/so-delayed) & RBAC
-- =================================================================================
BEGIN;

-- 1. Optional next_followup_date on donor_item_followup for per-SO follow-up scheduling
ALTER TABLE donor_item_followup ADD COLUMN IF NOT EXISTS next_followup_date DATE;

-- 2. Register Delayed Standing Orders Queue page in sys_pages
INSERT INTO sys_pages (page_key, parent_key, node_type, title_en, title_ar, route_path, sort_order, is_active) VALUES
    ('so_delayed', 'standing_orders', 'page', 'Delayed SOs Queue', 'قائمة الاستقطاعات المتأخرة', '/so-delayed', 5, TRUE)
ON CONFLICT (page_key) DO UPDATE SET
    parent_key = EXCLUDED.parent_key,
    node_type  = EXCLUDED.node_type,
    title_en   = EXCLUDED.title_en,
    title_ar   = EXCLUDED.title_ar,
    route_path = EXCLUDED.route_path,
    sort_order = EXCLUDED.sort_order,
    is_active  = EXCLUDED.is_active;

-- 3. Grant RBAC permissions matching approved matrix:
--    ADMIN & HASAN -> edit; TAREK & DIRECTOR -> view; SAJJAD & IMRAN & others -> none
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, 'so_delayed',
       CASE
           WHEN UPPER(u.username) IN ('ADMIN', 'HASAN') THEN 'edit'
           WHEN UPPER(u.username) IN ('TAREK', 'DIRECTOR') THEN 'view'
           ELSE 'none'
       END,
       'SYSTEM'
FROM sys_users u
ON CONFLICT (user_id, page_key) DO UPDATE SET access_level = EXCLUDED.access_level;

COMMIT;
