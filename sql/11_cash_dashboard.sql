-- =================================================================================
-- 11. Cash Donations Executive Dashboard Page Registration & RBAC Permissions
-- =================================================================================
SET client_encoding = 'UTF8';

INSERT INTO sys_pages (page_key, parent_key, node_type, title_en, title_ar, route_path, sort_order, is_active) VALUES
    ('cash_dashboard', 'cash_donations', 'page', 'Cash Executive Dashboard', 'لوحة مؤشرات التبرعات النقدية', '/cash-dashboard', 4, TRUE)
ON CONFLICT (page_key) DO UPDATE SET
    parent_key = EXCLUDED.parent_key,
    node_type  = EXCLUDED.node_type,
    title_en   = EXCLUDED.title_en,
    title_ar   = EXCLUDED.title_ar,
    route_path = EXCLUDED.route_path,
    sort_order = EXCLUDED.sort_order,
    is_active  = EXCLUDED.is_active;

INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, 'cash_dashboard',
       CASE
           WHEN UPPER(u.username) IN ('ADMIN', 'TAREK', 'SAJJAD', 'IMRAN') OR u.role_id = 1 THEN 'edit'
           WHEN UPPER(u.username) = 'HASAN' THEN 'view'
           ELSE 'none'
       END,
       'SYSTEM'
FROM sys_users u
ON CONFLICT (user_id, page_key) DO UPDATE SET
    access_level = EXCLUDED.access_level;
