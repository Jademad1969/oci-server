-- =================================================================================
-- Migration 006: Central Lookup Tables Management Page (/lookups) & RBAC
-- =================================================================================
BEGIN;

INSERT INTO sys_pages (page_key, parent_key, node_type, title_en, title_ar, route_path, sort_order, is_active) VALUES
    ('lookups', 'admin', 'page', 'Lookup Tables', 'الجداول الفرعية والثوابت', '/lookups', 3, TRUE)
ON CONFLICT (page_key) DO UPDATE SET
    parent_key = EXCLUDED.parent_key,
    node_type  = EXCLUDED.node_type,
    title_en   = EXCLUDED.title_en,
    title_ar   = EXCLUDED.title_ar,
    route_path = EXCLUDED.route_path,
    sort_order = EXCLUDED.sort_order,
    is_active  = EXCLUDED.is_active;

-- Grant 'edit' to ADMIN only by default; others 'none' (Admin can grant from /users)
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, 'lookups',
       CASE WHEN UPPER(u.username) = 'ADMIN' THEN 'edit' ELSE 'none' END,
       'SYSTEM'
FROM sys_users u
ON CONFLICT (user_id, page_key) DO UPDATE SET access_level = EXCLUDED.access_level;

COMMIT;
