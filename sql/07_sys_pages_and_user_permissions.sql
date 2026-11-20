-- =================================================================================
-- 7. جدول صفحات النظام الهرمي وصلاحيات المستخدمين الفردية
--    (Hierarchical System Pages Tree & Per-User Page Permissions)
-- =================================================================================

CREATE TABLE IF NOT EXISTS sys_pages (
    page_key VARCHAR(40) PRIMARY KEY,
    parent_key VARCHAR(40) REFERENCES sys_pages(page_key) ON DELETE CASCADE,
    node_type VARCHAR(15) NOT NULL CHECK (node_type IN ('module', 'group', 'page')),
    title_en VARCHAR(80) NOT NULL,
    title_ar VARCHAR(80),
    route_path VARCHAR(100),
    sort_order SMALLINT NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS sys_user_permissions (
    user_id INT NOT NULL REFERENCES sys_users(user_id) ON DELETE CASCADE,
    page_key VARCHAR(40) NOT NULL REFERENCES sys_pages(page_key) ON DELETE CASCADE,
    access_level VARCHAR(10) NOT NULL CHECK (access_level IN ('none', 'view', 'edit')),
    granted_by VARCHAR(30) DEFAULT 'SYSTEM',
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, page_key)
);

-- إدراج شجرة الوحدات والمجموعات والصفحات (Modules -> Groups -> Pages)
INSERT INTO sys_pages (page_key, parent_key, node_type, title_en, title_ar, route_path, sort_order, is_active) VALUES
    -- 1. الوحدات الرئيسية (Top-Level Modules)
    ('general',          NULL,              'module', 'General System',               'النظام العام',                     NULL,                 1, TRUE),
    ('standing_orders',  NULL,              'module', 'Bank Standing Orders Module',  'وحدة الاستقطاعات البنكية',         NULL,                 2, TRUE),
    ('admin',            NULL,              'module', 'Administration',               'إدارة النظام',                     NULL,                 3, TRUE),

    -- 2. صفحات النظام العام
    ('about',            'general',         'page',   'About System',                 'حول النظام',                       '/about',             1, TRUE),

    -- 3. صفحات ومجموعات وحدة الاستقطاعات البنكية
    ('donors',           'standing_orders', 'page',   'Donors & Standing Orders',     'المتبرعين والاستقطاعات',           '/',                  1, TRUE),
    ('audit',            'standing_orders', 'page',   'Bank Codes Audit',             'تدقيق أكواد البنوك',               '/bank-codes-audit',  2, TRUE),
    ('reconcile',        'standing_orders', 'page',   'Bank Reconciliation',          'مطابقة كشوف البنوك',               '/bank-reconcile',    3, TRUE),
    ('followup',         'standing_orders', 'page',   'Donor Follow-up',              'متابعة المتبرعين',                 '/followup',          4, TRUE),
    ('so_reports_group', 'standing_orders', 'group',  'Standing Orders Reports',      'تقارير الاستقطاعات',               NULL,                 5, TRUE),

    -- 4. صفحات التقارير الفرعية تحت عقدة تقارير الاستقطاعات (so_reports_group)
    ('so_dashboard',     'so_reports_group','page',   'SO Executive Dashboard',       'لوحة المؤشرات التنفيذية للاستقطاعات', '/reports-dashboard', 1, TRUE),
    ('reports',          'so_reports_group','page',   'SO Analytical Reports',        'التقارير التحليلية للاستقطاعات',   '/reports',           2, TRUE),
    ('reports_matrix',   'so_reports_group','page',   'Year & Matrix Reports',        'تقارير المصفوفات السنوية',         '/reports-matrix',    3, TRUE),

    -- 5. صفحات إدارة النظام
    ('users',            'admin',           'page',   'Users & Permissions',          'المستخدمين والصلاحيات',            '/users',             1, TRUE)
ON CONFLICT (page_key) DO UPDATE SET
    parent_key = EXCLUDED.parent_key,
    node_type  = EXCLUDED.node_type,
    title_en   = EXCLUDED.title_en,
    title_ar   = EXCLUDED.title_ar,
    route_path = EXCLUDED.route_path,
    sort_order = EXCLUDED.sort_order,
    is_active  = EXCLUDED.is_active;

-- منح الصلاحيات الافتراضية للمستخدمين الحاليين (ADMIN, TAREK -> edit, HASAN -> view)
INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, p.page_key,
       CASE
           WHEN UPPER(u.username) IN ('ADMIN', 'TAREK') OR u.role_id = 1 THEN 'edit'
           WHEN p.page_key = 'users' THEN 'none'
           ELSE 'view'
       END AS access_level,
       'SYSTEM'
FROM sys_users u
CROSS JOIN sys_pages p
WHERE p.node_type = 'page'
ON CONFLICT (user_id, page_key) DO NOTHING;
