-- =================================================================================
-- 8. عروض تصدير البيانات (Group A Views) وتريجر حركات التفعيل/الإيقاف وإجراء الاستحقاق الشهري
-- =================================================================================

-- 1. ACTIVE_DON_ADDRESS (قائمة المتبرعين الفعالين بعناوين المنازل للرسائل البريدية)
CREATE OR REPLACE VIEW vw_active_don_address AS
SELECT
    a.donor_no,
    COALESCE(d.prefix_name, '') AS prefix_name,
    a.donor_name,
    COALESCE(e.care_nm, '') AS carenm,
    'BLOCK: ' || COALESCE(a.donor_block::text, '') ||
    ' ,ROAD: ' || COALESCE(a.donor_road, '') ||
    ' ,BUILD: ' || COALESCE(a.donor_building, '') ||
    ' ,FLAT: ' || COALESCE(a.donor_flat::text, '') AS address,
    COALESCE(so.sumpay, 0)::numeric(10,3) AS sumpay,
    COALESCE(so.st_no, 0)::int AS st_no,
    COALESCE(a.donor_tel2, a.donor_mobile, '') AS donor_tel2,
    COALESCE(a.donor_ename, '') AS donor_ename
FROM donor_master a
LEFT JOIN lkp_name_prefixes d ON a.name_prefix = d.prefix_cd
LEFT JOIN lkp_cares e ON CASE WHEN a.care ~ '^[0-9]+$' THEN a.care::smallint ELSE NULL END = e.care_cd
JOIN (
    SELECT donor_no, SUM(monthly_pay) AS sumpay, COUNT(*) AS st_no
    FROM donor_item
    WHERE status_no = 1
    GROUP BY donor_no
) so ON a.donor_no = so.donor_no
WHERE a.address_type = 1
  AND a.donor_p_box IS NULL
ORDER BY so.sumpay DESC;

-- 2. ACTIVE_DON_PBOX (قائمة المتبرعين بصناديق البريد P.O. Box)
CREATE OR REPLACE VIEW vw_active_don_pbox AS
SELECT
    a.donor_no,
    COALESCE(d.prefix_name, '') AS prefix_name,
    a.donor_name,
    COALESCE(e.care_nm, '') AS carenm,
    'P_BOX: ' || COALESCE(a.donor_p_box::text, '') AS p_box,
    COALESCE(so.sumpay, 0)::numeric(10,3) AS sumpay,
    COALESCE(so.st_no, 0)::int AS st_no,
    COALESCE(a.donor_tel2, a.donor_mobile, '') AS donor_tel2,
    COALESCE(a.donor_ename, '') AS donor_ename,
    so.so_status_group
FROM donor_master a
LEFT JOIN lkp_name_prefixes d ON a.name_prefix = d.prefix_cd
LEFT JOIN lkp_cares e ON CASE WHEN a.care ~ '^[0-9]+$' THEN a.care::smallint ELSE NULL END = e.care_cd
JOIN (
    SELECT
        donor_no,
        status_no AS so_status_group,
        SUM(monthly_pay) AS sumpay,
        COUNT(*) AS st_no
    FROM donor_item
    GROUP BY donor_no, status_no
) so ON a.donor_no = so.donor_no
WHERE a.donor_p_box IS NOT NULL
ORDER BY so.sumpay DESC;

-- 3. SMS_SUBSCRIPTIONS (دليل أرقام الهواتف والرسائل النصية للمتبرعين)
CREATE OR REPLACE VIEW vw_sms_subscriptions AS
SELECT
    a.donor_no,
    a.donor_name,
    COALESCE(a.donor_ename, '') AS donor_ename,
    COALESCE(a.donor_mobile, '') AS donor_mobile,
    COALESCE(a.donor_tel1, '') AS donor_tel1,
    COALESCE(a.donor_tel2, '') AS donor_tel2,
    a.status_no,
    COALESCE(a.donor_contact, 1) AS donor_contact
FROM donor_master a
ORDER BY a.donor_no ASC;

-- 4. UPTO_SPECIFIC_AMT (المتبرعون حسب الحد الأدنى لقيمة الاستقطاع الشهري - يشمل UPTO5 / UPTO10 / UPTO25)
CREATE OR REPLACE VIEW vw_upto_specific_amt AS
SELECT
    a.donor_no,
    a.so_id,
    a.monthly_pay,
    COALESCE(b.donor_ename, '') AS donor_ename,
    b.donor_name,
    COALESCE(b.donor_tel2, b.donor_mobile, '') AS mobile,
    CASE WHEN b.donor_p_box IS NOT NULL THEN 'P.BOX: ' || b.donor_p_box::text ELSE '' END AS p_box,
    'FLAT:' || COALESCE(b.donor_flat::text, '') ||
    ' BLD: ' || COALESCE(b.donor_building, '') ||
    ' ROAD: ' || COALESCE(b.donor_road, '') ||
    ' BLOCK: ' || COALESCE(b.donor_block::text, '') AS address,
    COALESCE(b.donor_contact, 1) AS donor_contact
FROM donor_item a
JOIN donor_master b ON a.donor_no = b.donor_no
WHERE a.status_no = 1
  AND a.monthly_pay >= COALESCE((SELECT so_min_amt FROM sys_donor_setup LIMIT 1), 5)
ORDER BY a.monthly_pay DESC, a.donor_no ASC;

-- 5. تريجر تسجيل حركات تفعيل وإيقاف الاستقطاع تلقائياً (يحاكي COUNT_VALID_ACT_DEACT في أوراكل)
CREATE OR REPLACE FUNCTION fn_log_donor_item_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status_no IS DISTINCT FROM NEW.status_no THEN
        IF OLD.status_no = 1 AND NEW.status_no = 2 THEN
            INSERT INTO donor_item_actdeact_trns (so_id, donor_no, item_no, start_date, trans_type, trans_date)
            VALUES (OLD.so_id, OLD.donor_no, CASE WHEN OLD.item_no ~ '^[0-9]+$' THEN OLD.item_no::int ELSE 1 END, OLD.donation_start_date, 2, CURRENT_TIMESTAMP);
        ELSIF OLD.status_no = 2 AND NEW.status_no = 1 THEN
            INSERT INTO donor_item_actdeact_trns (so_id, donor_no, item_no, start_date, trans_type, trans_date)
            VALUES (OLD.so_id, OLD.donor_no, CASE WHEN OLD.item_no ~ '^[0-9]+$' THEN OLD.item_no::int ELSE 1 END, OLD.donation_start_date, 1, CURRENT_TIMESTAMP);
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_log_donor_item_status_change
AFTER UPDATE OF status_no ON donor_item
FOR EACH ROW EXECUTE FUNCTION fn_log_donor_item_status_change();

-- 6. إجراء توليد استحقاقات الشهر الجديد تلقائياً (يحاكي GENERAT_PAYMENTS في أوراكل)
CREATE OR REPLACE PROCEDURE sp_generate_monthly_payments(p_target_month DATE DEFAULT DATE_TRUNC('month', CURRENT_DATE)::date)
LANGUAGE plpgsql
AS $$
DECLARE
    v_month DATE := DATE_TRUNC('month', p_target_month)::date;
BEGIN
    INSERT INTO money_trans (
        so_id, donor_no, item_no, region_no, donation_start_date,
        month_year, paid_sum, status_no, pay_type, bank_cd, st_order_no, alt_st_no
    )
    SELECT
        s.so_id, s.donor_no, s.item_no, COALESCE(s.region_no, 0), s.donation_start_date,
        v_month, s.monthly_pay, 2, 2, s.bank2_cd, COALESCE(s.sort_field, ''), s.alt_so_code
    FROM donor_item s
    WHERE s.status_no = 1
      AND s.donation_start_date <= v_month
      AND NOT EXISTS (
          SELECT 1 FROM money_trans x
          WHERE x.so_id = s.so_id AND x.month_year = v_month
      )
    ON CONFLICT (so_id, month_year) DO NOTHING;

    UPDATE last_update_money_trans SET last_up = CURRENT_DATE;
    IF NOT FOUND THEN
        INSERT INTO last_update_money_trans (last_up) VALUES (CURRENT_DATE) ON CONFLICT DO NOTHING;
    END IF;
END;
$$;

-- 7. تسجيل صفحة مركز العروض وتصدير البيانات (Data Views & Export Center) في sys_pages
INSERT INTO sys_pages (page_key, parent_key, node_type, title_en, title_ar, route_path, sort_order, is_active) VALUES
    ('data_views_export', 'so_reports_group', 'page', 'Data Views & Export Center', 'مركز عروض وتصدير البيانات', '/reports-views', 4, TRUE)
ON CONFLICT (page_key) DO UPDATE SET
    parent_key = EXCLUDED.parent_key,
    node_type  = EXCLUDED.node_type,
    title_en   = EXCLUDED.title_en,
    title_ar   = EXCLUDED.title_ar,
    route_path = EXCLUDED.route_path,
    sort_order = EXCLUDED.sort_order,
    is_active  = EXCLUDED.is_active;

INSERT INTO sys_user_permissions (user_id, page_key, access_level, granted_by)
SELECT u.user_id, 'data_views_export',
       CASE WHEN UPPER(u.username) IN ('ADMIN', 'TAREK') OR u.role_id = 1 THEN 'edit' ELSE 'view' END,
       'SYSTEM'
FROM sys_users u
ON CONFLICT (user_id, page_key) DO NOTHING;
