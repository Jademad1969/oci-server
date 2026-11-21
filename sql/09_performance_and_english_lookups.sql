-- =================================================================================
-- 9. تحسينات الأداء الفائق واستكمال القيم الإنجليزية في جداول الأكواد المرجعية والعروض
--    (High-Performance Payment Summary Cache, Indexes & Complete English Lookups)
-- =================================================================================

SET client_encoding = 'UTF8';

-- 1. استكمال الأعمدة والقيم الإنجليزية في كافة جداول الـ Lookup
ALTER TABLE lkp_cares ADD COLUMN IF NOT EXISTS care_enm VARCHAR(50);
ALTER TABLE lkp_contact_feedback ADD COLUMN IF NOT EXISTS feedback_e_desc VARCHAR(60);

-- تحديث القيم الإنجليزية للألقاب (lkp_name_prefixes)
UPDATE lkp_name_prefixes SET prefix_ename = CASE prefix_cd
    WHEN 1  THEN 'Mr.'
    WHEN 2  THEN 'Mrs.'
    WHEN 3  THEN 'Brother'
    WHEN 4  THEN 'Sister'
    WHEN 5  THEN 'Dr.'
    WHEN 6  THEN 'Dr. (Mrs.)'
    WHEN 7  THEN 'Brother'
    WHEN 8  THEN 'Sister'
    WHEN 9  THEN 'Mr. / Brother'
    WHEN 10 THEN 'Ms. / Sister'
    WHEN 11 THEN 'Honorable'
    WHEN 12 THEN 'H.E. Sheikh'
    WHEN 13 THEN 'H.E. Sheikha'
    WHEN 14 THEN 'H.H. Sheikh'
    WHEN 15 THEN 'H.H. Sheikha'
    WHEN 16 THEN 'H.E. Sheikh Dr.'
    WHEN 17 THEN 'H.E. Sheikh'
    WHEN 18 THEN 'Mr.'
    WHEN 19 THEN 'Brother'
    WHEN 20 THEN 'Messrs.'
    WHEN 21 THEN 'Mrs. / Ms.'
    WHEN 22 THEN 'Messrs.'
    WHEN 23 THEN 'Dr.'
    WHEN 24 THEN 'Eng.'
    ELSE COALESCE(NULLIF(TRIM(prefix_ename), ''), prefix_name)
END;

-- تحديث القيم الإنجليزية للتحية / الرعاية (lkp_cares)
UPDATE lkp_cares SET care_enm = CASE care_cd
    WHEN 1 THEN 'May Allah Preserve Him'
    WHEN 2 THEN 'May Allah Preserve Her'
    WHEN 3 THEN 'May Allah Preserve Them'
    WHEN 4 THEN 'Respected (Pl.)'
    WHEN 5 THEN 'Respected'
    WHEN 6 THEN 'Honorable (M)'
    WHEN 7 THEN 'Honorable (F)'
    ELSE COALESCE(NULLIF(TRIM(care_enm), ''), 'Respected')
END;

-- تحديث القيم الإنجليزية لأنواع الحسابات (lkp_acc_types)
UPDATE lkp_acc_types SET acc_type_e_desc = CASE acc_type_no
    WHEN 1 THEN 'Saving'
    WHEN 2 THEN 'Current'
    WHEN 3 THEN 'None / Unknown'
    ELSE COALESCE(NULLIF(TRIM(acc_type_e_desc), ''), acc_type_desc)
END;

-- تحديث القيم الإنجليزية لبنود التبرع (lkp_charity_items)
UPDATE lkp_charity_items SET item_e_desc = CASE item_cd
    WHEN '1' THEN 'Zakat'
    WHEN '2' THEN 'Sadaqah'
    WHEN '3' THEN 'Waqf'
    WHEN '4' THEN 'Projects'
    WHEN '5' THEN 'Ramadan Zakat'
    WHEN '6' THEN 'Preacher Support'
    WHEN '7' THEN 'Discover Islam'
    WHEN '8' THEN 'Printing Daawah Materials'
    WHEN '9' THEN 'New Muslim Care'
    ELSE COALESCE(NULLIF(TRIM(item_e_desc), ''), item_desc)
END
WHERE item_e_desc IS NULL OR TRIM(item_e_desc) = '' OR item_cd IN ('1','2','3','4','5','6','7','8','9');

-- تحديث القيم الإنجليزية لنتائج المتابعة وأسباب التأخير وملاحظات التواصل
UPDATE lkp_follow_results SET result_enm = COALESCE(NULLIF(TRIM(result_enm), ''), result_nm);
UPDATE lkp_delay_reasons SET reason_enm = COALESCE(NULLIF(TRIM(reason_enm), ''), reason_nm);
UPDATE lkp_contact_feedback SET feedback_e_desc = CASE feedback_cd
    WHEN 1 THEN 'Stopped Completely'
    WHEN 2 THEN 'Transferred Donation'
    WHEN 3 THEN 'Contact Numbers'
    WHEN 4 THEN 'Donation Period Ended'
    WHEN 5 THEN 'Refer to Bank'
    ELSE COALESCE(NULLIF(TRIM(feedback_e_desc), ''), feedback_desc)
END;

-- تحديث أسماء المدن والمناطق الإنجليزية الناقصة في جدول المجمعات (lkp_towns)
UPDATE lkp_towns SET etown_nm = CASE TRIM(town_nm)
    WHEN 'أمواج'            THEN 'Amwaj'
    WHEN 'ابوالعيش'         THEN 'Abu Al-Aish'
    WHEN 'ابوبهام'          THEN 'Abu Baham'
    WHEN 'ابوصيبع'          THEN 'Abu Saiba'
    WHEN 'ابوقوة'           THEN 'Abu Quwah'
    WHEN 'البديع'           THEN 'Budaiya'
    WHEN 'البرهامة'         THEN 'Al-Burhama'
    WHEN 'البسيتين'         THEN 'Busaiteen'
    WHEN 'الجسرة'           THEN 'Jasra'
    WHEN 'الجنبية'          THEN 'Janabiyah'
    WHEN 'الحجر'            THEN 'Al-Hajar'
    WHEN 'الحد'             THEN 'Al-Hidd'
    WHEN 'مدينة الحد'       THEN 'Al-Hidd'
    WHEN 'الحمريه'          THEN 'Al-Hamriyah'
    WHEN 'الحورة'           THEN 'Al-Hoora'
    WHEN 'الخارجية'         THEN 'Al-Kharijiyah'
    WHEN 'الخميس'           THEN 'Al-Khamis'
    WHEN 'الدراز'           THEN 'Diraz'
    WHEN 'الدور'            THEN 'Al-Dur'
    WHEN 'الدير'            THEN 'Al-Dair'
    WHEN 'الديه'            THEN 'Daih'
    WHEN 'الرفاع الشرقى'    THEN 'East Riffa'
    WHEN 'الرفاع الشرقي'    THEN 'East Riffa'
    WHEN 'الرفاع الغربى'    THEN 'West Riffa'
    WHEN 'الرفاع الغربي'    THEN 'West Riffa'
    WHEN 'الرفاع'           THEN 'Riffa'
    WHEN 'الرميثية'         THEN 'Al-Rumaithiyah'
    WHEN 'الزلاق'           THEN 'Zallaq'
    WHEN 'الزنج'            THEN 'Zinj'
    WHEN 'الزنج الجديد'     THEN 'New Zinj'
    WHEN 'السهلة الجنوبية'  THEN 'South Sehla'
    WHEN 'السهلة الشمالية'  THEN 'North Sehla'
    WHEN 'السهلة الفوقية'   THEN 'Upper Sehla'
    WHEN 'الشاخورة'         THEN 'Shakhoora'
    WHEN 'الصالحية'         THEN 'Salhiya'
    WHEN 'الصخير'           THEN 'Sakhir'
    WHEN 'العكر'            THEN 'Al-Eker'
    WHEN 'القدم'            THEN 'Al-Qadam'
    WHEN 'القرية'           THEN 'Al-Qaryah'
    WHEN 'القريه'           THEN 'Al-Qaryah'
    WHEN 'القلعة'           THEN 'Al-Qalaa'
    WHEN 'المالكية'         THEN 'Malkiya'
    WHEN 'المحرق'           THEN 'Muharraq'
    WHEN 'مدينة المحرق'     THEN 'Muharraq'
    WHEN 'المحمدية'         THEN 'Al-Muhammadiyah'
    WHEN 'المرخ'            THEN 'Al-Markh'
    WHEN 'المصلى'           THEN 'Al-Musalla'
    WHEN 'المعامير'         THEN 'Maameer'
    WHEN 'المقشع'           THEN 'Al-Muqsha'
    WHEN 'الممطلة'          THEN 'Al-Mumtalah'
    WHEN 'المنطقة الصناعية' THEN 'Industrial Area'
    WHEN 'المنامة'          THEN 'Manama'
    WHEN 'مدينة المنامة'    THEN 'Manama'
    WHEN 'الجفير'           THEN 'Juffair'
    WHEN 'الناصفة'          THEN 'Al-Nasfah'
    WHEN 'النبيه صالح'      THEN 'Nabih Saleh'
    WHEN 'النويدرات'        THEN 'Nuwaidrat'
    WHEN 'الهمله'           THEN 'Al-Hamala'
    WHEN 'ام البيض'         THEN 'Umm Al-Baidh'
    WHEN 'ام الصمان'        THEN 'Umm Al-Samman'
    WHEN 'ام النعسان'       THEN 'Umm Al-Nasan'
    WHEN 'باربار'           THEN 'Barbar'
    WHEN 'بلاج الجزائر'     THEN 'Al-Jazaer Beach'
    WHEN 'بلاد القديم'      THEN 'Bilad Al-Qadeem'
    WHEN 'بنى جمرة'         THEN 'Bani Jamra'
    WHEN 'بورى'             THEN 'Buri'
    WHEN 'بوري'             THEN 'Buri'
    WHEN 'توبلى'            THEN 'Tubli'
    WHEN 'توبلي'            THEN 'Tubli'
    WHEN 'جبلةحبشى'         THEN 'Jiblat Habshi'
    WHEN 'جدالحاج'          THEN 'Jid Al-Haj'
    WHEN 'جدحفص'            THEN 'Jidhafs'
    WHEN 'جدعلى'            THEN 'Jid Ali'
    WHEN 'جرداب'            THEN 'Jurdab'
    WHEN 'جزر حوار'         THEN 'Hawar Islands'
    WHEN 'جسر الملك فهد'    THEN 'King Fahd Causeway'
    WHEN 'جنوسان'           THEN 'Jannusan'
    WHEN 'جو'               THEN 'Jaww'
    WHEN 'حالة السلطة'      THEN 'Halat Al-Sulta'
    WHEN 'حالة النعيم'      THEN 'Halat Al-Naim'
    WHEN 'حلة بوصالح'       THEN 'Hillat Abdul Saleh'
    WHEN 'حوار'             THEN 'Hawar'
    WHEN 'داركليب'          THEN 'Dar Kulaib'
    WHEN 'دمستان'           THEN 'Dumistan'
    WHEN 'راس ابوجرجور'     THEN 'Ras Abu Jarjur'
    WHEN 'راس زويد'         THEN 'Ras Zuwayed'
    WHEN 'سار'              THEN 'Saar'
    WHEN 'سافره'            THEN 'Safrah'
    WHEN 'سفاله'            THEN 'Sufala'
    WHEN 'سلماباد'          THEN 'Salmabad'
    WHEN 'سماهيج'           THEN 'Samaheej'
    WHEN 'سنابس'            THEN 'Sanabis'
    WHEN 'سند'              THEN 'Sanad'
    WHEN 'شهركان'           THEN 'Shahrakan'
    WHEN 'صدد'              THEN 'Sadad'
    WHEN 'طشان'             THEN 'Tashan'
    WHEN 'عالى'             THEN 'Aali'
    WHEN 'عالي'             THEN 'Aali'
    WHEN 'عراد'             THEN 'Arad'
    WHEN 'عسكر'             THEN 'Askar'
    WHEN 'عوالى'            THEN 'Awali'
    WHEN 'قلالى'            THEN 'Qalali'
    WHEN 'قلالي'            THEN 'Qalali'
    WHEN 'كرانة'            THEN 'Karranah'
    WHEN 'كرباباد'          THEN 'Karbabad'
    WHEN 'كرزكان'           THEN 'Karzakan'
    WHEN 'مدينة حمد'        THEN 'Hamad Town'
    WHEN 'مدينة زايد'       THEN 'Zayed Town'
    WHEN 'مدينة سلمان'      THEN 'Salman Town'
    WHEN 'مدينة عيسى'       THEN 'Isa Town'
    WHEN 'مرقوبان'          THEN 'Marquban'
    WHEN 'مزرع'             THEN 'Mazraa'
    WHEN 'مقابة'            THEN 'Maqaba'
    WHEN 'مقابه'            THEN 'Maqaba'
    WHEN 'مهزة'             THEN 'Mahazza'
    WHEN 'واديان'           THEN 'Wadiyan'
    ELSE COALESCE(NULLIF(TRIM(etown_nm), ''), town_nm)
END
WHERE etown_nm IS NULL OR TRIM(etown_nm) = '';

-- معالجة أي متبرع بدون اسم إنجليزي
UPDATE donor_master
SET donor_ename = CASE WHEN TRIM(donor_name) = 'غير معروف' THEN 'Unknown Donor' ELSE donor_name END
WHERE donor_ename IS NULL OR TRIM(donor_ename) = '';

-- =================================================================================
-- 2. جدول ملخص سداد الاستقطاعات الفوري (so_payment_summary) لتسريع الاستعلامات 100x
-- =================================================================================

CREATE TABLE IF NOT EXISTS so_payment_summary (
    so_id INT PRIMARY KEY,
    last_paid_month DATE,
    paid_count INT NOT NULL DEFAULT 0,
    unpaid_count INT NOT NULL DEFAULT 0
);

-- تعبئة الجدول من جدول الحركات المالية الحالي (money_trans)
TRUNCATE TABLE so_payment_summary;
INSERT INTO so_payment_summary (so_id, last_paid_month, paid_count, unpaid_count)
SELECT
    i.so_id,
    lp.last_paid_month,
    COALESCE(lp.paid_count, 0),
    COALESCE(lp.unpaid_count, 0)
FROM donor_item i
LEFT JOIN (
    SELECT
        so_id,
        MAX(month_year) FILTER (WHERE status_no = 1) AS last_paid_month,
        COUNT(*) FILTER (WHERE status_no = 1) AS paid_count,
        COUNT(*) FILTER (WHERE status_no <> 1) AS unpaid_count
    FROM money_trans
    GROUP BY so_id
) lp ON i.so_id = lp.so_id;

-- دوال وتريجرات المزامنة التلقائية الفورية عند أي تعديل في money_trans أو donor_item
CREATE OR REPLACE FUNCTION fn_refresh_so_payment_summary_for_ids(p_so_ids INT[])
RETURNS VOID AS $$
BEGIN
    IF p_so_ids IS NULL OR array_length(p_so_ids, 1) IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO so_payment_summary (so_id, last_paid_month, paid_count, unpaid_count)
    SELECT
        u.so_id,
        MAX(m.month_year) FILTER (WHERE m.status_no = 1) AS last_paid_month,
        COUNT(m.so_id) FILTER (WHERE m.status_no = 1) AS paid_count,
        COUNT(m.so_id) FILTER (WHERE m.status_no <> 1) AS unpaid_count
    FROM (SELECT DISTINCT unnest(p_so_ids) AS so_id) u
    LEFT JOIN money_trans m ON m.so_id = u.so_id
    GROUP BY u.so_id
    ON CONFLICT (so_id) DO UPDATE SET
        last_paid_month = EXCLUDED.last_paid_month,
        paid_count      = EXCLUDED.paid_count,
        unpaid_count    = EXCLUDED.unpaid_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_trg_money_trans_sync_ins()
RETURNS TRIGGER AS $$
DECLARE
    v_ids INT[];
BEGIN
    SELECT array_agg(DISTINCT so_id) INTO v_ids FROM new_rows;
    PERFORM fn_refresh_so_payment_summary_for_ids(v_ids);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_trg_money_trans_sync_upd()
RETURNS TRIGGER AS $$
DECLARE
    v_ids INT[];
BEGIN
    SELECT array_agg(DISTINCT so_id) INTO v_ids
    FROM (
        SELECT so_id FROM new_rows
        UNION
        SELECT so_id FROM old_rows
    ) s;
    PERFORM fn_refresh_so_payment_summary_for_ids(v_ids);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_trg_money_trans_sync_del()
RETURNS TRIGGER AS $$
DECLARE
    v_ids INT[];
BEGIN
    SELECT array_agg(DISTINCT so_id) INTO v_ids FROM old_rows;
    PERFORM fn_refresh_so_payment_summary_for_ids(v_ids);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_money_trans_sync_summary_ins ON money_trans;
CREATE TRIGGER trg_money_trans_sync_summary_ins
AFTER INSERT ON money_trans
REFERENCING NEW TABLE AS new_rows
FOR EACH STATEMENT EXECUTE FUNCTION fn_trg_money_trans_sync_ins();

DROP TRIGGER IF EXISTS trg_money_trans_sync_summary_upd ON money_trans;
CREATE TRIGGER trg_money_trans_sync_summary_upd
AFTER UPDATE ON money_trans
REFERENCING NEW TABLE AS new_rows OLD TABLE AS old_rows
FOR EACH STATEMENT EXECUTE FUNCTION fn_trg_money_trans_sync_upd();

DROP TRIGGER IF EXISTS trg_money_trans_sync_summary_del ON money_trans;
CREATE TRIGGER trg_money_trans_sync_summary_del
AFTER DELETE ON money_trans
REFERENCING OLD TABLE AS old_rows
FOR EACH STATEMENT EXECUTE FUNCTION fn_trg_money_trans_sync_del();

-- =================================================================================
-- 3. تحديث العرض الموحد vw_standing_orders_summary ليستخدم so_payment_summary والقيم الإنجليزية
-- =================================================================================

DROP VIEW IF EXISTS vw_standing_orders_summary;
CREATE OR REPLACE VIEW vw_standing_orders_summary AS
SELECT 
    i.so_id,
    i.donor_no,
    d.donor_name,
    COALESCE(NULLIF(TRIM(d.donor_ename), ''), d.donor_name) AS donor_ename,
    d.donor_cpr,
    d.status_no AS donor_status_no,
    d.donor_tel1,
    d.donor_tel2,
    d.donor_mobile,
    i.item_no,
    i.item_no2,
    c.item_desc,
    COALESCE(NULLIF(TRIM(c.item_e_desc), ''), c.item_desc) AS item_e_desc,
    i.donation_start_date,
    i.donation_expected_edate,
    i.monthly_pay,
    i.bank2_cd,
    b.bank_desc,
    COALESCE(NULLIF(TRIM(b.bank_e_desc), ''), b.bank_desc) AS bank_e_desc,
    i.donor_acc_no,
    i.sort_field,
    i.alt_so_code,
    i.through_form,
    i.status_no,
    i.deactive_date,
    lp.last_paid_month,
    COALESCE(lp.paid_count, 0) AS paid_installments_count,
    COALESCE(lp.unpaid_count, 0) AS unpaid_installments_count,
    GREATEST(0, (
        EXTRACT(YEAR FROM AGE(
            DATE_TRUNC('month', CASE WHEN i.status_no = 2 AND i.deactive_date IS NOT NULL THEN i.deactive_date ELSE CURRENT_DATE END),
            DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date))
        )) * 12 +
        EXTRACT(MONTH FROM AGE(
            DATE_TRUNC('month', CASE WHEN i.status_no = 2 AND i.deactive_date IS NOT NULL THEN i.deactive_date ELSE CURRENT_DATE END),
            DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date))
        ))
    )::int) AS actual_delay_months,
    GREATEST(0, (
        EXTRACT(YEAR FROM AGE(DATE_TRUNC('month', CURRENT_DATE), DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date)))) * 12 +
        EXTRACT(MONTH FROM AGE(DATE_TRUNC('month', CURRENT_DATE), DATE_TRUNC('month', COALESCE(lp.last_paid_month, i.donation_start_date))))
    )::int) AS virtual_delay_months,
    CASE 
        WHEN lp.last_paid_month IS NULL THEN 'Never Paid'
        ELSE ''
    END AS payment_notes,
    COALESCE(dc.total_so_count, 0) AS donor_total_so_count,
    COALESCE(dc.active_so_count, 0) AS donor_active_so_count,
    lf.last_call_date,
    lf.last_call_by,
    COALESCE(lf.last_result_enm, 'No Follow-up') AS last_followup_result,
    COALESCE(lf.last_reason_enm, '-') AS last_delay_reason,
    COALESCE(lf.last_method_enm, '-') AS last_contact_method,
    COALESCE(lf.last_call_notes, '') AS last_followup_notes,
    CASE 
        WHEN lf.last_call_date IS NOT NULL THEN 
            TO_CHAR(lf.last_call_date, 'YYYY-MM-DD') || ' [' || lf.last_method_enm || ' - ' || lf.last_call_by || ']: ' || 
            COALESCE(lf.last_result_enm, '') || ' (Reason: ' || COALESCE(lf.last_reason_enm, 'N/A') || ')'
        ELSE 'No Follow-up'
    END AS last_followup_summary,
    COALESCE(lf.total_followups_count, 0) AS has_followup
FROM donor_item i
JOIN donor_master d ON i.donor_no = d.donor_no
LEFT JOIN lkp_banks b ON i.bank2_cd = b.bank_cd
LEFT JOIN lkp_charity_items c ON i.item_no = c.item_cd
LEFT JOIN so_payment_summary lp ON i.so_id = lp.so_id
LEFT JOIN (
    SELECT 
        donor_no,
        COUNT(*) AS total_so_count,
        COUNT(*) FILTER (WHERE status_no = 1) AS active_so_count
    FROM donor_item
    GROUP BY donor_no
) dc ON i.donor_no = dc.donor_no
LEFT JOIN (
    SELECT DISTINCT ON (f.donor_no)
        f.donor_no,
        f.call_date AS last_call_date,
        f.call_by AS last_call_by,
        COALESCE(NULLIF(TRIM(r.result_enm), ''), r.result_nm) AS last_result_enm,
        COALESCE(NULLIF(TRIM(dr.reason_enm), ''), dr.reason_nm) AS last_reason_enm,
        CASE f.contact_method
            WHEN 1 THEN 'Call'
            WHEN 2 THEN 'SMS'
            WHEN 3 THEN 'Email'
            ELSE 'Call'
        END AS last_method_enm,
        f.call_result_notes AS last_call_notes,
        COUNT(*) OVER (PARTITION BY f.donor_no) AS total_followups_count
    FROM donor_followup f
    LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
    LEFT JOIN lkp_delay_reasons dr ON f.delay_reason_cd = dr.reason_cd
    ORDER BY f.donor_no, f.call_date DESC, f.trans_id DESC
) lf ON i.donor_no = lf.donor_no;

-- تحديث عروض التصدير (vw_active_don_address و vw_active_don_pbox) لتشمل الألقاب والتحية بالإنجليزية
DROP VIEW IF EXISTS vw_active_don_address;
CREATE OR REPLACE VIEW vw_active_don_address AS
SELECT
    a.donor_no,
    COALESCE(NULLIF(TRIM(d.prefix_ename), ''), d.prefix_name, '')::varchar(35) AS prefix_name,
    a.donor_name,
    COALESCE(NULLIF(TRIM(e.care_enm), ''), e.care_nm, '')::varchar(50) AS carenm,
    'BLOCK: ' || COALESCE(a.donor_block::text, '') ||
    ' ,ROAD: ' || COALESCE(a.donor_road, '') ||
    ' ,BUILD: ' || COALESCE(a.donor_building, '') ||
    ' ,FLAT: ' || COALESCE(a.donor_flat::text, '') AS address,
    COALESCE(so.sumpay, 0)::numeric(10,3) AS sumpay,
    COALESCE(so.st_no, 0)::int AS st_no,
    COALESCE(a.donor_tel2, a.donor_mobile, '') AS donor_tel2,
    COALESCE(NULLIF(TRIM(a.donor_ename), ''), a.donor_name, '')::varchar(100) AS donor_ename
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

DROP VIEW IF EXISTS vw_active_don_pbox;
CREATE OR REPLACE VIEW vw_active_don_pbox AS
SELECT
    a.donor_no,
    COALESCE(NULLIF(TRIM(d.prefix_ename), ''), d.prefix_name, '')::varchar(35) AS prefix_name,
    a.donor_name,
    COALESCE(NULLIF(TRIM(e.care_enm), ''), e.care_nm, '')::varchar(50) AS carenm,
    'P_BOX: ' || COALESCE(a.donor_p_box::text, '') AS p_box,
    COALESCE(so.sumpay, 0)::numeric(10,3) AS sumpay,
    COALESCE(so.st_no, 0)::int AS st_no,
    COALESCE(a.donor_tel2, a.donor_mobile, '') AS donor_tel2,
    COALESCE(NULLIF(TRIM(a.donor_ename), ''), a.donor_name, '')::varchar(100) AS donor_ename,
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

-- =================================================================================
-- 4. الفهارس الإضافية عالية الأداء (Additional High-Performance Indexes)
-- =================================================================================

CREATE INDEX IF NOT EXISTS idx_donor_master_ename ON donor_master(donor_ename);
CREATE INDEX IF NOT EXISTS idx_donor_followup_donor_date ON donor_followup(donor_no, call_date DESC, trans_id DESC);
CREATE INDEX IF NOT EXISTS idx_donor_followup_result ON donor_followup(call_result_cd);
CREATE INDEX IF NOT EXISTS idx_donor_followup_reason ON donor_followup(delay_reason_cd);
CREATE INDEX IF NOT EXISTS idx_donor_item_followup_so_id ON donor_item_followup(so_id, call_date DESC);
CREATE INDEX IF NOT EXISTS idx_donor_item_followup_donor_no ON donor_item_followup(donor_no, call_date DESC);
DROP INDEX IF EXISTS idx_bnkstmnt_load_month_bank;
CREATE INDEX IF NOT EXISTS idx_bnkstmnt_load_month_bank ON bank_statement_load(money_trans_month, bank_cd, cash_deposit, money_trans_status, sys_found, bank_stmnt_payamt);
CREATE INDEX IF NOT EXISTS idx_bnkstmnt_load_so_id ON bank_statement_load(so_id);
CREATE INDEX IF NOT EXISTS idx_bnkstmnt_load_donor_no ON bank_statement_load(donor_no);
CREATE INDEX IF NOT EXISTS idx_money_trans_month_so_status ON money_trans(month_year, so_id, status_no, paid_sum);
CREATE INDEX IF NOT EXISTS idx_deactiv_hist_date_bank ON donor_item_deactiv_hist(deactive_date, bank_cd);
CREATE INDEX IF NOT EXISTS idx_deactiv_hist_so_id ON donor_item_deactiv_hist(so_id);
CREATE INDEX IF NOT EXISTS idx_deactiv_hist_donor_no ON donor_item_deactiv_hist(donor_no);
CREATE INDEX IF NOT EXISTS idx_actdeact_trns_so_id ON donor_item_actdeact_trns(so_id);
CREATE INDEX IF NOT EXISTS idx_actdeact_trns_donor_no ON donor_item_actdeact_trns(donor_no);

ANALYZE;
