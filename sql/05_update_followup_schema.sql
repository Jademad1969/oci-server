-- إزالة قيد (المتبرع + التاريخ) للسماح بأكثر من تواصل في نفس اليوم ومنع الكتابة فوق السجلات السابقة
ALTER TABLE donor_followup DROP CONSTRAINT IF EXISTS donor_followup_donor_no_call_date_key;

-- إضافة عمود سبب التأخير (مرتبط بجدول الأسباب lkp_delay_reasons) وعمود طريقة التواصل
ALTER TABLE donor_followup 
    ADD COLUMN IF NOT EXISTS delay_reason_cd SMALLINT REFERENCES lkp_delay_reasons(reason_cd),
    ADD COLUMN IF NOT EXISTS contact_method SMALLINT NOT NULL DEFAULT 1; -- 1: اتصال هاتفي, 2: رسالة (SMS/WhatsApp), 3: بريد إلكتروني

-- تحديث السجلات التجريبية السابقة ليكون لها سبب افتراضي
UPDATE donor_followup SET delay_reason_cd = 2, contact_method = 1 WHERE delay_reason_cd IS NULL;

-- تحديث الـ View الموحد ليشمل سبب التأخير وطريقة التواصل في ملخص آخر متابعة
DROP VIEW IF EXISTS vw_standing_orders_summary;
CREATE OR REPLACE VIEW vw_standing_orders_summary AS
SELECT 
    i.so_id,
    i.donor_no,
    d.donor_name,
    d.donor_ename,
    d.donor_cpr,
    d.status_no AS donor_status_no,
    d.donor_tel1,
    d.donor_tel2,
    d.donor_mobile,
    i.item_no,
    i.item_no2,
    c.item_desc,
    i.donation_start_date,
    i.donation_expected_edate,
    i.monthly_pay,
    i.bank2_cd,
    b.bank_desc,
    b.bank_e_desc,
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
        WHEN lp.last_paid_month IS NULL THEN 'لم يتم سداد أي شهر'
        ELSE ''
    END AS payment_notes,
    COALESCE(dc.total_so_count, 0) AS donor_total_so_count,
    COALESCE(dc.active_so_count, 0) AS donor_active_so_count,
    lf.last_call_date,
    lf.last_call_by,
    COALESCE(lf.last_result_nm, 'بدون متابعة') AS last_followup_result,
    COALESCE(lf.last_reason_nm, '-') AS last_delay_reason,
    COALESCE(lf.last_method_nm, '-') AS last_contact_method,
    COALESCE(lf.last_call_notes, '') AS last_followup_notes,
    CASE 
        WHEN lf.last_call_date IS NOT NULL THEN 
            TO_CHAR(lf.last_call_date, 'YYYY-MM-DD') || ' [' || lf.last_method_nm || ' - ' || lf.last_call_by || ']: ' || 
            COALESCE(lf.last_result_nm, '') || ' (السبب: ' || COALESCE(lf.last_reason_nm, 'غير محدد') || ')'
        ELSE 'بدون متابعة'
    END AS last_followup_summary,
    COALESCE(lf.total_followups_count, 0) AS has_followup
FROM donor_item i
JOIN donor_master d ON i.donor_no = d.donor_no
LEFT JOIN lkp_banks b ON i.bank2_cd = b.bank_cd
LEFT JOIN lkp_charity_items c ON i.item_no = c.item_cd
LEFT JOIN (
    SELECT 
        so_id,
        MAX(month_year) FILTER (WHERE status_no = 1) AS last_paid_month,
        COUNT(*) FILTER (WHERE status_no = 1) AS paid_count,
        COUNT(*) FILTER (WHERE status_no = 2) AS unpaid_count
    FROM money_trans
    GROUP BY so_id
) lp ON i.so_id = lp.so_id
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
        r.result_nm AS last_result_nm,
        dr.reason_nm AS last_reason_nm,
        CASE f.contact_method
            WHEN 1 THEN 'اتصال'
            WHEN 2 THEN 'رسالة'
            WHEN 3 THEN 'إيميل'
            ELSE 'اتصال'
        END AS last_method_nm,
        f.call_result_notes AS last_call_notes,
        COUNT(*) OVER (PARTITION BY f.donor_no) AS total_followups_count
    FROM donor_followup f
    LEFT JOIN lkp_follow_results r ON f.call_result_cd = r.result_cd
    LEFT JOIN lkp_delay_reasons dr ON f.delay_reason_cd = dr.reason_cd
    ORDER BY f.donor_no, f.call_date DESC, f.trans_id DESC
) lf ON i.donor_no = lf.donor_no;
