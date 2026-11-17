DELETE FROM donor_item_followup;

-- 1. متابعات خاصة بالاستقطاع رقم 101 فقط (للمتبرع رقم 1 - موسى عبداللطيف)
INSERT INTO donor_item_followup (
    so_id, donor_no, item_no, donation_start_date, call_date, call_time,
    call_by, call_result_cd, delay_reason_cd, call_result_notes, delayed_months, last_paid_month
) VALUES
(101, 1, '1', '2019-11-01', '2021-05-12', '10:15', 'AQEEL', 3, 1, 'متابعة خاصة بالاستقطاع 101 - لم يرد', 6, '2020-10-01'),
(101, 1, '1', '2019-11-01', '2022-08-20', '11:30', 'HASAN', 2, 4, 'متابعة خاصة بالاستقطاع 101 - طلب إيقاف هذا الاستقطاع فقط', 14, '2020-10-01');

-- 2. متابعة خاصة بالاستقطاع رقم 102 فقط (لنفس المتبرع رقم 1 - موسى عبداللطيف)
INSERT INTO donor_item_followup (
    so_id, donor_no, item_no, donation_start_date, call_date, call_time,
    call_by, call_result_cd, delay_reason_cd, call_result_notes, delayed_months, last_paid_month
) VALUES
(102, 1, '1', '2026-06-01', '2026-10-05', '09:45', 'TAREK', 1, 2, 'متابعة خاصة بالاستقطاع 102 - الاستقطاع منتظم ومستمر', 1, '2026-09-01');

-- 3. متابعة خاصة بالاستقطاع رقم 227 (للمتبرعة رقم 104 - عزيزه العلوي - مطابقة للصورة الأصلية في الـ PDF)
INSERT INTO donor_item_followup (
    so_id, donor_no, item_no, donation_start_date, call_date, call_time,
    call_by, call_result_cd, delay_reason_cd, call_result_notes, delayed_months, last_paid_month
) VALUES
(227, 104, '1', '2025-01-01', '2019-10-29', '10:25', 'AQEEL', 1, 2, 'استمارة جديدة - غير البنك', 3, '2019-07-01');
