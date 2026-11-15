-- 1. الإعدادات العامة للنظام
INSERT INTO sys_donor_setup (setup_id, not_paid_month, not_paid_month2, so_min_amt, accepted_delayed_months, grace_period_months)
VALUES (1, '2026-09-01', '2026-10-01', 10.000, 6, 2)
ON CONFLICT (setup_id) DO NOTHING;

-- 2. الأدوار والمستخدمين (كلمة المرور الافتراضية لـ TAREK و HASAN هي: 123456)
INSERT INTO sys_roles (role_id, role_code, role_name_ar, role_name_en, permissions) VALUES
(1, 'ADMIN', 'مدير النظام', 'System Administrator', '{"all": true}'::jsonb),
(2, 'DATA_ENTRY', 'مدخل بيانات ومطابقة', 'Data Entry & Reconciliation', '{"donors": true, "reconcile": true}'::jsonb),
(3, 'FOLLOWUP', 'موظف متابعة', 'Follow-up Agent', '{"followup": true, "reports": true}'::jsonb)
ON CONFLICT (role_code) DO NOTHING;

-- تشفير كلمة المرور '123456' باستخدام امتداد pgcrypto أو هاش Bcrypt قياسي
INSERT INTO sys_users (username, password_hash, full_name_ar, full_name_en, role_id) VALUES
('TAREK', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'طارق - مدير النظام', 'Tarek Admin', 1),
('HASAN', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'حسن - متابعة المتبرعين', 'Hasan Followup', 3)
ON CONFLICT (username) DO NOTHING;

-- 3. البنوك البحرينية وإعدادات المطابقة الخاصة بها
INSERT INTO lkp_banks (bank_cd, bank_desc, bank_e_desc, bank_type_islam, run_deactivate_delayed_so, auto_so_based_code, created_by) VALUES
(1, 'البحرين الإسلامي', 'BAHRAIN ISLAMIC BANK', 1, 1, 1, 'SYSTEM'),
(2, 'بنك السلام (إثمار سابقاً)', 'AL SALAM BANK (ITHMAR)', 1, 1, 1, 'SYSTEM'),
(4, 'البحرين الوطني', 'NATIONAL BANK OF BAHRAIN', 2, 1, 2, 'SYSTEM'),
(5, 'البحرين والكويت', 'BANK OF BAHRAIN AND KUWAIT', 2, 1, 1, 'SYSTEM'),
(6, 'الأهلي المتحد', 'AHLI UNITED BANK', 2, 1, 1, 'SYSTEM'),
(14, 'بيت التمويل الكويتي', 'KUWAIT FINANCE HOUSE', 1, 1, 2, 'SYSTEM'),
(19, 'البركة الإسلامي', 'AL BARAKA ISLAMIC BANK', 1, 1, 1, 'SYSTEM')
ON CONFLICT (bank_cd) DO NOTHING;

-- 4. الأكواد المرجعية (الألقاب، الرعاية، أنواع الحسابات، البنود، نتائج المتابعة)
INSERT INTO lkp_name_prefixes (prefix_cd, prefix_name, prefix_ename) VALUES
(1, 'حضرة الفاضل', 'Mr.'), (2, 'حضرة الفاضلة', 'Mrs./Ms.'), (3, 'سعادة الشيخ', 'Sheikh'), (4, 'الدكتور', 'Dr.')
ON CONFLICT (prefix_cd) DO NOTHING;

INSERT INTO lkp_cares (care_cd, care_nm) VALUES
(1, 'حفظه الله'), (2, 'حفظها الله'), (3, 'المحترم'), (4, 'الموقر')
ON CONFLICT (care_cd) DO NOTHING;

INSERT INTO lkp_acc_types (acc_type_no, acc_type_desc, acc_type_e_desc) VALUES
(1, 'توفير', 'Saving'), (2, 'جاري', 'Current'), (3, 'بدون', 'None')
ON CONFLICT (acc_type_no) DO NOTHING;

INSERT INTO lkp_charity_items (item_cd, item_desc, item_e_desc) VALUES
('1', 'صدقة', 'Sadaqah'), ('2', 'زكاة', 'Zakat'), ('3', 'دعوة', 'Daawah'), ('4', 'مساهمة عامة', 'General')
ON CONFLICT (item_cd) DO NOTHING;

INSERT INTO lkp_band_master (band_cd, band_desc, band_edesc) VALUES
(1, 'التبرعات العامة والصدقات', 'General Donations')
ON CONFLICT (band_cd) DO NOTHING;

INSERT INTO lkp_band_details (band_det_cd, band_cd, band_det_desc, band_det_edesc) VALUES
(1, 1, 'صدقة', 'Sadaqah'), (2, 1, 'زكاة', 'Zakat'), (3, 1, 'دعوة', 'Daawah'), (4, 1, 'مساهمة عامة', 'General')
ON CONFLICT (band_det_cd) DO NOTHING;

INSERT INTO lkp_towns (block_cd, town_nm, etown_nm) VALUES
(210, 'المحرق', 'Muharraq'), (324, 'الجفير', 'Juffair'), (356, 'المنامة', 'Manama'), (721, 'مدينة عيسى', 'Isa Town'), (912, 'الرفاع', 'Riffa')
ON CONFLICT (block_cd) DO NOTHING;

INSERT INTO lkp_follow_results (result_cd, result_nm, result_enm) VALUES
(1, 'سوف يستمر', 'Will Continue'), (2, 'اعتذر عن الاستمرار', 'Cancelled'), (3, 'لم يرد على الاتصال', 'No Answer'), (4, 'الرقم غير صحيح / مفصول', 'Wrong Number'), (5, 'وعد بتحديث الاستمارة بالبنك', 'Promised to Update')
ON CONFLICT (result_cd) DO NOTHING;

INSERT INTO lkp_delay_reasons (reason_cd, reason_nm, reason_enm) VALUES
(1, 'عدم كفاية الرصيد', 'Insufficient Funds'), (2, 'تغيير البنك أو الحساب', 'Changed Bank'), (3, 'انتهاء صلاحية الاستقطاع بالبنك', 'SO Expired'), (4, 'ظروف مالية خاصة', 'Financial Reasons')
ON CONFLICT (reason_cd) DO NOTHING;

-- 5. إدراج متبرعين واستقطاعات وحركات مالية مطابقة لواقع الجمعية للاختبار
INSERT INTO donor_master (donor_no, name_prefix, f_nm, s_nm, t_nm, l_nm, donor_name, donor_ename, gen_cd, lang_cd, donor_contact, donor_cpr, care, address_type, donor_p_box, donor_tel1, donor_tel2, donor_mobile, bank2_cd, acc_type_no, donor_acc_no, donor_name_acc, status_no, user_id, append_date)
VALUES
(1, 1, 'موسى', 'عبداللطيف', '', 'مصطفى', 'موسى عبداللطيف مصطفى', 'Moosa A Latif Mutafa', 1, 1, 1, '490101143', '1', 2, 11, '17293817', '39120638', '39699500', 1, 3, '245661601', 'Moosa A Latif Mutafa', 1, 'TAREK', '2010-10-02'),
(104, 2, 'عزيزه', 'محمد', 'طيب', 'العلوي', 'عزيزه محمد طيب العلوي', 'Aziza Mohd Taib Al Alawi', 2, 1, 1, '710304277', '2', 1, NULL, '17292329', '39294002', NULL, 1, 1, '1-504327-1-3', 'Aziza Mohd Taib Al Alawi', 2, 'HASAN', '2002-11-25'),
(215, 1, 'خالد', 'أحمد', 'سلمان', 'البستكي', 'خالد أحمد سلمان البستكي', 'Khalid Ahmed Salman Al Bastaki', 1, 1, 1, '820511234', '1', 1, NULL, NULL, '39445566', NULL, 4, 1, '01-998877-2', 'Khalid Ahmed Al Bastaki', 1, 'TAREK', '2026-09-14')
ON CONFLICT (donor_no) DO NOTHING;

INSERT INTO donor_item (so_id, donor_no, item_no, item_no2, donation_start_date, monthly_pay, bank2_cd, donor_acc_no, sort_field, alt_so_code, through_form, status_no, userid, append_date)
VALUES
(101, 1, '1', 1, '2019-11-01', 10.000, 1, '123456', '999', '0', 1, 2, 'TAREK', '2019-11-01'),
(102, 1, '1', 1, '2026-06-01', 30.000, 1, '2-456616-01', '374', NULL, 1, 1, 'TAREK', '2026-06-01'),
(227, 104, '1', 1, '2025-01-01', 5.000, 1, '1-504327-1-3', '3837', NULL, 1, 2, 'HASAN', '2025-01-01')
ON CONFLICT (so_id) DO NOTHING;

-- إدراج حركات مالية (أشهر مسددة وأشهر غير مسددة لحساب أشهر التأخير بدقة)
INSERT INTO money_trans (so_id, month_year, donor_no, item_no, donation_start_date, paid_sum, status_no, bank_cd, st_order_no) VALUES
(102, '2026-06-01', 1, '1', '2026-06-01', 30.000, 1, 1, '374'),
(102, '2026-07-01', 1, '1', '2026-06-01', 30.000, 1, 1, '374'),
(102, '2026-08-01', 1, '1', '2026-06-01', 30.000, 1, 1, '374'),
(102, '2026-09-01', 1, '1', '2026-06-01', 30.000, 1, 1, '374'),
(102, '2026-10-01', 1, '1', '2026-06-01', 30.000, 1, 1, '374'),
(102, '2026-11-01', 1, '1', '2026-06-01', 30.000, 2, 1, '374'),
(227, '2025-04-01', 104, '1', '2025-01-01', 5.000, 1, 1, '3837')
ON CONFLICT (so_id, month_year) DO NOTHING;

INSERT INTO donor_followup (donor_no, call_date, call_time, call_by, call_result_cd, call_result_notes)
VALUES (104, '2025-03-18', '11:00', 'HASAN', 1, 'وعدت بتحديث الاستقطاع')
ON CONFLICT (donor_no, call_date) DO NOTHING;
