-- =================================================================================
-- نظام إدارة الاستقطاعات الشهرية - جمعية اكتشف الإسلام (DIC Bahrain)
-- PostgreSQL 16 Unified & Refactored Schema (Merged LOOKUP + DONOR + RBAC)
-- =================================================================================

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

-- =================================================================================
-- 1. جداول إدارة المستخدمين والأدوار والصلاحيات (RBAC & Security)
--    (بديل حديث ومشفر لجدول DIC_USERS و SCREEN_TABLE و GRANT_MENU)
-- =================================================================================

CREATE TABLE sys_roles (
    role_id SERIAL PRIMARY KEY,
    role_code VARCHAR(30) UNIQUE NOT NULL, -- ADMIN, DATA_ENTRY, RECONCILIATION, FOLLOWUP, AUDITOR
    role_name_ar VARCHAR(60) NOT NULL,
    role_name_en VARCHAR(60) NOT NULL,
    permissions JSONB NOT NULL DEFAULT '{}'::jsonb, -- صلاحيات الشاشات والعمليات
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE sys_users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(30) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Bcrypt Hashed Password
    full_name_ar VARCHAR(60) NOT NULL,
    full_name_en VARCHAR(60),
    role_id INT NOT NULL REFERENCES sys_roles(role_id),
    emp_id INT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =================================================================================
-- 2. جداول الأكواد المرجعية والإعدادات (Merged from LOOKUP & DONOR_SETUP)
-- =================================================================================

CREATE TABLE sys_donor_setup (
    setup_id INT PRIMARY KEY DEFAULT 1 CHECK (setup_id = 1), -- يضمن وجود سجل إعدادات واحد فقط
    not_paid_month DATE,
    not_paid_month2 DATE,
    so_min_amt NUMERIC(8,3) NOT NULL DEFAULT 10.000,
    accepted_delayed_months INT NOT NULL DEFAULT 6,
    grace_period_months INT NOT NULL DEFAULT 2, -- فترة السماح (شهرين)
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE lkp_banks (
    bank_cd SMALLINT PRIMARY KEY,
    bank_desc VARCHAR(75) NOT NULL,
    bank_e_desc VARCHAR(75) NOT NULL,
    bank_type_islam SMALLINT DEFAULT 1,
    subscription_ltrcd VARCHAR(10),
    po_box INT,
    dic_accno VARCHAR(40),
    run_deactivate_delayed_so SMALLINT NOT NULL DEFAULT 1, -- 1: Yes, 2: No
    fawri_keywords VARCHAR(500) DEFAULT 'FAWRI,CASH,BENEFIT',
    bnkstmnt_code_type SMALLINT DEFAULT 1,
    auto_so_based_code SMALLINT NOT NULL DEFAULT 1, -- 1: Original SO Code (sort_field), 2: Alt Code (alt_so_code)
    created_by VARCHAR(30),
    created_on TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE lkp_bank_accounts (
    bank_cd SMALLINT NOT NULL REFERENCES lkp_banks(bank_cd),
    bank_acc_no VARCHAR(50) NOT NULL,
    iban VARCHAR(100),
    account_name VARCHAR(75),
    account_status SMALLINT NOT NULL DEFAULT 1,
    so_account SMALLINT NOT NULL DEFAULT 2,
    deactivation_date DATE,
    deactivation_reason VARCHAR(200),
    PRIMARY KEY (bank_cd, bank_acc_no)
);

CREATE TABLE lkp_acc_types (
    acc_type_no SMALLINT PRIMARY KEY,
    acc_type_desc VARCHAR(25) NOT NULL,
    acc_type_e_desc VARCHAR(25)
);

CREATE TABLE lkp_name_prefixes (
    prefix_cd SMALLINT PRIMARY KEY,
    prefix_name VARCHAR(35) NOT NULL,
    prefix_ename VARCHAR(35)
);

CREATE TABLE lkp_cares (
    care_cd SMALLINT PRIMARY KEY,
    care_nm VARCHAR(35) NOT NULL
);

CREATE TABLE lkp_towns (
    block_cd INT PRIMARY KEY,
    town_nm VARCHAR(40) NOT NULL,
    etown_nm VARCHAR(40)
);

CREATE TABLE lkp_regions (
    region_cd SMALLINT PRIMARY KEY,
    region_desc VARCHAR(30) NOT NULL,
    region_e_desc VARCHAR(30)
);

CREATE TABLE lkp_charity_items (
    item_cd VARCHAR(4) PRIMARY KEY,
    item_desc VARCHAR(50) NOT NULL,
    item_e_desc VARCHAR(50),
    item_max_value NUMERIC(8,3),
    has_details SMALLINT DEFAULT 2,
    receipt_print SMALLINT DEFAULT 1
);

CREATE TABLE lkp_band_master (
    band_cd INT PRIMARY KEY,
    band_desc VARCHAR(50) NOT NULL,
    band_edesc VARCHAR(50),
    estimate_val NUMERIC(9,3),
    outgoing_val NUMERIC(9,3),
    benefit_code VARCHAR(30) UNIQUE,
    usernm VARCHAR(30)
);

CREATE TABLE lkp_band_details (
    band_det_cd INT PRIMARY KEY,
    band_cd INT REFERENCES lkp_band_master(band_cd),
    band_det_desc VARCHAR(50) NOT NULL,
    band_det_edesc VARCHAR(50),
    estimate_det_val NUMERIC(9,3),
    outgoing_det_val NUMERIC(9,3),
    nation_flag SMALLINT DEFAULT 2,
    model_cd SMALLINT,
    usernm VARCHAR(30)
);

CREATE TABLE lkp_contact_feedback (
    feedback_cd SMALLINT PRIMARY KEY,
    feedback_desc VARCHAR(60) NOT NULL
);

CREATE TABLE lkp_follow_results (
    result_cd SMALLINT PRIMARY KEY,
    result_nm VARCHAR(100) NOT NULL,
    result_enm VARCHAR(100)
);

CREATE TABLE lkp_delay_reasons (
    reason_cd SMALLINT PRIMARY KEY,
    reason_nm VARCHAR(100) NOT NULL,
    reason_enm VARCHAR(100)
);

CREATE TABLE lkp_messages (
    message_cd SMALLINT PRIMARY KEY,
    message_brief VARCHAR(60) NOT NULL,
    message_text TEXT NOT NULL,
    message_etext TEXT,
    message_type SMALLINT
);

-- =================================================================================
-- 3. جداول المتبرعين والاستقطاعات (Core Donor & Standing Orders Tables)
-- =================================================================================

CREATE SEQUENCE seq_so_id START WITH 6355;
CREATE SEQUENCE seq_bnkstmnt_transid START WITH 1259301 CACHE 20;

CREATE TABLE donor_master (
    donor_no INT PRIMARY KEY,
    name_prefix SMALLINT REFERENCES lkp_name_prefixes(prefix_cd),
    donor_name VARCHAR(100) NOT NULL,
    donor_ename VARCHAR(100),
    f_nm VARCHAR(25),
    s_nm VARCHAR(25),
    t_nm VARCHAR(25),
    l_nm VARCHAR(25),
    ll_nm VARCHAR(25),
    f_enm VARCHAR(25),
    s_enm VARCHAR(25),
    t_enm VARCHAR(25),
    l_enm VARCHAR(25),
    gen_cd SMALLINT CHECK (gen_cd IN (1, 2)), -- 1: ذكر, 2: أنثى
    lang_cd SMALLINT DEFAULT 1,               -- 1: عربي, 2: إنجليزي
    donor_contact SMALLINT DEFAULT 1 CHECK (donor_contact IN (1, 2)), -- 1: نعم, 2: لا
    donor_cpr VARCHAR(11),                    -- الرقم السكاني البحريني (9 أرقام)
    care VARCHAR(15),
    address_type SMALLINT DEFAULT 1,          -- 1: عنوان منزل, 2: ص.ب / غير مباشر
    donor_flat SMALLINT,
    donor_building VARCHAR(15),
    donor_road VARCHAR(50),
    donor_block INT,
    town_cd SMALLINT,
    donor_p_box INT,
    full_address VARCHAR(150),
    donor_tel1 VARCHAR(20),
    donor_tel2 VARCHAR(20),                   -- نقال 1
    donor_mobile VARCHAR(20),                 -- نقال 2
    donor_fax VARCHAR(20),
    bank1_cd SMALLINT REFERENCES lkp_banks(bank_cd),
    bank2_cd SMALLINT REFERENCES lkp_banks(bank_cd),
    acc_type_no SMALLINT REFERENCES lkp_acc_types(acc_type_no),
    donor_acc_no VARCHAR(30),
    donor_name_acc VARCHAR(60),
    donor_ename_acc VARCHAR(60),
    status_no SMALLINT NOT NULL DEFAULT 1,    -- 1: فعال, 2: غير فعال
    thanking_ltr SMALLINT DEFAULT 2,
    contact_feedback SMALLINT REFERENCES lkp_contact_feedback(feedback_cd),
    notes VARCHAR(250),
    user_id VARCHAR(30),
    append_date DATE DEFAULT CURRENT_DATE,
    last_update TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    call_date DATE,
    flg INT
);

CREATE TABLE donor_item (
    so_id INT PRIMARY KEY DEFAULT nextval('seq_so_id'),
    donor_no INT NOT NULL REFERENCES donor_master(donor_no),
    item_no VARCHAR(4) NOT NULL,              -- بند التبرع النصي
    item_no2 SMALLINT NOT NULL,               -- ربط بجدول lkp_band_details
    region_no SMALLINT DEFAULT 0,
    donation_start_date DATE NOT NULL,
    donation_expected_edate DATE,
    frequency NUMERIC(3,1) DEFAULT 1.0,
    monthly_pay NUMERIC(10,3) NOT NULL,       -- الدقة المالية للدينار البحريني (3 خانات عشرية)
    bank1_cd SMALLINT REFERENCES lkp_banks(bank_cd),
    bank2_cd SMALLINT NOT NULL REFERENCES lkp_banks(bank_cd),
    acc_type_no SMALLINT,
    donor_acc_no VARCHAR(30),
    sort_field VARCHAR(25),                   -- كود الاستقطاع الأصلي في البنك
    alt_so_code VARCHAR(25),                  -- كود الاستقطاع البديل (إثمار/السلام)
    through_form SMALLINT NOT NULL DEFAULT 1, -- 1: باستمارة, 2: بدون استمارة
    status_no SMALLINT NOT NULL DEFAULT 1,    -- 1: فعال, 2: غير فعال
    dic_representer VARCHAR(50),
    userid VARCHAR(30) NOT NULL,
    append_date DATE NOT NULL DEFAULT CURRENT_DATE,
    reactive_by VARCHAR(30),
    reactive_date DATE,
    deactive_date DATE
);

-- تريجر تنظيف الكود البديل تلقائياً (يحاكي TRIMITHMARCODE في النظام القديم)
CREATE OR REPLACE FUNCTION fn_clean_donor_item_codes()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.alt_so_code IS NOT NULL THEN
        NEW.alt_so_code := UPPER(TRIM(NEW.alt_so_code));
    END IF;
    IF NEW.sort_field IS NOT NULL THEN
        NEW.sort_field := TRIM(NEW.sort_field);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_clean_donor_item_codes
BEFORE INSERT OR UPDATE ON donor_item
FOR EACH ROW EXECUTE FUNCTION fn_clean_donor_item_codes();

-- =================================================================================
-- 4. جداول الحركات المالية الشهرية ومطابقة البنوك (Transactions & Reconciliation)
-- =================================================================================

CREATE TABLE money_trans (
    so_id INT NOT NULL REFERENCES donor_item(so_id),
    month_year DATE NOT NULL,                 -- دائماً أول يوم في الشهر (YYYY-MM-01)
    donor_no INT NOT NULL REFERENCES donor_master(donor_no),
    item_no VARCHAR(4) NOT NULL,
    region_no SMALLINT DEFAULT 0,
    donation_start_date DATE NOT NULL,
    paid_sum NUMERIC(10,3) NOT NULL,
    status_no SMALLINT NOT NULL DEFAULT 2,    -- 1: مسدد (Collected), 2: غير مسدد (Unpaid)
    pay_type SMALLINT DEFAULT 2,
    bank_cd SMALLINT NOT NULL REFERENCES lkp_banks(bank_cd),
    st_order_no VARCHAR(25) NOT NULL,
    alt_st_no VARCHAR(25),
    receipt_no INT,
    receipt_date DATE,
    original_record VARCHAR(2),
    bank_statmnt_transid BIGINT,
    bank_statmnt_transdate TIMESTAMP WITH TIME ZONE,
    bank_statmnt_trnauser VARCHAR(30),
    PRIMARY KEY (so_id, month_year)
);

CREATE TABLE last_update_money_trans (
    last_up DATE PRIMARY KEY
);

CREATE TABLE bank_statement_load (
    trans_id BIGINT PRIMARY KEY DEFAULT nextval('seq_bnkstmnt_transid'),
    bank_cd SMALLINT NOT NULL REFERENCES lkp_banks(bank_cd),
    money_trans_month DATE NOT NULL,          -- الشهر الذي تتم مطابقته (YYYY-MM-01)
    bank_stmnt_month VARCHAR(100) NOT NULL,   -- تاريخ الإيداع كما ورد في ملف البنك
    bank_stmnt_paydesc VARCHAR(2500) NOT NULL,
    bank_stmnt_payamt NUMERIC(15,3) NOT NULL DEFAULT 0,
    cash_deposit SMALLINT,                    -- 1: Cash/Fawri, 2: SO, 3: Fawri+
    st_order_no VARCHAR(30),
    sys_found SMALLINT DEFAULT 0,
    sys_amt NUMERIC(15,3),
    money_trans_found SMALLINT DEFAULT 0,
    money_trans_status SMALLINT NOT NULL DEFAULT 2,
    so_id INT REFERENCES donor_item(so_id),
    donor_no INT,
    item_no INT,
    donation_start_date DATE,
    user_nm VARCHAR(30) NOT NULL,
    time_stamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- تريجر الحماية العكسي عند حذف كشف البنك (يحاكي UPDATE_MONYTRNS_TONULL بدقة وأمان)
CREATE OR REPLACE FUNCTION fn_rollback_money_trans_on_stmnt_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.cash_deposit = 2 AND OLD.sys_found = 1 AND OLD.so_id IS NOT NULL THEN
        UPDATE money_trans
        SET bank_statmnt_transid = NULL,
            bank_statmnt_transdate = NULL,
            bank_statmnt_trnauser = NULL,
            status_no = 2
        WHERE so_id = OLD.so_id
          AND bank_cd = OLD.bank_cd
          AND month_year = OLD.money_trans_month;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_rollback_money_trans_on_delete
BEFORE DELETE ON bank_statement_load
FOR EACH ROW EXECUTE FUNCTION fn_rollback_money_trans_on_stmnt_delete();

CREATE TABLE bankmonthly_stmntupd (
    bank_cd SMALLINT NOT NULL REFERENCES lkp_banks(bank_cd),
    month_year DATE NOT NULL,
    updated_by VARCHAR(30) NOT NULL,
    update_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_amt NUMERIC(12,3) NOT NULL,
    PRIMARY KEY (bank_cd, month_year)
);

CREATE TABLE last_bank_statement (
    bank_cd SMALLINT NOT NULL,
    month_year DATE NOT NULL,
    PRIMARY KEY (bank_cd, month_year)
);

CREATE TABLE other_payments (
    payment_id SERIAL PRIMARY KEY,
    donation_desc VARCHAR(100),
    donation_date DATE,
    donation_bank SMALLINT REFERENCES lkp_banks(bank_cd),
    donation_amt NUMERIC(10,3)
);

-- =================================================================================
-- 5. جداول المتابعة وأرشفة الإيقاف والتدقيق (Follow-up & Audit History)
-- =================================================================================

CREATE TABLE donor_followup (
    trans_id SERIAL PRIMARY KEY,
    donor_no INT NOT NULL REFERENCES donor_master(donor_no),
    call_date DATE NOT NULL,
    call_time VARCHAR(10),
    call_by VARCHAR(30) NOT NULL,
    call_result_cd SMALLINT NOT NULL REFERENCES lkp_follow_results(result_cd),
    call_result_notes VARCHAR(250),
    append_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (donor_no, call_date)
);

CREATE TABLE donor_item_followup (
    trans_id SERIAL PRIMARY KEY,
    so_id INT NOT NULL REFERENCES donor_item(so_id),
    donor_no INT NOT NULL REFERENCES donor_master(donor_no),
    item_no VARCHAR(4) NOT NULL,
    donation_start_date DATE NOT NULL,
    call_date DATE NOT NULL,
    call_time VARCHAR(10),
    call_by VARCHAR(30) NOT NULL,
    call_result_cd SMALLINT NOT NULL REFERENCES lkp_follow_results(result_cd),
    delay_reason_cd SMALLINT NOT NULL REFERENCES lkp_delay_reasons(reason_cd),
    call_result_notes VARCHAR(250),
    delayed_months SMALLINT NOT NULL,
    last_paid_month DATE NOT NULL,
    msg_type SMALLINT,
    msg_date DATE,
    msg_text VARCHAR(500),
    append_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE donor_item_deactiv_hist (
    id SERIAL PRIMARY KEY,
    so_id INT REFERENCES donor_item(so_id),
    donor_no INT NOT NULL REFERENCES donor_master(donor_no),
    item_no SMALLINT NOT NULL,
    donation_start_date DATE NOT NULL,
    delay_month SMALLINT NOT NULL,
    deactive_date DATE NOT NULL DEFAULT CURRENT_DATE,
    bank_cd SMALLINT NOT NULL,
    deactive_reason VARCHAR(150)
);

CREATE TABLE donor_item_actdeact_trns (
    trans_id SERIAL PRIMARY KEY,
    so_id INT REFERENCES donor_item(so_id),
    donor_no INT NOT NULL,
    item_no INT NOT NULL,
    start_date DATE NOT NULL,
    trans_type SMALLINT NOT NULL, -- 1: Activated, 2: Deactivated
    trans_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE deactivate_donor_trans (
    trans_cd SERIAL PRIMARY KEY,
    donor_no INT NOT NULL REFERENCES donor_master(donor_no),
    trans_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    append_by VARCHAR(30) NOT NULL,
    reason_notes VARCHAR(150)
);

-- =================================================================================
-- 6. الفهارس عالية الأداء (High-Performance Indexes for 500K+ Rows)
-- =================================================================================

CREATE INDEX idx_donor_master_status ON donor_master(status_no);
CREATE INDEX idx_donor_master_cpr ON donor_master(donor_cpr);
CREATE INDEX idx_donor_master_mobile ON donor_master(donor_tel2, donor_mobile);
CREATE INDEX idx_donor_master_name ON donor_master(donor_name);

CREATE INDEX idx_donor_item_donor_no ON donor_item(donor_no);
CREATE INDEX idx_donor_item_bank_status ON donor_item(bank2_cd, status_no);
CREATE INDEX idx_donor_item_sort_field ON donor_item(UPPER(sort_field));
CREATE INDEX idx_donor_item_alt_code ON donor_item(UPPER(alt_so_code));

CREATE INDEX idx_money_trans_donor_no ON money_trans(donor_no);
CREATE INDEX idx_money_trans_month_bank_status ON money_trans(month_year, bank_cd, status_no);
CREATE INDEX idx_money_trans_so_status_month ON money_trans(so_id, status_no, month_year DESC);
CREATE INDEX idx_money_trans_st_order ON money_trans(bank_cd, month_year, st_order_no);

CREATE INDEX idx_bnkstmnt_load_bank_month ON bank_statement_load(bank_cd, money_trans_month);
