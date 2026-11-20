CREATE OR REPLACE TRIGGER trg_rollback_money_trans_on_delete
BEFORE DELETE ON bank_statement_load
FOR EACH ROW EXECUTE FUNCTION fn_rollback_money_trans_on_stmnt_delete();

CREATE TABLE IF NOT EXISTS bankmonthly_stmntupd (
    bank_cd SMALLINT NOT NULL REFERENCES lkp_banks(bank_cd),
    month_year DATE NOT NULL,
    updated_by VARCHAR(30) NOT NULL,
    update_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_amt NUMERIC(12,3) NOT NULL,
    PRIMARY KEY (bank_cd, month_year)
);

CREATE TABLE IF NOT EXISTS last_bank_statement (
    bank_cd SMALLINT NOT NULL,
    month_year DATE NOT NULL,
    PRIMARY KEY (bank_cd, month_year)
);

CREATE TABLE IF NOT EXISTS other_payments (
    payment_id SERIAL PRIMARY KEY,
    donation_desc VARCHAR(100),
    donation_date DATE,
    donation_bank SMALLINT REFERENCES lkp_banks(bank_cd),
    donation_amt NUMERIC(10,3)
);

CREATE TABLE IF NOT EXISTS donor_followup (
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

CREATE TABLE IF NOT EXISTS donor_item_followup (
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

CREATE TABLE IF NOT EXISTS donor_item_deactiv_hist (
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

CREATE TABLE IF NOT EXISTS donor_item_actdeact_trns (
    trans_id SERIAL PRIMARY KEY,
    so_id INT REFERENCES donor_item(so_id),
    donor_no INT NOT NULL,
    item_no INT NOT NULL,
    start_date DATE NOT NULL,
    trans_type SMALLINT NOT NULL,
    trans_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS deactivate_donor_trans (
    trans_cd SERIAL PRIMARY KEY,
    donor_no INT NOT NULL REFERENCES donor_master(donor_no),
    trans_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    append_by VARCHAR(30) NOT NULL,
    reason_notes VARCHAR(150)
);

CREATE INDEX IF NOT EXISTS idx_donor_master_status ON donor_master(status_no);
CREATE INDEX IF NOT EXISTS idx_donor_master_cpr ON donor_master(donor_cpr);
CREATE INDEX IF NOT EXISTS idx_donor_master_mobile ON donor_master(donor_tel2, donor_mobile);
CREATE INDEX IF NOT EXISTS idx_donor_master_name ON donor_master(donor_name);
CREATE INDEX IF NOT EXISTS idx_donor_item_donor_no ON donor_item(donor_no);
CREATE INDEX IF NOT EXISTS idx_donor_item_bank_status ON donor_item(bank2_cd, status_no);
CREATE INDEX IF NOT EXISTS idx_donor_item_sort_field ON donor_item(UPPER(sort_field));
CREATE INDEX IF NOT EXISTS idx_donor_item_alt_code ON donor_item(UPPER(alt_so_code));
CREATE INDEX IF NOT EXISTS idx_money_trans_donor_no ON money_trans(donor_no);
CREATE INDEX IF NOT EXISTS idx_money_trans_month_bank_status ON money_trans(month_year, bank_cd, status_no);
CREATE INDEX IF NOT EXISTS idx_money_trans_so_status_month ON money_trans(so_id, status_no, month_year DESC);
CREATE INDEX IF NOT EXISTS idx_money_trans_st_order ON money_trans(bank_cd, month_year, st_order_no);
CREATE INDEX IF NOT EXISTS idx_bnkstmnt_load_bank_month ON bank_statement_load(bank_cd, money_trans_month);
