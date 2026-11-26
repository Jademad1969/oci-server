-- =================================================================================
-- Migration 007: Add auto_generate_monthly_so control to sys_donor_setup
--                & update sp_generate_monthly_payments to honor it safely
-- =================================================================================
BEGIN;

-- 1. Add boolean switch to sys_donor_setup (Default FALSE until Go-Live)
ALTER TABLE sys_donor_setup
    ADD COLUMN IF NOT EXISTS auto_generate_monthly_so BOOLEAN NOT NULL DEFAULT FALSE;

-- Ensure singleton row exists
INSERT INTO sys_donor_setup (setup_id, so_min_amt, accepted_delayed_months, grace_period_months, auto_generate_monthly_so)
VALUES (1, 10.000, 6, 2, FALSE)
ON CONFLICT (setup_id) DO NOTHING;

-- 2. Update sp_generate_monthly_payments to check auto_generate_monthly_so
--    and strictly avoid PK (so_id, month_year) conflicts via NOT EXISTS + ON CONFLICT DO NOTHING
CREATE OR REPLACE PROCEDURE public.sp_generate_monthly_payments(
    IN p_target_month DATE DEFAULT (date_trunc('month'::text, (CURRENT_DATE)::timestamp with time zone))::date
)
LANGUAGE plpgsql
AS $procedure$
DECLARE
    v_month DATE := DATE_TRUNC('month', p_target_month)::date;
    v_auto_enabled BOOLEAN := FALSE;
BEGIN
    SELECT COALESCE(auto_generate_monthly_so, FALSE)
    INTO v_auto_enabled
    FROM sys_donor_setup
    WHERE setup_id = 1;

    IF NOT COALESCE(v_auto_enabled, FALSE) THEN
        RAISE NOTICE 'sp_generate_monthly_payments skipped: auto_generate_monthly_so is disabled in sys_donor_setup.';
        RETURN;
    END IF;

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
$procedure$;

COMMIT;
