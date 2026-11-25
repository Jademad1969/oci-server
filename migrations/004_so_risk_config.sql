-- =================================================================================
-- Migration 004: Standing Orders Composite Risk Scoring Configuration (so_risk_config)
-- =================================================================================
BEGIN;

CREATE TABLE IF NOT EXISTS so_risk_config (
    config_id           SMALLINT PRIMARY KEY DEFAULT 1 CHECK (config_id = 1),
    weight_monthly      SMALLINT NOT NULL DEFAULT 35 CHECK (weight_monthly BETWEEN 0 AND 100),
    weight_delay        SMALLINT NOT NULL DEFAULT 30 CHECK (weight_delay BETWEEN 0 AND 100),
    weight_loyalty      SMALLINT NOT NULL DEFAULT 20 CHECK (weight_loyalty BETWEEN 0 AND 100),
    weight_followup     SMALLINT NOT NULL DEFAULT 15 CHECK (weight_followup BETWEEN 0 AND 100),
    tier_critical_min   SMALLINT NOT NULL DEFAULT 75 CHECK (tier_critical_min BETWEEN 1 AND 100),
    tier_high_min       SMALLINT NOT NULL DEFAULT 55 CHECK (tier_high_min BETWEEN 1 AND 100),
    tier_medium_min     SMALLINT NOT NULL DEFAULT 35 CHECK (tier_medium_min BETWEEN 1 AND 100),
    followup_stale_days SMALLINT NOT NULL DEFAULT 60 CHECK (followup_stale_days BETWEEN 1 AND 365),
    updated_by          VARCHAR(30) DEFAULT 'SYSTEM',
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO so_risk_config (
    config_id, weight_monthly, weight_delay, weight_loyalty, weight_followup,
    tier_critical_min, tier_high_min, tier_medium_min, followup_stale_days, updated_by
) VALUES (1, 35, 30, 20, 15, 75, 55, 35, 60, 'SYSTEM')
ON CONFLICT (config_id) DO NOTHING;

COMMIT;
