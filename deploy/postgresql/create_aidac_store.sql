-- Run with psql as a PostgreSQL administrator.
-- This script intentionally does not contain a password.

CREATE ROLE aidac_app LOGIN;
\password aidac_app

GRANT CONNECT ON DATABASE aidac_pgsql TO aidac_app;

\connect aidac_pgsql

CREATE SCHEMA IF NOT EXISTS aidac AUTHORIZATION aidac_app;
GRANT USAGE, CREATE ON SCHEMA aidac TO aidac_app;

-- AI-DAC creates and migrates its lifecycle tables with:
--   export AIDAC_ALERT_STORE_DSN='postgresql://aidac_app:...@HOST:5432/aidac_pgsql'
--   export AIDAC_ALERT_STORE_SCHEMA='aidac'
--   aidac storage init
