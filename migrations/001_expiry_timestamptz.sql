-- 001_expiry_timestamptz.sql
--
-- Converts otps.expires_at and refresh_tokens.expires_at from TIMESTAMP to TIMESTAMPTZ.
-- See docs/migrations.md for the background.
--
-- Older versions stored the application host's local wall-clock time in these columns,
-- and Postgres cannot tell which zone that was. Pass it in auth.legacy_tz (default UTC):
--
--   psql "$DATABASE_URL" -f migrations/001_expiry_timestamptz.sql
--   PGOPTIONS="-c auth.legacy_tz=Asia/Kolkata" psql "$DATABASE_URL" -f migrations/001_expiry_timestamptz.sql
--
-- Safe to re-run: columns that are already TIMESTAMPTZ and tables that do not exist are skipped.
-- An unknown zone name aborts the script before anything is changed.
-- ALTER COLUMN ... TYPE rewrites the table under an ACCESS EXCLUSIVE lock, so run it while the app is stopped.
--
-- Rollback (writes UTC wall-clock time back):
--   ALTER TABLE otps           ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
--   ALTER TABLE refresh_tokens ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';

BEGIN;

-- Give up after 10s instead of queueing behind a long transaction and blocking every other query.
SET LOCAL lock_timeout = '10s';

DO $$
DECLARE
    legacy_tz text := COALESCE(NULLIF(current_setting('auth.legacy_tz', true), ''), 'UTC');
    tbl       text;
BEGIN
    -- Raises "time zone ... not recognized" for a typo, which rolls everything back.
    PERFORM now() AT TIME ZONE legacy_tz;

    FOR tbl IN
        SELECT c.table_name::text
        FROM information_schema.columns c
        WHERE c.table_schema = current_schema()
          AND c.table_name IN ('otps', 'refresh_tokens')
          AND c.column_name = 'expires_at'
          AND c.data_type = 'timestamp without time zone'
        ORDER BY c.table_name
    LOOP
        EXECUTE format(
            'ALTER TABLE %I ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE %L',
            tbl, legacy_tz
        );
        RAISE NOTICE '%.expires_at converted to TIMESTAMPTZ (legacy zone: %)', tbl, legacy_tz;
    END LOOP;
END
$$;

COMMIT;
