#**migrations**

The `migrations` folder holds the SQL scripts that move an existing database to the schema the current version of the library expects.
A brand new database does not need them, because `CheckTables` creates every table in its latest form.

Each script has a running number in its name (`001_...`), runs inside a single transaction, and is safe to run more than once, so a failure leaves the database exactly as it was.

## 1. Expiry Columns (`001_expiry_timestamptz.sql`)
This script changes `expires_at` in the `otps` and `refresh_tokens` tables from `TIMESTAMP` to `TIMESTAMPTZ`.

* **The Problem:** A plain `TIMESTAMP` has no time zone. The old code gave it the local time of the application server, so a server in India (UTC+5:30) saved an OTP that expires at 18:35 local time as `18:35`, and the library then read that back as 18:35 UTC. On a server in the US (UTC-8) the OTP was already expired the moment it was sent, and on a server in India it stayed valid for hours too long.
* **The Fix:** `TIMESTAMPTZ` stores an exact moment in time. The library now always writes expiry times in UTC and reads them back in UTC, so an OTP lasts the same 5 minutes whatever the time zone of the server is.
* **Why you must tell it the old zone:** The rows that are already in the table only hold the local clock reading, and the database cannot work out which zone that was. The script assumes UTC unless you say otherwise.

```
psql "$DATABASE_URL" -f migrations/001_expiry_timestamptz.sql
```

If your application servers were not running in UTC, pass their zone (any name from `pg_timezone_names`):

```
PGOPTIONS="-c auth.legacy_tz=Asia/Kolkata" psql "$DATABASE_URL" -f migrations/001_expiry_timestamptz.sql
```

* **If you forget it:** `CheckTables` (so `auth.New`) returns `ErrSchemaOutdated` when it finds the old column type, instead of silently running on the old schema.
* **If the zone name is wrong:** The script stops with an error before it changes anything.
* **While it runs:** Changing a column type rewrites the table and locks it, so stop the application first. Old OTPs and refresh tokens that were written in a different zone than you declared are off by that difference only until they expire.
* **Not changed:** `created_at` in `refresh_tokens` is not an expiry column, so it stays a `TIMESTAMP`. It is written by `NOW()` on a connection that is set to UTC.

## 2. Testing other time zones
The tests in `tests/timezone_test.go` cover the OTP and refresh token expiry, the storage layer and this migration.
To run the whole test process in another time zone, set `AUTH_TEST_TZ` (the normal `TZ` variable is not used because Go ignores it on Windows):

```
AUTH_TEST_TZ=Asia/Kolkata go test ./tests/
```

The CI does this for three zones (+5:30, -8 or -7 with daylight saving, and +14), so a change that makes expiry depend on the server's time zone fails the build.
