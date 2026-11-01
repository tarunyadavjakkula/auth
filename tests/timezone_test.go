package tests

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

/*
Zones the storage tests are repeated in: a half-hour positive offset,
a negative offset with DST, and the largest positive offset (UTC+14).
*/
var nonUTCZones = []string{"Asia/Kolkata", "America/Los_Angeles", "Pacific/Kiritimati"}

/* Column types as reported by information_schema. */
const (
	typeTimestamp   = "timestamp without time zone"
	typeTimestamptz = "timestamp with time zone"
)

/* captureSender is an EmailSender that keeps the last body so a test can read the OTP out of it. */
type captureSender struct {
	mu   sync.Mutex
	body string
}

func (c *captureSender) SendEmail(_ context.Context, _, _, body string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.body = body
	return nil
}

var otpBodyPattern = regexp.MustCompile(`Your OTP is: (\d+)`)

func (c *captureSender) lastCode(t *testing.T) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	m := otpBodyPattern.FindStringSubmatch(c.body)
	if m == nil {
		t.Fatalf("no OTP found in email body %q", c.body)
	}
	return m[1]
}

func loadZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("failed to load zone %q: %v", name, err)
	}
	return loc
}

func openStorage(t *testing.T, ctx context.Context) *auth.PostgresStorage {
	t.Helper()
	s, err := auth.NewPostgresStorage(ctx, testDBPort, testDBUser, testDBPass, testDBName, testDBHost)
	if err != nil {
		t.Fatalf("failed to create PostgresStorage: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
	})
	return s
}

/* newTestStorage returns a PostgresStorage over a freshly created, current schema. */
func newTestStorage(t *testing.T) *auth.PostgresStorage {
	t.Helper()
	ctx := context.Background()
	preCleanDB(t, ctx)
	s := openStorage(t, ctx)
	if err := s.CheckTables(ctx); err != nil {
		t.Fatalf("failed to check tables: %v", err)
	}
	return s
}

/*
assertStoredExpiry reads the instant straight from the database, independent of
how the library reads it back. EXTRACT(EPOCH) of a timestamptz does not depend on
any session zone, while on a plain TIMESTAMP it is shifted by the writer's offset.
*/
func assertStoredExpiry(t *testing.T, db *pgxpool.Pool, table, keyColumn, key string, want time.Duration) {
	t.Helper()
	var epoch float64
	query := fmt.Sprintf("SELECT EXTRACT(EPOCH FROM expires_at)::float8 FROM %s WHERE %s = $1", table, keyColumn)
	if err := db.QueryRow(context.Background(), query, key).Scan(&epoch); err != nil {
		t.Fatalf("failed to read stored expiry from %s: %v", table, err)
	}
	skew := epoch - float64(time.Now().Unix()) - want.Seconds()
	if math.Abs(skew) > 30 {
		t.Errorf("expected %s expiry about %v from now, got %.0fs off: the stored instant is shifted by the local zone offset", table, want, skew)
	}
}

/* assertUTCInstant checks that a value read from storage is the expected instant, in UTC. */
func assertUTCInstant(t *testing.T, what string, got, want time.Time) {
	t.Helper()
	if !got.Equal(want) {
		t.Errorf("expected %s to return the instant %v, got: %v", what, want, got)
	}
	if got.Location() != time.UTC {
		t.Errorf("expected %s to return UTC, got zone: %v", what, got.Location())
	}
}

/* assertExpiryTypes checks the data type of both expiry columns. */
func assertExpiryTypes(t *testing.T, db *pgxpool.Pool, want string) {
	t.Helper()
	for _, table := range []string{"otps", "refresh_tokens"} {
		var got string
		err := db.QueryRow(context.Background(),
			"SELECT data_type::text FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = 'expires_at'",
			table,
		).Scan(&got)
		if err != nil {
			t.Fatalf("failed to read the type of %s.expires_at: %v", table, err)
		}
		if got != want {
			t.Errorf("expected %s.expires_at to be %q, got: %q", table, want, got)
		}
	}
}

/*
insertOTPRaw inserts an OTP whose expiry is the given SQL expression, so a test
can let either the Go client ($3) or the server's clock (NOW()) write the instant.
*/
func insertOTPRaw(t *testing.T, db *pgxpool.Pool, email, expiresExpr string, args ...any) {
	t.Helper()
	query := fmt.Sprintf("INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, %s)", expiresExpr)
	all := append([]any{email, computeTestOTPHash("123456")}, args...)
	if _, err := db.Exec(context.Background(), query, all...); err != nil {
		t.Fatalf("failed to insert OTP for %s: %v", email, err)
	}
}

/* ======================== Process Zone ======================== */

/*
TestTimezoneProcessZone verifies that the test process really runs in the zone
named by AUTH_TEST_TZ. Without it the CI runs would silently fall back to UTC.
*/
func TestTimezoneProcessZone(t *testing.T) {
	name := os.Getenv(testZoneEnv)
	if name == "" {
		t.Skipf("%s is not set", testZoneEnv)
	}

	if got := time.Now().Location().String(); got != name {
		t.Fatalf("expected process zone %q, got: %q", name, got)
	}
}

/* ======================== Schema ======================== */

/*
TestIntegrationTimezoneExpiryColumns verifies that a new schema stores expiry
times as TIMESTAMPTZ.
*/
func TestIntegrationTimezoneExpiryColumns(t *testing.T) {
	skipIfShort(t)
	setupTestAuth(t)

	assertExpiryTypes(t, getTestDBPool(t, context.Background()), typeTimestamptz)
}

/* ======================== OTP ======================== */

/*
TestIntegrationTimezoneOTPLifecycle runs the real SendOTP -> VerifyOTP path.
With the old TIMESTAMP column a host west of UTC rejected a code sent a moment
ago, and a host east of UTC kept it valid for hours.
*/
func TestIntegrationTimezoneOTPLifecycle(t *testing.T) {
	skipIfShort(t)
	sender := &captureSender{}
	a := setupTestAuth(t, auth.WithOTP(6, 5*time.Minute), auth.WithEmailSender(sender))
	db := getTestDBPool(t, context.Background())

	err := a.SendOTP(context.Background(), "tz-otp@example.com")
	if err != nil {
		t.Fatalf("failed to send OTP: %v", err)
	}
	assertStoredExpiry(t, db, "otps", "email", "tz-otp@example.com", 5*time.Minute)

	exists, err := a.OTPExists(context.Background(), "tz-otp@example.com")
	if err != nil || !exists {
		t.Fatalf("expected the new OTP to exist, got exists=%v err=%v", exists, err)
	}

	err = a.VerifyOTP(context.Background(), "tz-otp@example.com", sender.lastCode(t))
	if err != nil {
		t.Errorf("expected the new OTP to verify, got: %v", err)
	}
}

/*
TestIntegrationTimezoneOTPExpiry verifies both sides of the expiry line, with
the expiry written by the Go client and by the database's own clock.
*/
func TestIntegrationTimezoneOTPExpiry(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	db := getTestDBPool(t, context.Background())

	cases := []struct {
		email   string
		expr    string
		args    []any
		wantErr error
	}{
		{"go-live@example.com", "$3", []any{time.Now().Add(5 * time.Minute)}, nil},
		{"go-dead@example.com", "$3", []any{time.Now().Add(-5 * time.Minute)}, auth.ErrOTPExpired},
		{"db-live@example.com", "NOW() + INTERVAL '5 minutes'", nil, nil},
		{"db-dead@example.com", "NOW() - INTERVAL '5 minutes'", nil, auth.ErrOTPExpired},
	}
	for _, tc := range cases {
		insertOTPRaw(t, db, tc.email, tc.expr, tc.args...)
	}

	active, err := a.ListActiveOTPs(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(active) != 2 {
		t.Errorf("expected 2 active OTPs, got: %v", active)
	}
	for _, email := range active {
		if email != "go-live@example.com" && email != "db-live@example.com" {
			t.Errorf("expired OTP listed as active: %s", email)
		}
	}

	for _, tc := range cases {
		err := a.VerifyOTP(context.Background(), tc.email, "123456")
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: expected %v, got: %v", tc.email, tc.wantErr, err)
		}
	}
}

/* ======================== Refresh Token ======================== */

/*
TestIntegrationTimezoneRefreshTokenLifecycle tests:
generate -> validate -> expire -> cleanup, with expired tokens written by both
the Go client and the database.
*/
func TestIntegrationTimezoneRefreshTokenLifecycle(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t, auth.WithRefreshToken(2*time.Hour, 32))
	db := getTestDBPool(t, context.Background())
	_ = a.RegisterUser(context.Background(), "tz-refresh@example.com", "TestP@ssword1!")

	token, err := a.GenerateRefreshToken(context.Background(), "tz-refresh@example.com")
	if err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}
	assertStoredExpiry(t, db, "refresh_tokens", "token", token, 2*time.Hour)

	userID, err := a.ValidateRefreshToken(context.Background(), token)
	if err != nil || userID != "tz-refresh@example.com" {
		t.Fatalf("expected the new token to validate, got user=%q err=%v", userID, err)
	}

	_, err = db.Exec(context.Background(),
		"INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3), ($4, $2, NOW() - INTERVAL '1 hour')",
		"go-expired", "tz-refresh@example.com", time.Now().Add(-1*time.Hour), "db-expired",
	)
	if err != nil {
		t.Fatalf("failed to insert expired tokens: %v", err)
	}
	for _, expired := range []string{"go-expired", "db-expired"} {
		_, err := a.ValidateRefreshToken(context.Background(), expired)
		if !errors.Is(err, auth.ErrRefreshTokenExpired) {
			t.Errorf("expected ErrRefreshTokenExpired for %s, got: %v", expired, err)
		}
	}

	_ = a.CleanupExpiredRefreshTokens(context.Background())

	for _, expired := range []string{"go-expired", "db-expired"} {
		_, err := a.ValidateRefreshToken(context.Background(), expired)
		if !errors.Is(err, auth.ErrRefreshTokenInvalid) {
			t.Errorf("expected ErrRefreshTokenInvalid after cleanup for %s, got: %v", expired, err)
		}
	}
	_, err = a.ValidateRefreshToken(context.Background(), token)
	if err != nil {
		t.Errorf("cleanup should keep the live token, got: %v", err)
	}
}

/* ======================== Storage ======================== */

/*
TestIntegrationTimezoneStorageRoundTrip hands the storage layer times in
non-UTC zones, as a caller in those zones would, and expects the same instant
back in UTC. It also covers the NOW() comparisons in ListActiveOTPs and the
cleanup queries.
*/
func TestIntegrationTimezoneStorageRoundTrip(t *testing.T) {
	skipIfShort(t)

	for _, zone := range nonUTCZones {
		t.Run(zone, func(t *testing.T) {
			loc := loadZone(t, zone)
			s := newTestStorage(t)

			/* Postgres keeps microseconds, so truncate before comparing */
			live := time.Now().Add(10 * time.Minute).Truncate(time.Microsecond).In(loc)
			dead := time.Now().Add(-10 * time.Minute).Truncate(time.Microsecond).In(loc)

			_ = s.InsertOTP(context.Background(), "live@example.com", "hash", live)
			_ = s.InsertOTP(context.Background(), "dead@example.com", "hash", dead)

			_, got, err := s.GetOTP(context.Background(), "live@example.com")
			if err != nil {
				t.Fatalf("failed to get OTP: %v", err)
			}
			assertUTCInstant(t, "GetOTP", got, live)

			emails, err := s.ListActiveOTPs(context.Background(), 10, 0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(emails) != 1 || emails[0] != "live@example.com" {
				t.Errorf("expected only live@example.com to be active, got: %v", emails)
			}

			_ = s.CleanupExpiredOTPs(context.Background())

			_, _, err = s.GetOTP(context.Background(), "dead@example.com")
			if !errors.Is(err, auth.ErrOTPNotFound) {
				t.Errorf("expected ErrOTPNotFound after cleanup, got: %v", err)
			}
			_, _, err = s.GetOTP(context.Background(), "live@example.com")
			if err != nil {
				t.Errorf("cleanup should keep the live OTP, got: %v", err)
			}

			_ = s.InsertUser(context.Background(), "tz-user@example.com", "hash", "salt")
			_ = s.InsertRefreshToken(context.Background(), "live-token", "tz-user@example.com", live)
			_ = s.InsertRefreshToken(context.Background(), "dead-token", "tz-user@example.com", dead)

			_, gotRT, _, err := s.GetRefreshToken(context.Background(), "live-token")
			if err != nil {
				t.Fatalf("failed to get refresh token: %v", err)
			}
			assertUTCInstant(t, "GetRefreshToken", gotRT, live)

			_ = s.CleanupExpiredRefreshTokens(context.Background())

			_, _, _, err = s.GetRefreshToken(context.Background(), "dead-token")
			if err == nil {
				t.Error("expected the expired refresh token to be cleaned up")
			}
			_, _, _, err = s.GetRefreshToken(context.Background(), "live-token")
			if err != nil {
				t.Errorf("cleanup should keep the live refresh token, got: %v", err)
			}
		})
	}
}

/* ======================== Migration ======================== */

/* legacySchema is the schema written by versions that used a plain TIMESTAMP, with one row per table. */
const legacySchema = `
	CREATE TABLE users (user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL, salt TEXT NOT NULL);
	CREATE TABLE otps (email TEXT PRIMARY KEY, code TEXT NOT NULL, expires_at TIMESTAMP NOT NULL);
	CREATE TABLE refresh_tokens (
		token TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
		expires_at TIMESTAMP NOT NULL,
		revoked BOOLEAN NOT NULL DEFAULT false,
		created_at TIMESTAMP NOT NULL DEFAULT NOW()
	);
	INSERT INTO users VALUES ('legacy@example.com', 'h', 's');
	INSERT INTO otps VALUES ('legacy@example.com', 'c', '2030-01-01 12:00:00');
	INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ('legacy-token', 'legacy@example.com', '2030-01-01 12:00:00');
`

/* legacyWallClock is the reading 2030-01-01 12:00 of the zone the legacy rows were written in. */
func legacyWallClock(loc *time.Location) time.Time {
	return time.Date(2030, 1, 1, 12, 0, 0, 0, loc)
}

/* newLegacyDB drops every table and recreates the legacy schema. */
func newLegacyDB(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	preCleanDB(t, ctx)
	db := getTestDBPool(t, ctx)
	if _, err := db.Exec(ctx, legacySchema); err != nil {
		t.Fatalf("failed to create legacy schema: %v", err)
	}
	return db
}

/* assertLegacyRows checks the instant held by the legacy row of each table. */
func assertLegacyRows(t *testing.T, db *pgxpool.Pool, want time.Time) {
	t.Helper()
	for _, query := range []string{
		"SELECT EXTRACT(EPOCH FROM expires_at)::bigint FROM otps WHERE email = 'legacy@example.com'",
		"SELECT EXTRACT(EPOCH FROM expires_at)::bigint FROM refresh_tokens WHERE token = 'legacy-token'",
	} {
		var got int64
		if err := db.QueryRow(context.Background(), query).Scan(&got); err != nil {
			t.Fatalf("failed to read legacy row: %v", err)
		}
		if got != want.Unix() {
			t.Errorf("expected epoch %d (%v), got: %d", want.Unix(), want.UTC(), got)
		}
	}
}

/*
runMigration executes the migration script on one dedicated connection, so that
auth.legacy_tz applies to it the same way PGOPTIONS does for psql.
*/
func runMigration(ctx context.Context, db *pgxpool.Pool, legacyZone string) error {
	script, err := os.ReadFile(filepath.Join("..", "migrations", "001_expiry_timestamptz.sql"))
	if err != nil {
		return err
	}
	conn, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if legacyZone != "" {
		if _, err := conn.Exec(ctx, "SELECT set_config('auth.legacy_tz', $1, false)", legacyZone); err != nil {
			return err
		}
	}
	if _, err := conn.Exec(ctx, string(script)); err != nil {
		/* The script's BEGIN left the session in an aborted transaction */
		_, _ = conn.Exec(ctx, "ROLLBACK")
		return err
	}
	return nil
}

/*
TestIntegrationTimezoneMigration runs migrations/001_expiry_timestamptz.sql on a
schema written by the old code and verifies that the stored instants survive.
*/
func TestIntegrationTimezoneMigration(t *testing.T) {
	skipIfShort(t)

	t.Run("declared legacy zone", func(t *testing.T) {
		kolkata := loadZone(t, "Asia/Kolkata")
		db := newLegacyDB(t, context.Background())
		s := openStorage(t, context.Background())

		err := s.CheckTables(context.Background())
		if !errors.Is(err, auth.ErrSchemaOutdated) {
			t.Fatalf("expected ErrSchemaOutdated for the old schema, got: %v", err)
		}

		err = runMigration(context.Background(), db, "Asia/Kolkata")
		if err != nil {
			t.Fatalf("migration failed: %v", err)
		}
		assertExpiryTypes(t, db, typeTimestamptz)
		assertLegacyRows(t, db, legacyWallClock(kolkata))

		/* Running it twice must change nothing */
		err = runMigration(context.Background(), db, "Asia/Kolkata")
		if err != nil {
			t.Fatalf("second migration run failed: %v", err)
		}
		assertLegacyRows(t, db, legacyWallClock(kolkata))

		err = s.CheckTables(context.Background())
		if err != nil {
			t.Fatalf("expected the migrated schema to be accepted, got: %v", err)
		}
		_, got, err := s.GetOTP(context.Background(), "legacy@example.com")
		if err != nil {
			t.Fatalf("failed to get migrated OTP: %v", err)
		}
		assertUTCInstant(t, "GetOTP", got, legacyWallClock(kolkata))
	})

	t.Run("default legacy zone is UTC", func(t *testing.T) {
		db := newLegacyDB(t, context.Background())

		err := runMigration(context.Background(), db, "")
		if err != nil {
			t.Fatalf("migration failed: %v", err)
		}
		assertExpiryTypes(t, db, typeTimestamptz)
		assertLegacyRows(t, db, legacyWallClock(time.UTC))
	})

	t.Run("unknown legacy zone changes nothing", func(t *testing.T) {
		db := newLegacyDB(t, context.Background())

		err := runMigration(context.Background(), db, "Not/AZone")
		if err == nil {
			t.Fatal("expected an error for an unknown zone")
		}
		assertExpiryTypes(t, db, typeTimestamp)
		assertLegacyRows(t, db, legacyWallClock(time.UTC))
	})
}
