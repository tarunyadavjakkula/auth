package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

/*
StorageEngine defines all database operations required by the Auth library.
Expiry times (OTPs and refresh tokens) are UTC instants: implementations must
store them and return them in UTC.
*/
type StorageEngine interface {
	CheckTables(ctx context.Context) error

	/* Users */
	InsertUser(ctx context.Context, username, hash, salt string) error
	UpdateUserPassword(ctx context.Context, username, hash, salt string) (int64, error)
	DeleteUser(ctx context.Context, username string) error
	UserExists(ctx context.Context, username string) (bool, error)
	GetUserHashAndSalt(ctx context.Context, username string) (hash string, salt string, err error)
	ListUsers(ctx context.Context, limit, offset int) ([]User, error)
	UpsertOAuthUser(ctx context.Context, email string) error

	/* Spaces */
	InsertSpace(ctx context.Context, name string, authority int) error
	DeleteSpace(ctx context.Context, name string) error

	/* Roles */
	InsertRole(ctx context.Context, role string) error
	DeleteRole(ctx context.Context, role string) error

	/* Permissions */
	InsertPermission(ctx context.Context, username, spaceName, role string) error
	CheckPermissionExists(ctx context.Context, username, spaceName, role string) (bool, error)
	DeletePermission(ctx context.Context, username, spaceName, role string) error

	/* OTP */
	InsertOTP(ctx context.Context, email, code string, expiresAt time.Time) error
	GetOTP(ctx context.Context, email string) (code string, expiresAt time.Time, err error)
	DeleteOTP(ctx context.Context, email string) error
	ListActiveOTPs(ctx context.Context, limit, offset int) ([]string, error)
	CleanupExpiredOTPs(ctx context.Context) error

	/* Refresh Tokens */
	InsertRefreshToken(ctx context.Context, token, userID string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, token string) (userID string, expiresAt time.Time, revoked bool, err error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RevokeAllUserRefreshTokens(ctx context.Context, userID string) error
	CleanupExpiredRefreshTokens(ctx context.Context) error
	Close() error
}

/* PostgresStorage implements the StorageEngine interface using pgxpool. */
type PostgresStorage struct {
	pool *pgxpool.Pool
}

/* NewPostgresStorage creates a new PostgresStorage with an active connection pool. */
func NewPostgresStorage(ctx context.Context, port uint16, dbUser, dbPass, dbName, host string) (*PostgresStorage, error) {
	if dbUser == "" || dbName == "" || host == "" {
		return nil, ErrEmptyInput
	}
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(dbUser, dbPass),
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   dbName,
	}

	cfg, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w\nPlease configure Postgres correctly", err)
	}
	/* Pin every session to UTC so NOW() never depends on the server's time zone */
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w\nPlease configure Postgres correctly", err)
	}

	if err := pool.QueryRow(ctx, "SELECT 1").Scan(new(int)); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	return &PostgresStorage{pool: pool}, nil
}

/* Close closes the database connection pool. */
func (p *PostgresStorage) Close() error {
	if p.pool != nil {
		p.pool.Close()
	}
	return nil
}

/* CheckTables systematically creates all required tables if they do not exist, then verifies the expiry columns. */
func (p *PostgresStorage) CheckTables(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS spaces (
			spaceName TEXT PRIMARY KEY, 
			authority INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS users (
			user_id TEXT PRIMARY KEY, 
			password_hash TEXT NOT NULL, 
			salt TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS roles (
			role TEXT PRIMARY KEY
		);
		CREATE TABLE IF NOT EXISTS permissions (
			user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE, 
			spaceName TEXT NOT NULL REFERENCES spaces(spaceName) ON DELETE CASCADE, 
			role TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE, 
			PRIMARY KEY (user_id, spaceName, role)
		);
		CREATE TABLE IF NOT EXISTS otps (
			email TEXT PRIMARY KEY, 
			code TEXT NOT NULL, 
			expires_at TIMESTAMPTZ NOT NULL
		);
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			token TEXT PRIMARY KEY, 
			user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE, 
			expires_at TIMESTAMPTZ NOT NULL, 
			revoked BOOLEAN NOT NULL DEFAULT false, 
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		);
	`
	_, err := p.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to initialize database schema: %w", err)
	}
	return p.checkExpiryColumns(ctx)
}

/*
checkExpiryColumns returns ErrSchemaOutdated if an expiry column is still a plain TIMESTAMP.
CREATE TABLE IF NOT EXISTS leaves old tables untouched, and their rows hold the host's
local time, so the operator must convert them: run migrations/001_expiry_timestamptz.sql.
*/
func (p *PostgresStorage) checkExpiryColumns(ctx context.Context) error {
	rows, err := p.pool.Query(ctx, `
		SELECT table_name::text, data_type::text
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name IN ('otps', 'refresh_tokens')
		  AND column_name = 'expires_at'`)
	if err != nil {
		return fmt.Errorf("failed to verify database schema: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var table, dataType string
		if err := rows.Scan(&table, &dataType); err != nil {
			return fmt.Errorf("failed to verify database schema: %w", err)
		}
		if dataType != "timestamp with time zone" {
			return fmt.Errorf("%w: %s.expires_at is %q, expected \"timestamp with time zone\"; run migrations/001_expiry_timestamptz.sql", ErrSchemaOutdated, table, dataType)
		}
	}
	return rows.Err()
}

/* Users */

/* InsertUser inserts a new user. */
func (p *PostgresStorage) InsertUser(ctx context.Context, username, hash, salt string) error {
	_, err := p.pool.Exec(ctx, "INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)", username, hash, salt)
	return err
}

/* UpdateUserPassword updates a user's password. */
func (p *PostgresStorage) UpdateUserPassword(ctx context.Context, username, hash, salt string) (int64, error) {
	cmdTag, err := p.pool.Exec(ctx, "UPDATE users SET password_hash = $1, salt = $2 WHERE user_id = $3", hash, salt, username)
	if err != nil {
		return 0, err
	}
	return cmdTag.RowsAffected(), nil
}

/* DeleteUser deletes a user. */
func (p *PostgresStorage) DeleteUser(ctx context.Context, username string) error {
	_, err := p.pool.Exec(ctx, "DELETE FROM users WHERE user_id = $1", username)
	return err
}

/* UserExists checks if a user exists. */
func (p *PostgresStorage) UserExists(ctx context.Context, username string) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)", username).Scan(&exists)
	return exists, err
}

/* GetUserHashAndSalt retrieves the hash and salt for a user. */
func (p *PostgresStorage) GetUserHashAndSalt(ctx context.Context, username string) (string, string, error) {
	var storedHash, storedSalt string
	err := p.pool.QueryRow(ctx, "SELECT password_hash, salt FROM users WHERE user_id = $1", username).Scan(&storedHash, &storedSalt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", "", ErrUserNotFound
		}
		return "", "", err
	}
	return storedHash, storedSalt, nil
}

/* ListUsers retrieves a list of users. */
func (p *PostgresStorage) ListUsers(ctx context.Context, limit, offset int) ([]User, error) {
	rows, err := p.pool.Query(ctx, "SELECT user_id FROM users LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.UserID); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

/* UpsertOAuthUser inserts an OAuth user. */
func (p *PostgresStorage) UpsertOAuthUser(ctx context.Context, email string) error {
	_, err := p.pool.Exec(ctx, "INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO NOTHING", email, OAuthManagedHash, OAuthManagedSalt)
	return err
}

/* Spaces */

/* InsertSpace creates a new space. */
func (p *PostgresStorage) InsertSpace(ctx context.Context, name string, authority int) error {
	_, err := p.pool.Exec(ctx, "INSERT INTO spaces (spaceName, authority) VALUES ($1, $2)", name, authority)
	return err
}

/* DeleteSpace deletes a space. */
func (p *PostgresStorage) DeleteSpace(ctx context.Context, name string) error {
	_, err := p.pool.Exec(ctx, "DELETE FROM spaces WHERE spaceName = $1", name)
	return err
}

/* Roles */

/* InsertRole creates a new role. */
func (p *PostgresStorage) InsertRole(ctx context.Context, role string) error {
	_, err := p.pool.Exec(ctx, "INSERT INTO roles (role) VALUES ($1)", role)
	return err
}

/* DeleteRole deletes a role. */
func (p *PostgresStorage) DeleteRole(ctx context.Context, role string) error {
	_, err := p.pool.Exec(ctx, "DELETE FROM roles WHERE role = $1", role)
	return err
}

/* Permissions */

/* InsertPermission grants a role in a space. */
func (p *PostgresStorage) InsertPermission(ctx context.Context, username, spaceName, role string) error {
	_, err := p.pool.Exec(ctx, "INSERT INTO permissions (user_id, spaceName, role) VALUES ($1, $2, $3)", username, spaceName, role)
	return err
}

/* CheckPermissionExists checks if a specific permission exists. */
func (p *PostgresStorage) CheckPermissionExists(ctx context.Context, username, spaceName, role string) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM permissions WHERE user_id = $1 AND spaceName = $2 AND role = $3)", username, spaceName, role).Scan(&exists)
	return exists, err
}

/* DeletePermission removes a role in a space. */
func (p *PostgresStorage) DeletePermission(ctx context.Context, username, spaceName, role string) error {
	_, err := p.pool.Exec(ctx, "DELETE FROM permissions WHERE user_id = $1 AND spaceName = $2 AND role = $3", username, spaceName, role)
	return err
}

/* OTP */

/* InsertOTP inserts or updates an OTP. The expiry is stored in UTC. */
func (p *PostgresStorage) InsertOTP(ctx context.Context, email, code string, expiresAt time.Time) error {
	_, err := p.pool.Exec(ctx, "INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET code = EXCLUDED.code, expires_at = EXCLUDED.expires_at", email, code, expiresAt.UTC())
	return err
}

/* GetOTP retrieves an OTP. The expiry is returned in UTC. */
func (p *PostgresStorage) GetOTP(ctx context.Context, email string) (string, time.Time, error) {
	var code string
	var expiresAt time.Time
	err := p.pool.QueryRow(ctx, "SELECT code, expires_at FROM otps WHERE email = $1", email).Scan(&code, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", time.Time{}, ErrOTPNotFound
		}
		return "", time.Time{}, err
	}
	return code, expiresAt.UTC(), nil
}

/* DeleteOTP deletes an OTP. */
func (p *PostgresStorage) DeleteOTP(ctx context.Context, email string) error {
	_, err := p.pool.Exec(ctx, "DELETE FROM otps WHERE email = $1", email)
	return err
}

/* ListActiveOTPs returns a list of unexpired OTPs. */
func (p *PostgresStorage) ListActiveOTPs(ctx context.Context, limit, offset int) ([]string, error) {
	rows, err := p.pool.Query(ctx, "SELECT email FROM otps WHERE expires_at > NOW() LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		emails = append(emails, email)
	}
	return emails, rows.Err()
}

/* CleanupExpiredOTPs deletes all expired OTPs. */
func (p *PostgresStorage) CleanupExpiredOTPs(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, "DELETE FROM otps WHERE expires_at < NOW()")
	return err
}

/* Refresh Tokens */

/* InsertRefreshToken inserts a new refresh token. The expiry is stored in UTC. */
func (p *PostgresStorage) InsertRefreshToken(ctx context.Context, token, userID string, expiresAt time.Time) error {
	_, err := p.pool.Exec(ctx, "INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)", token, userID, expiresAt.UTC())
	return err
}

/* GetRefreshToken retrieves a refresh token. The expiry is returned in UTC. */
func (p *PostgresStorage) GetRefreshToken(ctx context.Context, token string) (string, time.Time, bool, error) {
	var userID string
	var expiresAt time.Time
	var revoked bool
	err := p.pool.QueryRow(ctx, "SELECT user_id, expires_at, revoked FROM refresh_tokens WHERE token = $1", token).Scan(&userID, &expiresAt, &revoked)
	return userID, expiresAt.UTC(), revoked, err
}

/* RevokeRefreshToken revokes a refresh token. */
func (p *PostgresStorage) RevokeRefreshToken(ctx context.Context, token string) error {
	cmdTag, err := p.pool.Exec(ctx, "UPDATE refresh_tokens SET revoked = true WHERE token = $1", token)
	if err != nil {
		return err
	}
	if cmdTag.RowsAffected() == 0 {
		return ErrRefreshTokenInvalid
	}
	return nil
}

/* RevokeAllUserRefreshTokens revokes all refresh tokens for a user. */
func (p *PostgresStorage) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	_, err := p.pool.Exec(ctx, "UPDATE refresh_tokens SET revoked = true WHERE user_id = $1", userID)
	return err
}

/* CleanupExpiredRefreshTokens deletes expired refresh tokens. */
func (p *PostgresStorage) CleanupExpiredRefreshTokens(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, "DELETE FROM refresh_tokens WHERE expires_at < NOW()")
	return err
}
