package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

/*
RefreshToken represents a stored refresh token in the database.
Each refresh token is tied to a user and has an expiration time.
Tokens can be individually revoked without affecting other tokens.
*/
type RefreshToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

/*
RefreshTokenConfig holds the configuration for refresh token behaviour.
Expiry is how long a refresh token remains valid (e.g. 7 days).
TokenLength is the byte length of the random token (default 32 = 64 hex chars).
*/
type RefreshTokenConfig struct {
	Expiry      time.Duration
	TokenLength int
}

/*
GenerateRefreshToken creates a new opaque refresh token for the given user,
stores it in the database, and returns the token string.
The caller should return this to the client alongside the JWT access token.
*/
func (a *Auth) GenerateRefreshToken(ctx context.Context, userID string) (string, error) {
	if userID == "" {
		return "", ErrEmptyInput
	}
	if a.storage == nil {
		return "", ErrDatabaseUnavailable
	}
	if a.refreshTokenExpiry <= 0 {
		return "", fmt.Errorf("%w: refresh token expiry not configured, use WithRefreshToken()", ErrNotInitialized)
	}

	/* Generate a cryptographically secure random token */
	tokenBytes := make([]byte, a.refreshTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	/* Expiry is kept in UTC so it never depends on the host's time zone */
	expiresAt := time.Now().UTC().Add(a.refreshTokenExpiry)

	err := a.storage.InsertRefreshToken(ctx, token, userID, expiresAt)
	if err != nil {
		return "", fmt.Errorf("%w: failed to store refresh token: %v", ErrDatabaseUnavailable, err)
	}

	if a.redisClient != nil {
		pipe := a.redisClient.Pipeline()
		pipe.Set(ctx, "refresh:"+token, userID, a.refreshTokenExpiry)
		pipe.SAdd(ctx, "user_tokens:"+userID, token)
		pipe.Expire(ctx, "user_tokens:"+userID, a.refreshTokenExpiry)
		_, _ = pipe.Exec(ctx)
	}

	return token, nil
}

/*
ValidateRefreshToken checks if a refresh token is valid (exists, not revoked, not expired).
If valid, it returns the associated user ID.
*/
func (a *Auth) ValidateRefreshToken(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", ErrEmptyInput
	}
	if a.storage == nil {
		return "", ErrDatabaseUnavailable
	}

	if a.redisClient != nil {
		cachedUser, err := a.redisClient.Get(ctx, "refresh:"+token).Result()
		if err == nil {
			return cachedUser, nil
		}
	}

	ch := a.requestGroup.DoChan("validate_refresh:"+token, func() (interface{}, error) {
		/* Use a detached context so no single caller's cancellation aborts the shared DB flight. */
		dbCtx := context.WithoutCancel(ctx)
		userID, expiresAt, revoked, err := a.storage.GetRefreshToken(dbCtx, token)
		if err != nil {
			return "", ErrRefreshTokenInvalid
		}

		if revoked {
			return "", ErrRefreshTokenRevoked
		}

		if time.Now().After(expiresAt) {
			return "", ErrRefreshTokenExpired
		}

		if a.redisClient != nil {
			ttl := time.Until(expiresAt)
			if ttl > 0 {
				pipe := a.redisClient.Pipeline()
				pipe.Set(dbCtx, "refresh:"+token, userID, ttl)
				pipe.SAdd(dbCtx, "user_tokens:"+userID, token)
				pipe.Expire(dbCtx, "user_tokens:"+userID, a.refreshTokenExpiry)
				_, _ = pipe.Exec(dbCtx)
			}
		}

		return userID, nil
	})

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return "", res.Err
		}
		return res.Val.(string), nil
	}
}

/*
RotateRefreshToken validates the old refresh token, revokes it,
and issues a new one. This implements refresh token rotation, which
limits the damage if a token is leaked.

Returns the new token and the associated user ID.
*/
func (a *Auth) RotateRefreshToken(ctx context.Context, oldToken string) (newToken string, userID string, err error) {
	/* Validate the existing token first */
	userID, err = a.ValidateRefreshToken(ctx, oldToken)
	if err != nil {
		return "", "", err
	}

	/* Revoke the old token */
	if err := a.RevokeRefreshToken(ctx, oldToken); err != nil {
		return "", "", fmt.Errorf("failed to revoke old token: %w", err)
	}

	/* Issue a new one */
	newToken, err = a.GenerateRefreshToken(ctx, userID)
	if err != nil {
		return "", "", err
	}

	return newToken, userID, nil
}

/*
RevokeRefreshToken marks a specific refresh token as revoked.
The token will no longer pass validation.
*/
func (a *Auth) RevokeRefreshToken(ctx context.Context, token string) error {
	if token == "" {
		return ErrEmptyInput
	}
	if a.storage == nil {
		return ErrDatabaseUnavailable
	}

	if err := a.storage.RevokeRefreshToken(ctx, token); err != nil {
		if err == ErrRefreshTokenInvalid {
			return ErrRefreshTokenInvalid
		}
		return fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}

	if a.redisClient != nil {
		a.redisClient.Del(ctx, "refresh:"+token)
	}

	return nil
}

/*
RevokeAllUserRefreshTokens revokes every refresh token for a given user.
Use this when a user changes their password or you detect suspicious activity.
*/
func (a *Auth) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrEmptyInput
	}
	if a.storage == nil {
		return ErrDatabaseUnavailable
	}

	/* DB is the source of truth: revoke there first. */
	if err := a.storage.RevokeAllUserRefreshTokens(ctx, userID); err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}

	/* Only invalidate the cache after a successful DB write. */
	if a.redisClient != nil {
		tokens, err := a.redisClient.SMembers(ctx, "user_tokens:"+userID).Result()
		if err == nil && len(tokens) > 0 {
			keys := make([]string, len(tokens))
			for i, t := range tokens {
				keys[i] = "refresh:" + t
			}
			pipe := a.redisClient.Pipeline()
			pipe.Del(ctx, keys...)
			pipe.Del(ctx, "user_tokens:"+userID)
			_, _ = pipe.Exec(ctx)
		}
	}

	return nil
}

/*
CleanupExpiredRefreshTokens removes expired refresh tokens from the database.
This is called periodically by the background cleanup routine.
*/
func (a *Auth) CleanupExpiredRefreshTokens(ctx context.Context) error {
	if a.storage == nil {
		return ErrDatabaseUnavailable
	}

	if err := a.storage.CleanupExpiredRefreshTokens(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}

	return nil
}
