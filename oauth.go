package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

type googleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

func generateOAuthStateAndVerifier() (state, codeVerifier, codeChallenge string, err error){
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil{
		return "", "", "", fmt.Errorf("failed to generate oauth state: %w", err)
	}
	state = base64.RawURLEncoding.EncodeToString(stateBytes)

	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil{
		return "", "", "", fmt.Errorf("failed to generate pkce verifier: %w", err)
	} 
	codeVerifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(h[:])

	return state, codeVerifier, codeChallenge, nil
}

/*
GetGoogleLoginURL generates the URL to the Google consent screen.

It generates a random state and PKCE code verifier and challenge (SHA256).
It stores the code verifier in Redis with the state as the key and a TTL of 5 minutes.
Consumer applications do not need to manage or generate state manually.
CSRF protection and replay protection is handled by the library internally.
Returns the URL to the Google consent screen with the state and code challenge.
*/
func (a *Auth) GetGoogleLoginURL(ctx context.Context) (string, error) {
	if a.oauthConfig == nil {
		return "", ErrOAuthNotInitialized
	}
	if a.redisClient == nil {
		return "", ErrRedisUnavailable
	}

	state, codeVerifier, codeChallenge, err := generateOAuthStateAndVerifier()
	if err != nil {
		return "", fmt.Errorf("failed to generate oauth state and verifier: %w", err)
	}
	if state == "" {
		return "", ErrEmptyInput
	}


	err = a.redisClient.Set(ctx, "oauth:state:"+state, codeVerifier, 5*time.Minute).Err()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}

	return a.oauthConfig.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
	
}

/*
HandleGoogleCallback exchanges the auth code for a token, fetches user info,
upserts the user into the database, and returns a generated JWT string.

HandleGoogleCallback validates the returned OAuth state, exchanges the 
authorization code for tokens using the stored PKCE code verifier,
fetches the user profile, and upserts the user into the database.
Returns a generated JWT string.

Rejects the callback if the returned state does not match the value
stored in Redis or if the state has expired.
Enforces single-use replay protection by immediately deleting
the state from Redis after successful retrieval.
Uses PKCE to verify the OAuth response.
*/
func (a *Auth) HandleGoogleCallback(ctx context.Context, code, state string) (string, error) {
	if code == "" || state == "" {
		return "", ErrEmptyInput
	}
	if a.oauthConfig == nil {
		return "", ErrOAuthNotInitialized
	}
	if a.redisClient == nil {
		return "", ErrRedisUnavailable
	}


	stateKey := "oauth:state:" + state
	codeVerifier, err := a.redisClient.Get(ctx, stateKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrOAuthInvalidState
		}
		return "", fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
	}
	
	/*
	Replay Protection:
	Delete the state key after retrieval.
	*/
	err = a.redisClient.Del(ctx, stateKey).Err()
	if err != nil {
		return "", fmt.Errorf("failed to delete state from redis: %w", err)
	}

	token, err := a.oauthConfig.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthExchangeFailed, err)
	}

	


	client := a.oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthProfileFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: status code %d", ErrOAuthProfileFetchFailed, resp.StatusCode)
	}

	var user googleUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthProfileFetchFailed, err)
	}

	if !user.VerifiedEmail {
		return "", fmt.Errorf("oauth email is not verified by provider")
	}

	if err := a.upsertOAuthUser(ctx, user.Email); err != nil {
		return "", err
	}

	jwtStr, err := a.GenerateToken(ctx, user.Email)
	if err != nil {
		return "", fmt.Errorf("failed to generate jwt after oauth login: %w", err)
	}

	return jwtStr, nil
}
