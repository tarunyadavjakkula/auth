package tests

import (
	"context"
	"net/url"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
	"github.com/redis/go-redis/v9"
)


func TestOAuthLoginURL_StateAndPKCE(t *testing.T){

	if !isRedisAvailable(t) {
		t.Skip("Redis is not available, skipping oauth test")
	}

	ctx := context.Background()
	rClient := redis.NewClient(&redis.Options{
		Addr:testRedisHost,
	})
	defer rClient.Close()

	a, err := auth.New(
		ctx,
		auth.WithOAuth("client_id", "client_secret", "http://localhost/callback"),
		auth.WithRedis(rClient),
	)
	if err != nil {
		t.Fatalf("failed to init auth: %v",err)
	}
	defer a.Close()

	loginURL, err := a.GetGoogleLoginURL(ctx)
	if err != nil {
		t.Fatalf("unexpected error from GetGoogleLoginURL: %v", err)
	}

	parsed, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("failed to parse login URL: %v", err)
	}

	q := parsed.Query()

	/* Verify state parameter is present and is not empty */
	state := q.Get("state")
	if state == "" {
		t.Fatalf("expected non-empty state query parameter in login URL")
	}

	/* Verify PKCE parameters are present */
	if q.Get("code_challenge") == "" {
		t.Fatalf("expected code_challenge parameter in login URL")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("expected code_challenge_method to be S256, got %s", q.Get("code_challenge_method"))
	}

	/* Verify state exists in Redis and contains the verifier */
	verifier, err := rClient.Get(ctx, "oauth:state:"+state).Result()
	if err != nil {
		t.Fatalf("expected state in redis: %v", err)
	}
	if verifier == "" {
		t.Fatalf("expected non-empty code_verifier stored in redis")
	}
}

func TestOAuthCallback_InvalidStateAndReplay(t *testing.T){

	if !isRedisAvailable(t) {
		t.Skip("Redis is not available, skipping oauth test")
	}

	ctx := context.Background()
	rClient := redis.NewClient(&redis.Options{
		Addr:testRedisHost,
	})
	defer rClient.Close()

	a, err := auth.New(
		ctx,
		auth.WithOAuth("client_id", "client_secret", "http://localhost/callback"), 
		auth.WithRedis(rClient),	
	)
	if err != nil {
		t.Fatalf("failed to init auth: %v", err)
	}
	defer a.Close()
	
	/* Missing or empty inputs */
	if _, err := a.HandleGoogleCallback(ctx, "", "some_state"); err != auth.ErrEmptyInput {
		t.Fatalf("expected ErrEmptyInput for empty code, got: %v", err)
	}
	if _, err := a.HandleGoogleCallback(ctx, "some_code", ""); err != auth.ErrEmptyInput {
		t.Fatalf("expected ErrEmptyInput for empty state, got: %v", err)
	}

	/* Non-existent or Forged state should return ErrOAuthInvalidState */
	_, err = a.HandleGoogleCallback(ctx, "some_code", "forged_state")
	if err != auth.ErrOAuthInvalidState {
		t.Fatalf("expected ErrOAuthInvalidState for forged state got: %v", err)
	}

	/*
	Test Replay Protection:
	state can only be consumed once.
	*/
	testState := "test_replay_state_12345"
	testVerifier := "test_code_verifier_12345"
	err = rClient.Set(ctx, "oauth:state:"+testState, testVerifier, 1*time.Minute).Err()
	if err != nil {
		t.Fatalf("failed to seed state in redis: %v", err)
	}

	_, _ = a.HandleGoogleCallback(ctx, "invalid_code", testState)

	_, err = a.HandleGoogleCallback(ctx, "invalid_code", testState)
	if err != auth.ErrOAuthInvalidState {
		t.Fatalf("expected replay callback to return ErrOAuthInvalidState, got: %v", err)
	}

}