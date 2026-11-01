package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"time"
)

/* Helper: Generates a secure random number based on the configured OTP length */
func (a *Auth) generateOTP() (string, error) {
	/* 1. Validation Guard */
	if a.otpLength < 4 || a.otpLength > 10 {
		return "", fmt.Errorf("%w: length %d (must be between 4 and 10)", ErrInvalidInput, a.otpLength)
	}

	/* 2. Calculate the max value (e.g., 10^6 = 1,000,000)*/
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(a.otpLength)), nil)

	/* 3. Generate secure random number */
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	/* 4. Dynamically pad the string (e.g., 6 digits becomes %06d) */
	return fmt.Sprintf("%0*d", a.otpLength, n), nil
}

/*
computeOTPHash returns the HMAC-SHA256 of code keyed with the Auth pepper.
If no pepper is configured the library still provides non-plaintext storage;
operators are strongly encouraged to configure WithPepper.
*/
func (a *Auth) computeOTPHash(code string) string {
	mac := hmac.New(sha256.New, a.pepper)
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

/*
SendOTP generates an OTP, saves it to the DB (upsert), and emails it.
Usage: auth.SendOTP("user@example.com")
*/
func (a *Auth) SendOTP(ctx context.Context, userEmail string) error {
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return ErrInvalidEmail
	}
	if a.storage == nil {
		return ErrNotInitialized
	}
	if a.emailSender == nil {
		return ErrSMTPNotInitialized
	}

	/* 1. Generate Code */
	code, err := a.generateOTP()
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	/* 2. Set Expiry in UTC (Uses the config field instead of hardcoded value) */
	if a.otpExpiry <= 0 {
		return fmt.Errorf("%w: duration %v", ErrInvalidInput, a.otpExpiry)
	}
	expiry := time.Now().UTC().Add(a.otpExpiry)

	/* 3. Hash the OTP before storage — plaintext codes must never reach the database. */
	hashedCode := a.computeOTPHash(code)

	/* 4. Upsert into DB */
	if err := a.storage.InsertOTP(ctx, userEmail, hashedCode, expiry); err != nil {
		return fmt.Errorf("db error saving OTP: %w", err)
	}

	/* 4. Send Email */
	subject := "Your Verification Code"
	/* Format to '5 minutes' instead of '5m0s' */
	minutes := int(a.otpExpiry.Minutes())
	body := fmt.Sprintf("Your OTP is: %s\n\nValid for %d minutes.", code, minutes)
	err = a.emailSender.SendEmail(ctx, userEmail, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

/*
VerifyOTP checks if the code is correct and not expired.
If valid, it deletes the OTP to prevent reuse.
*/
func (a *Auth) VerifyOTP(ctx context.Context, userEmail, inputCode string) error {
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return ErrInvalidEmail
	}
	if a.storage == nil {
		return ErrDatabaseUnavailable
	}

	/* Get the OTP */
	storedHash, expiry, err := a.storage.GetOTP(ctx, userEmail)
	if err != nil {
		if errors.Is(err, ErrOTPNotFound) {
			return ErrInvalidOTP
		}
		return fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}

	/* Hash the caller-supplied code and compare in constant time to prevent timing oracles. */
	inputHash := a.computeOTPHash(inputCode)
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(inputHash)) != 1 {
		return ErrInvalidOTP
	}
	if time.Now().After(expiry) {
		return ErrOTPExpired
	}

	/* Valid! Delete it. */
	_ = a.storage.DeleteOTP(ctx, userEmail)
	return nil
}

/*
startOTPCleanup is an internal function that runs in the background.
It periodically deletes expired OTPs from the database.
The cleanup cycle is fixed (5 minutes) to ensure consistent performance
regardless of the configured OTP expiration duration.
*/
func (a *Auth) startOTPCleanup(ctx context.Context) {
	/* Fixed 5-minute interval to prevent DB stress */
	ticker := time.NewTicker(5 * time.Minute)

	go func() {
		/* Ensure the ticker stops when we exit to prevent leaks */
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				/* The Timer ticked: Do the work */
				if a.storage != nil {
					_ = a.storage.CleanupExpiredOTPs(ctx)
				}

			case <-ctx.Done():
				/* The Context was cancelled: STOP EVERYTHING */
				/* This returns from the function, killing the goroutine "neatly" */
				return
			}
		}
	}()
}

func (a *Auth) OTPExists(ctx context.Context, userEmail string) (bool, error) {
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return false, ErrInvalidEmail
	}
	if a.storage == nil {
		return false, ErrDatabaseUnavailable
	}

	_, expiry, err := a.storage.GetOTP(ctx, userEmail)
	if err != nil {
		if errors.Is(err, ErrOTPNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}

	if time.Now().After(expiry) {
		return false, nil
	}

	return true, nil
}

func (a *Auth) ListActiveOTPs(ctx context.Context, limit, offset int) ([]string, error) {
	if a.storage == nil {
		return nil, ErrDatabaseUnavailable
	}

	emails, err := a.storage.ListActiveOTPs(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}

	return emails, nil
}
