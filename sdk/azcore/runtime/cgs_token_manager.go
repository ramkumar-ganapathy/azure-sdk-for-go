package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"errors"
)

var (
	tokenCache     string
	tokenExpiry    time.Time
	tokenLock      sync.Mutex
	deltaBufferSec = 30
	cmdPath        = "/home/ramgana/tuscany/token_mgr/bin/Debug/net9.0/tm"
    cgs_tm_once	   sync.Once
)

// JWT claims structure (only 'exp' used here)
type jwtClaims struct {
	Exp int64 `json:"exp"`
}

type TokenResponse struct {
	Status  string `json:"status"`
	Token   string `json:"token"`
	Message string `json:"message"`
}

func parseTokenExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}, ErrInvalidToken
	}
	claimsPart := parts[1]

	// Pad base64 string
	padded := claimsPart + strings.Repeat("=", (4-len(claimsPart)%4)%4)
	data, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return time.Time{}, err
	}

	var claims jwtClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		return time.Time{}, err
	}

	return time.Unix(claims.Exp, 0), nil
}

func fetchToken() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, cmdPath).Output()
	if err != nil {
		return "", err
	}

	var res TokenResponse
	if err := json.Unmarshal(output, &res); err != nil {
		return "", err
	}

	if res.Status != "Ok" {
		log.Println("Token Fetch failed: ", res.Message)
		return "", errors.New("token fetch failed")
	}

	expiry, err := parseTokenExpiry(res.Token)
	if err != nil {
		return "", err
	}

	log.Println("Response: ", res, "Expiry: ", expiry, "Until: ", time.Until(expiry))

	tokenExpiry = expiry
	return res.Token, nil
}

func CgsGetAuthToken() (string, error) {
    cgs_tm_once.Do(func() {
		tu := os.Getenv("CGS_PROXY_TOKEN_UTILITY")
		log.Printf("CGSTMOnce: Overriding TokenUtility: %s to %s\n", cmdPath, tu)
		cmdPath = tu
	})

	tokenLock.Lock()
	defer tokenLock.Unlock()

	if tokenCache != "" && time.Until(tokenExpiry) > time.Duration(deltaBufferSec)*time.Second {
		return tokenCache, nil
	}

	token, err := fetchToken()
	if err != nil {
		return "", err
	}

	tokenCache = token
	return token, nil
}

var ErrInvalidToken = &CustomError{"Invalid token format"}

type CustomError struct{ Msg string }

func (e *CustomError) Error() string { return e.Msg }

