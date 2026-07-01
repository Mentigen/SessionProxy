// Package service holds the application's business logic: everything the
// database schema deliberately does not enforce declaratively (see
// README.md section 4, "Примечание по бизнес-правилам 5 и 6"). Handlers in
// internal/transport are thin; the rules live here so they can be unit
// tested against gomock fakes of the domain repository interfaces.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"sessionproxy/internal/domain"
)

var (
	ErrInvalidCredentials = errors.New("service: invalid email or password")
	ErrEmailTaken         = errors.New("service: email already registered")
	ErrAPIKeyRevoked      = errors.New("service: api key revoked or expired")
)

// AuthService owns everything about proving who an owner is: password
// login issuing a JWT, and long-lived API keys for CLI/browser-extension
// clients (api_keys exists precisely for that, per README group 1).
type AuthService struct {
	users   domain.UserRepository
	apiKeys domain.APIKeyRepository
	jwtKey  []byte
	jwtTTL  time.Duration
}

func NewAuthService(users domain.UserRepository, apiKeys domain.APIKeyRepository, jwtKey []byte, jwtTTL time.Duration) *AuthService {
	return &AuthService{users: users, apiKeys: apiKeys, jwtKey: jwtKey, jwtTTL: jwtTTL}
}

func (s *AuthService) Register(ctx context.Context, email, password, displayName string) (domain.User, error) {
	if _, err := s.users.GetByEmail(ctx, email); err == nil {
		return domain.User{}, ErrEmailTaken
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return domain.User{}, fmt.Errorf("service: hash password: %w", err)
	}
	var namePtr *string
	if displayName != "" {
		namePtr = &displayName
	}
	return s.users.Create(ctx, domain.User{Email: email, PasswordHash: string(hash), DisplayName: namePtr})
}

// Login verifies a password and issues a JWT. It deliberately returns the
// same generic error for "no such user" and "wrong password" so the
// endpoint does not leak which emails are registered.
func (s *AuthService) Login(ctx context.Context, email, password string) (token string, user domain.User, err error) {
	user, err = s.users.GetByEmail(ctx, email)
	if err != nil {
		return "", domain.User{}, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return "", domain.User{}, ErrInvalidCredentials
	}
	token, err = s.issueJWT(user.ID)
	return token, user, err
}

func (s *AuthService) issueJWT(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"exp": time.Now().Add(s.jwtTTL).Unix(),
		"iat": time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(s.jwtKey)
}

// VerifyJWT returns the owner user_id embedded in a valid, unexpired token.
func (s *AuthService) VerifyJWT(tokenString string) (uuid.UUID, error) {
	parsed, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("service: unexpected signing method %v", t.Header["alg"])
		}
		return s.jwtKey, nil
	})
	if err != nil || !parsed.Valid {
		return uuid.Nil, fmt.Errorf("service: invalid token: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, fmt.Errorf("service: invalid token claims")
	}
	sub, _ := claims["sub"].(string)
	return uuid.Parse(sub)
}

// CreateAPIKey generates a random key, returns the raw value exactly once
// (the caller must show it to the owner now - it is never recoverable
// again), and stores only its SHA-256 hash, mirroring how password_hash
// never stores a plaintext password.
func (s *AuthService) CreateAPIKey(ctx context.Context, userID uuid.UUID, label string, deviceID *uuid.UUID, expiresAt *time.Time) (rawKey string, key domain.APIKey, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", domain.APIKey{}, fmt.Errorf("service: generate api key: %w", err)
	}
	rawKey = "spk_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := hashAPIKey(rawKey)

	var labelPtr *string
	if label != "" {
		labelPtr = &label
	}
	key, err = s.apiKeys.Create(ctx, domain.APIKey{UserID: userID, DeviceID: deviceID, KeyHash: hash, Label: labelPtr, ExpiresAt: expiresAt})
	if err != nil {
		return "", domain.APIKey{}, err
	}
	return rawKey, key, nil
}

// VerifyAPIKey looks up an API key by the hash of the raw value presented
// in a request (Bearer spk_...), rejecting revoked or expired keys.
func (s *AuthService) VerifyAPIKey(ctx context.Context, rawKey string) (uuid.UUID, error) {
	key, err := s.apiKeys.GetByHash(ctx, hashAPIKey(rawKey))
	if err != nil {
		return uuid.Nil, ErrInvalidCredentials
	}
	if key.RevokedAt != nil {
		return uuid.Nil, ErrAPIKeyRevoked
	}
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return uuid.Nil, ErrAPIKeyRevoked
	}
	return key.UserID, nil
}

func hashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
