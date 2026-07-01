package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"sessionproxy/internal/domain"
	"sessionproxy/internal/domain/mocks"
)

func testJWTKey() []byte { return []byte("unit-test-jwt-secret-32-bytes!!") }

// TestAuthService_LoginRoundTrip exercises the whole password path with a
// mocked UserRepository: Register hashes the password (never stores it in
// the clear), and Login only succeeds against the correct password, then
// issues a JWT that VerifyJWT can decode back to the same user_id.
func TestAuthService_LoginRoundTrip(t *testing.T) {
	ctrl := gomock.NewController(t)
	users := mocks.NewMockUserRepository(ctrl)
	apiKeys := mocks.NewMockAPIKeyRepository(ctrl)
	auth := NewAuthService(users, apiKeys, testJWTKey(), time.Hour)

	userID := uuid.New()
	var storedHash string

	users.EXPECT().GetByEmail(gomock.Any(), "owner@example.com").Return(domain.User{}, errors.New("not found")).Times(1)
	users.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u domain.User) (domain.User, error) {
		storedHash = u.PasswordHash
		require.NotEqual(t, "correct-password", storedHash, "password must be hashed before it reaches the repository")
		return domain.User{ID: userID, Email: u.Email, PasswordHash: u.PasswordHash}, nil
	})

	_, err := auth.Register(context.Background(), "owner@example.com", "correct-password", "")
	require.NoError(t, err)

	users.EXPECT().GetByEmail(gomock.Any(), "owner@example.com").Return(domain.User{ID: userID, Email: "owner@example.com", PasswordHash: storedHash}, nil).Times(2)

	_, _, err = auth.Login(context.Background(), "owner@example.com", "wrong-password")
	require.ErrorIs(t, err, ErrInvalidCredentials)

	token, user, err := auth.Login(context.Background(), "owner@example.com", "correct-password")
	require.NoError(t, err)
	require.Equal(t, userID, user.ID)

	verifiedID, err := auth.VerifyJWT(token)
	require.NoError(t, err)
	require.Equal(t, userID, verifiedID)
}

// TestAuthService_APIKeyRoundTrip checks that the raw key returned by
// CreateAPIKey verifies successfully, a wrong key does not, and a revoked
// key is rejected even though its hash still matches.
func TestAuthService_APIKeyRoundTrip(t *testing.T) {
	ctrl := gomock.NewController(t)
	users := mocks.NewMockUserRepository(ctrl)
	apiKeys := mocks.NewMockAPIKeyRepository(ctrl)
	auth := NewAuthService(users, apiKeys, testJWTKey(), time.Hour)

	userID := uuid.New()
	var storedHash string
	apiKeys.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, k domain.APIKey) (domain.APIKey, error) {
		storedHash = k.KeyHash
		return domain.APIKey{ID: uuid.New(), UserID: k.UserID, KeyHash: k.KeyHash}, nil
	})

	rawKey, _, err := auth.CreateAPIKey(context.Background(), userID, "cli", nil, nil)
	require.NoError(t, err)
	require.Contains(t, rawKey, "spk_")

	apiKeys.EXPECT().GetByHash(gomock.Any(), storedHash).Return(domain.APIKey{UserID: userID, KeyHash: storedHash}, nil)
	got, err := auth.VerifyAPIKey(context.Background(), rawKey)
	require.NoError(t, err)
	require.Equal(t, userID, got)

	apiKeys.EXPECT().GetByHash(gomock.Any(), gomock.Any()).Return(domain.APIKey{}, errors.New("not found"))
	_, err = auth.VerifyAPIKey(context.Background(), "spk_totally-wrong-key")
	require.ErrorIs(t, err, ErrInvalidCredentials)

	revokedAt := time.Now()
	apiKeys.EXPECT().GetByHash(gomock.Any(), storedHash).Return(domain.APIKey{UserID: userID, KeyHash: storedHash, RevokedAt: &revokedAt}, nil)
	_, err = auth.VerifyAPIKey(context.Background(), rawKey)
	require.ErrorIs(t, err, ErrAPIKeyRevoked)
}
