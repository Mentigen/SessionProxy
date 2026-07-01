package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sessionproxy/internal/service"
	apphttp "sessionproxy/internal/transport/http"
)

func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	require.NoError(t, err)
	return id
}

// newControlPlane wires a full apphttp.Server over the same repos setupEnv
// already builds, so this test exercises the real chi router, real
// AuthService JWT issuing, and real ownership middleware - not mocks.
func newControlPlane(env testEnv) *apphttp.Server {
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	auth := service.NewAuthService(env.repos.Users, env.repos.APIKeys, []byte("test-jwt-secret-32-bytes-minimum"), time.Hour)
	sessionImport := service.NewSessionImportService(env.repos.TargetSites, env.repos.OriginalSessions, env.repos.SessionCookies, env.repos.SessionTokens, env.cipher)
	links := service.NewLinkService(env.repos.OriginalSessions, env.repos.SharedLinks, env.repos.AccessPolicies, env.repos.Blacklist, env.repos.LinkTerminations)

	return &apphttp.Server{
		Logger:           logger,
		Auth:             auth,
		SessionImport:    sessionImport,
		Links:            links,
		Users:            env.repos.Users,
		Devices:          env.repos.Devices,
		APIKeys:          env.repos.APIKeys,
		TargetSites:      env.repos.TargetSites,
		OriginalSessions: env.repos.OriginalSessions,
		SharedLinks:      env.repos.SharedLinks,
		AccessPolicies:   env.repos.AccessPolicies,
		Blacklist:        env.repos.Blacklist,
		Guests:           env.repos.Guests,
		GuestSessions:    env.repos.GuestSessions,
		ProxyAccessLogs:  env.repos.ProxyAccessLogs,
		LinkTerminations: env.repos.LinkTerminations,
		SecurityEvents:   env.repos.SecurityEvents,
		Stats:            env.repos.Stats,
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func doJSON(t *testing.T, handler http.Handler, method, path, token string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec, out
}

// TestControlPlane_FullOwnerFlow walks the whole owner-facing path a real
// user would take: register, log in, import a session, create a link,
// confirm it is listed, then terminate it - checking every step lands the
// expected row (or status transition) in Postgres, not just a 2xx.
func TestControlPlane_FullOwnerFlow(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)
	handler := newControlPlane(env).Routes()

	_, _ = doJSON(t, handler, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email": "owner@example.com", "password": "correct-horse-battery-staple",
	})

	loginRec, loginBody := doJSON(t, handler, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email": "owner@example.com", "password": "correct-horse-battery-staple",
	})
	require.Equal(t, http.StatusOK, loginRec.Code)
	token, _ := loginBody["token"].(string)
	require.NotEmpty(t, token)

	importRec, importBody := doJSON(t, handler, http.MethodPost, "/api/v1/sessions/import", token, map[string]any{
		"base_domain": "github.com",
		"site_name":   "GitHub",
		"base_url":    "https://github.com",
		"cookies": []map[string]any{
			{"name": "session_id", "value": "plaintext-owner-cookie"},
		},
	})
	require.Equal(t, http.StatusCreated, importRec.Code)
	sessionID, _ := importBody["ID"].(string)
	require.NotEmpty(t, sessionID, "response: %v", importBody)

	// The cookie must be encrypted at rest - never the plaintext submitted above.
	cookies, err := env.repos.SessionCookies.ListBySession(ctx, mustParseUUID(t, sessionID))
	require.NoError(t, err)
	require.Len(t, cookies, 1)
	require.NotEqual(t, "plaintext-owner-cookie", cookies[0].ValueEncrypted)
	decrypted, err := env.cipher.Decrypt(cookies[0].ValueEncrypted)
	require.NoError(t, err)
	require.Equal(t, "plaintext-owner-cookie", decrypted)

	linkRec, linkBody := doJSON(t, handler, http.MethodPost, "/api/v1/links", token, map[string]any{
		"original_session_id": sessionID,
		"label":               "demo link",
		"ttl_seconds":         3600,
	})
	require.Equal(t, http.StatusCreated, linkRec.Code, "body: %v", linkBody)
	linkID, _ := linkBody["ID"].(string)
	require.NotEmpty(t, linkID)

	listRec, _ := doJSON(t, handler, http.MethodGet, "/api/v1/links", token, nil)
	require.Equal(t, http.StatusOK, listRec.Code)
	var links []map[string]any
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &links))
	require.Len(t, links, 1)

	termRec, _ := doJSON(t, handler, http.MethodPost, "/api/v1/links/"+linkID+"/terminate", token, map[string]any{"notes": "done testing"})
	require.Equal(t, http.StatusNoContent, termRec.Code)

	link, err := env.repos.SharedLinks.GetByID(ctx, mustParseUUID(t, linkID))
	require.NoError(t, err)
	require.Equal(t, "terminated", link.Status)

	termination, err := env.repos.LinkTerminations.GetByLink(ctx, mustParseUUID(t, linkID))
	require.NoError(t, err)
	require.NotNil(t, termination)
	require.Equal(t, "manual", termination.ReasonCode)
}

// TestControlPlane_OwnershipIsEnforced checks that a second owner cannot
// see or terminate the first owner's link - the 404-not-403 behavior
// documented in middleware.RequireLinkOwnership.
func TestControlPlane_OwnershipIsEnforced(t *testing.T) {
	env := setupEnv(t)
	handler := newControlPlane(env).Routes()

	doJSON(t, handler, http.MethodPost, "/api/v1/auth/register", "", map[string]any{"email": "alice@example.com", "password": "alice-password-123"})
	_, aliceLogin := doJSON(t, handler, http.MethodPost, "/api/v1/auth/login", "", map[string]any{"email": "alice@example.com", "password": "alice-password-123"})
	aliceToken := aliceLogin["token"].(string)

	_, importBody := doJSON(t, handler, http.MethodPost, "/api/v1/sessions/import", aliceToken, map[string]any{
		"base_domain": "example.com", "base_url": "https://example.com",
		"cookies": []map[string]any{{"name": "sid", "value": "alice-secret"}},
	})
	sessionID := importBody["ID"].(string)

	_, linkBody := doJSON(t, handler, http.MethodPost, "/api/v1/links", aliceToken, map[string]any{"original_session_id": sessionID})
	linkID := linkBody["ID"].(string)

	doJSON(t, handler, http.MethodPost, "/api/v1/auth/register", "", map[string]any{"email": "bob@example.com", "password": "bob-password-456"})
	_, bobLogin := doJSON(t, handler, http.MethodPost, "/api/v1/auth/login", "", map[string]any{"email": "bob@example.com", "password": "bob-password-456"})
	bobToken := bobLogin["token"].(string)

	getRec, _ := doJSON(t, handler, http.MethodGet, "/api/v1/links/"+linkID, bobToken, nil)
	require.Equal(t, http.StatusNotFound, getRec.Code, "bob must not be able to see alice's link")

	termRec, _ := doJSON(t, handler, http.MethodPost, "/api/v1/links/"+linkID+"/terminate", bobToken, nil)
	require.Equal(t, http.StatusNotFound, termRec.Code, "bob must not be able to terminate alice's link")
}
