package proxy

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"sessionproxy/internal/crypto"
	"sessionproxy/internal/domain"
)

// InjectionPlan holds everything needed to make the outgoing request to the
// target site look like it came from the owner: cookies rebuilt from
// decrypted session_cookies rows, and arbitrary headers rebuilt from
// decrypted session_tokens rows.
//
// Decryption happens exactly once, in BuildInjectionPlan, immediately before
// the request that will use it - the plan is not cached or reused across
// requests, so a decrypted value never lingers in memory longer than a
// single proxied request.
type InjectionPlan struct {
	Cookies []*http.Cookie
	Headers http.Header
}

type sessionCredentialReader interface {
	ListBySession(ctx context.Context, originalSessionID uuid.UUID) ([]domain.SessionCookie, error)
}

type sessionTokenReader interface {
	ListBySession(ctx context.Context, originalSessionID uuid.UUID) ([]domain.SessionToken, error)
}

// BuildInjectionPlan loads and decrypts the owner's cookies and tokens for
// one original_session. It is the only place in the application that calls
// Cipher.Decrypt on credential material.
func BuildInjectionPlan(ctx context.Context, cipher *crypto.Cipher, cookies sessionCredentialReader, tokens sessionTokenReader, originalSessionID uuid.UUID) (InjectionPlan, error) {
	plan := InjectionPlan{Headers: make(http.Header)}

	cookieRows, err := cookies.ListBySession(ctx, originalSessionID)
	if err != nil {
		return InjectionPlan{}, fmt.Errorf("proxy: load session_cookies: %w", err)
	}
	for _, c := range cookieRows {
		value, err := cipher.Decrypt(c.ValueEncrypted)
		if err != nil {
			return InjectionPlan{}, fmt.Errorf("proxy: decrypt session_cookie %q: %w", c.Name, err)
		}
		// #nosec G124 -- this http.Cookie is never sent to a browser via
		// Set-Cookie; it is only ever used through req.AddCookie() to build
		// the outgoing Cookie request header to the target site (see
		// InjectionPlan.Apply below). Secure/HttpOnly/SameSite are
		// response-cookie attributes and do not apply here.
		plan.Cookies = append(plan.Cookies, &http.Cookie{Name: c.Name, Value: value})
	}

	tokenRows, err := tokens.ListBySession(ctx, originalSessionID)
	if err != nil {
		return InjectionPlan{}, fmt.Errorf("proxy: load session_tokens: %w", err)
	}
	for _, t := range tokenRows {
		value, err := cipher.Decrypt(t.ValueEncrypted)
		if err != nil {
			return InjectionPlan{}, fmt.Errorf("proxy: decrypt session_token: %w", err)
		}
		headerName := "Authorization"
		if t.HeaderName != nil && *t.HeaderName != "" {
			headerName = *t.HeaderName
		}
		plan.Headers.Add(headerName, value)
	}

	return plan, nil
}

// Apply sets the owner's cookies and headers on the outgoing request,
// replacing whatever the guest sent. The guest's own Cookie/Authorization
// headers are never forwarded upstream: they could not be valid for the
// owner's account anyway, and forwarding them would blur the boundary this
// proxy exists to enforce.
func (p InjectionPlan) Apply(out *http.Request) {
	out.Header.Del("Cookie")
	out.Header.Del("Authorization")
	for _, c := range p.Cookies {
		out.AddCookie(c)
	}
	for name, values := range p.Headers {
		for _, v := range values {
			out.Header.Add(name, v)
		}
	}
}
