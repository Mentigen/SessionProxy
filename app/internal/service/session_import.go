package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"sessionproxy/internal/crypto"
	"sessionproxy/internal/domain"
)

// CookieInput/TokenInput are the plaintext shapes an owner submits when
// importing a session. Plaintext exists only transiently in this request;
// SessionImportService is the one place that turns it into
// value_encrypted before it ever reaches a repository.
type CookieInput struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Secure   bool
	HTTPOnly bool
	SameSite string
}

type TokenInput struct {
	TokenType  string
	HeaderName string
	Value      string
}

// SessionImportService implements FR1: importing an owner's session for a
// target site, with cookies/tokens encrypted before storage.
type SessionImportService struct {
	targetSites domain.TargetSiteRepository
	sessions    domain.OriginalSessionRepository
	cookies     domain.SessionCookieRepository
	tokens      domain.SessionTokenRepository
	cipher      *crypto.Cipher
}

func NewSessionImportService(sites domain.TargetSiteRepository, sessions domain.OriginalSessionRepository, cookies domain.SessionCookieRepository, tokens domain.SessionTokenRepository, cipher *crypto.Cipher) *SessionImportService {
	return &SessionImportService{targetSites: sites, sessions: sessions, cookies: cookies, tokens: tokens, cipher: cipher}
}

// Import creates (or reuses) the target_sites row for baseDomain, creates an
// original_session owned by userID, and stores every cookie/token
// encrypted. It returns the created session so the caller can immediately
// create a shared_link against it.
func (s *SessionImportService) Import(ctx context.Context, userID uuid.UUID, baseDomain, siteName, baseURL string, cookieInputs []CookieInput, tokenInputs []TokenInput) (domain.OriginalSession, error) {
	site, err := s.targetSites.GetOrCreateByDomain(ctx, baseDomain, siteName, baseURL)
	if err != nil {
		return domain.OriginalSession{}, fmt.Errorf("service: resolve target site: %w", err)
	}

	session, err := s.sessions.Create(ctx, domain.OriginalSession{UserID: userID, TargetSiteID: site.ID})
	if err != nil {
		return domain.OriginalSession{}, fmt.Errorf("service: create original_session: %w", err)
	}

	if len(cookieInputs) > 0 {
		rows := make([]domain.SessionCookie, 0, len(cookieInputs))
		for _, c := range cookieInputs {
			enc, err := s.cipher.Encrypt(c.Value)
			if err != nil {
				return domain.OriginalSession{}, fmt.Errorf("service: encrypt cookie %q: %w", c.Name, err)
			}
			row := domain.SessionCookie{
				OriginalSessionID: session.ID,
				Name:              c.Name,
				ValueEncrypted:    enc,
				Path:              c.Path,
				Secure:            c.Secure,
				HTTPOnly:          c.HTTPOnly,
			}
			if c.Domain != "" {
				row.Domain = &c.Domain
			}
			if c.SameSite != "" {
				row.SameSite = &c.SameSite
			}
			rows = append(rows, row)
		}
		if err := s.cookies.CreateBatch(ctx, rows); err != nil {
			return domain.OriginalSession{}, fmt.Errorf("service: store session_cookies: %w", err)
		}
	}

	if len(tokenInputs) > 0 {
		rows := make([]domain.SessionToken, 0, len(tokenInputs))
		for _, t := range tokenInputs {
			enc, err := s.cipher.Encrypt(t.Value)
			if err != nil {
				return domain.OriginalSession{}, fmt.Errorf("service: encrypt token: %w", err)
			}
			tokenType := t.TokenType
			if tokenType == "" {
				tokenType = "bearer" // session_tokens.token_type is NOT NULL in the schema
			}
			row := domain.SessionToken{OriginalSessionID: session.ID, ValueEncrypted: enc, TokenType: &tokenType}
			if t.HeaderName != "" {
				row.HeaderName = &t.HeaderName
			}
			rows = append(rows, row)
		}
		if err := s.tokens.CreateBatch(ctx, rows); err != nil {
			return domain.OriginalSession{}, fmt.Errorf("service: store session_tokens: %w", err)
		}
	}

	return session, nil
}
