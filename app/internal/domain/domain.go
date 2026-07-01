// Package domain contains the plain data types and repository interfaces the
// service layer depends on. Nothing here imports pgx, redis or net/http: the
// point is that internal/service can be unit-tested with gomock-generated
// fakes of these interfaces, with no database in the loop.
package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ---- Group 1: users, devices, api keys ----------------------------------

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	DisplayName  *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Device struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Name        *string
	Fingerprint *string
	LastSeenAt  *time.Time
	CreatedAt   time.Time
}

type APIKey struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	DeviceID  *uuid.UUID
	KeyHash   string
	Label     *string
	RevokedAt *time.Time
	ExpiresAt *time.Time
	CreatedAt time.Time
}

// ---- Group 2: target sites and owner sessions ----------------------------

type TargetSite struct {
	ID         uuid.UUID
	BaseDomain string
	Name       string
	BaseURL    string
	CreatedAt  time.Time
}

const (
	SessionStatusActive    = "active"
	SessionStatusRevoked   = "revoked"
	SessionStatusExpired   = "expired"
	LinkStatusActive       = "active"
	LinkStatusTerminated   = "terminated"
	GuestSessionActive     = "active"
	GuestSessionTerminated = "terminated"
)

type OriginalSession struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TargetSiteID uuid.UUID
	DeviceID     *uuid.UUID
	Status       string
	Label        *string
	ImportedAt   time.Time
	ExpiresAt    *time.Time
}

// SessionCookie mirrors session_cookies. ValueEncrypted is the ciphertext as
// stored in Postgres (base64(nonce||ct)); plaintext never appears in this type.
type SessionCookie struct {
	ID                uuid.UUID
	OriginalSessionID uuid.UUID
	Name              string
	ValueEncrypted    string
	Domain            *string
	Path              string
	Secure            bool
	HTTPOnly          bool
	SameSite          *string
	ExpiresAt         *time.Time
	CreatedAt         time.Time
}

type SessionToken struct {
	ID                uuid.UUID
	OriginalSessionID uuid.UUID
	TokenType         *string
	HeaderName        *string
	ValueEncrypted    string
	ExpiresAt         *time.Time
	CreatedAt         time.Time
}

// ---- Group 3: shared links, policies, blacklists -------------------------

type SharedLink struct {
	ID                uuid.UUID
	OriginalSessionID uuid.UUID
	Token             string
	Status            string
	Label             *string
	CreatedAt         time.Time
	ExpiresAt         *time.Time
}

type AccessPolicy struct {
	ID                  uuid.UUID
	UserID              uuid.UUID
	Name                string
	MaxRequests         *int64
	MaxBytesTransferred *int64
	MaxTTLSeconds       *int64
	// MaxViolationCount is nullable in the schema (DEFAULT 3, no NOT NULL);
	// nil is treated as the schema default of 3 by policy_resolver.
	MaxViolationCount *int64
	CreatedAt         time.Time
}

// DefaultMaxViolationCount mirrors the schema-level DEFAULT 3 on
// access_policies.max_violation_count, applied wherever the column is NULL.
const DefaultMaxViolationCount int64 = 3

const (
	PatternTypePrefix = "prefix"
	PatternTypeRegex  = "regex"
)

type BlacklistedEndpoint struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Pattern     string
	PatternType string
	Description *string
	CreatedAt   time.Time

	// BlockedMethods is populated by the repository from endpoint_blocked_methods.
	// An empty slice means "all methods are blocked for this path pattern".
	BlockedMethods []string
}

// ---- Group 4: guests, guest sessions, usage counters ---------------------

type Guest struct {
	ID                 uuid.UUID
	IPAddress          *string
	UserAgent          *string
	BrowserFingerprint *string
	FirstSeenAt        time.Time
	LastSeenAt         *time.Time
}

type GuestSession struct {
	ID            uuid.UUID
	SharedLinkID  uuid.UUID
	GuestID       *uuid.UUID
	Status        string
	StartedAt     time.Time
	LastRequestAt *time.Time
	TerminatedAt  *time.Time
}

type UsageCounters struct {
	ID               uuid.UUID
	SharedLinkID     uuid.UUID
	RequestCount     int64
	BytesTransferred int64
	ViolationCount   int64
	UpdatedAt        time.Time
}

// ---- Group 5: logs and security --------------------------------------

type ProxyAccessLog struct {
	ID               int64
	GuestSessionID   *uuid.UUID
	SharedLinkID     uuid.UUID
	TargetURL        string
	HTTPMethod       string
	ResponseStatus   *int
	BytesTransferred *int
	ResponseTimeMs   *int
	RequestedAt      time.Time
}

// Revocation reason codes, seeded once in migrations/00005.
const (
	ReasonTTLExpired     = "ttl_expired"
	ReasonRequestLimit   = "request_limit"
	ReasonTrafficLimit   = "traffic_limit"
	ReasonViolationLimit = "violation_limit"
	ReasonManual         = "manual"
)

type LinkTermination struct {
	ID           uuid.UUID
	SharedLinkID uuid.UUID
	ReasonCode   string
	TerminatedBy *uuid.UUID
	Notes        *string
	TerminatedAt time.Time
}

// RevocationReason mirrors the 5-row fixed reference table seeded once by
// migration 00005 (ttl_expired, request_limit, traffic_limit,
// violation_limit, manual).
type RevocationReason struct {
	Code        string
	Description *string
}

const (
	EventBlacklistViolation   = "blacklist_violation"
	EventRateLimitExceeded    = "rate_limit_exceeded"
	EventTrafficLimitExceeded = "traffic_limit_exceeded"
)

type SecurityEvent struct {
	ID             int64
	GuestSessionID *uuid.UUID
	SharedLinkID   uuid.UUID
	EventType      string
	TargetURL      *string
	HTTPMethod     *string
	Details        map[string]any
	OccurredAt     time.Time
}

// EffectivePolicy is the result of resolving all access_policies linked to a
// shared_link (M:N via link_policies) down to a single set of limits, using
// most-restrictive-wins: the minimum of each field across all linked
// policies, where a NULL field does not participate (acts as +Inf).
type EffectivePolicy struct {
	MaxRequests         *int64
	MaxBytesTransferred *int64
	MaxTTLSeconds       *int64
	MaxViolationCount   int64 // always has a value: schema default is 3
}

// LinkWithSession bundles a shared_link with just enough of its owning chain
// (original_session -> target_site) to drive proxying and ownership checks,
// without a full domain object graph.
type LinkWithSession struct {
	Link            SharedLink
	OriginalSession OriginalSession
	TargetSite      TargetSite
	OwnerUserID     uuid.UUID
}

// ---- Repository interfaces ------------------------------------------------
//
// Implementations live in internal/repository/pgx. The service layer only
// ever sees these interfaces, which is what makes gomock-based unit tests of
// internal/service possible without a real database.

type UserRepository interface {
	Create(ctx context.Context, u User) (User, error)
	GetByID(ctx context.Context, id uuid.UUID) (User, error)
	GetByEmail(ctx context.Context, email string) (User, error)
	List(ctx context.Context, limit, offset int) ([]User, error)
	Update(ctx context.Context, u User) (User, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type DeviceRepository interface {
	Create(ctx context.Context, d Device) (Device, error)
	GetByID(ctx context.Context, id uuid.UUID) (Device, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]Device, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type APIKeyRepository interface {
	Create(ctx context.Context, k APIKey) (APIKey, error)
	GetByHash(ctx context.Context, keyHash string) (APIKey, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]APIKey, error)
	Revoke(ctx context.Context, id uuid.UUID) error
}

type TargetSiteRepository interface {
	Create(ctx context.Context, s TargetSite) (TargetSite, error)
	GetByID(ctx context.Context, id uuid.UUID) (TargetSite, error)
	GetOrCreateByDomain(ctx context.Context, domain, name, baseURL string) (TargetSite, error)
	List(ctx context.Context) ([]TargetSite, error)
}

type OriginalSessionRepository interface {
	Create(ctx context.Context, s OriginalSession) (OriginalSession, error)
	GetByID(ctx context.Context, id uuid.UUID) (OriginalSession, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]OriginalSession, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
}

type SessionCookieRepository interface {
	CreateBatch(ctx context.Context, cookies []SessionCookie) error
	ListBySession(ctx context.Context, originalSessionID uuid.UUID) ([]SessionCookie, error)
}

type SessionTokenRepository interface {
	CreateBatch(ctx context.Context, tokens []SessionToken) error
	ListBySession(ctx context.Context, originalSessionID uuid.UUID) ([]SessionToken, error)
}

type SharedLinkRepository interface {
	Create(ctx context.Context, l SharedLink) (SharedLink, error)
	GetByToken(ctx context.Context, token string) (LinkWithSession, error)
	GetByID(ctx context.Context, id uuid.UUID) (SharedLink, error)
	ListByUser(ctx context.Context, userID uuid.UUID, status string) ([]SharedLink, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
	// OwnerUserID returns the user_id derived through
	// shared_links.original_session_id -> original_sessions.user_id, the
	// join every ownership check in the app must perform.
	OwnerUserID(ctx context.Context, linkID uuid.UUID) (uuid.UUID, error)
}

type AccessPolicyRepository interface {
	Create(ctx context.Context, p AccessPolicy) (AccessPolicy, error)
	GetByID(ctx context.Context, id uuid.UUID) (AccessPolicy, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]AccessPolicy, error)
	Delete(ctx context.Context, id uuid.UUID) error
	AttachToLink(ctx context.Context, linkID, policyID uuid.UUID) error
	// ListForLink returns every access_policy linked to a shared_link via
	// link_policies, the input to most-restrictive-wins resolution.
	ListForLink(ctx context.Context, linkID uuid.UUID) ([]AccessPolicy, error)
}

type BlacklistRepository interface {
	Create(ctx context.Context, e BlacklistedEndpoint) (BlacklistedEndpoint, error)
	GetByID(ctx context.Context, id uuid.UUID) (BlacklistedEndpoint, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]BlacklistedEndpoint, error)
	Delete(ctx context.Context, id uuid.UUID) error
	AttachToSite(ctx context.Context, siteID, endpointID uuid.UUID) error
	AttachToLink(ctx context.Context, linkID, endpointID uuid.UUID) error
	SetBlockedMethods(ctx context.Context, endpointID uuid.UUID, methods []string) error
	// RulesForLink returns the union of site-level and link-level blacklist
	// rules that apply to a given shared_link, each with its blocked methods
	// populated.
	RulesForLink(ctx context.Context, linkID, targetSiteID uuid.UUID) ([]BlacklistedEndpoint, error)
}

type GuestRepository interface {
	GetOrCreate(ctx context.Context, ipAddress, userAgent, fingerprint string) (Guest, error)
	List(ctx context.Context, limit, offset int) ([]Guest, error)
}

type GuestSessionRepository interface {
	Create(ctx context.Context, gs GuestSession) (GuestSession, error)
	GetActiveByLinkAndGuest(ctx context.Context, linkID uuid.UUID, guestID *uuid.UUID) (*GuestSession, error)
	ListByLink(ctx context.Context, linkID uuid.UUID) ([]GuestSession, error)
	Terminate(ctx context.Context, id uuid.UUID) error
	TouchLastRequest(ctx context.Context, id uuid.UUID) error
}

type UsageCounterRepository interface {
	GetByLink(ctx context.Context, linkID uuid.UUID) (UsageCounters, error)
	Upsert(ctx context.Context, c UsageCounters) error
}

type ProxyAccessLogRepository interface {
	Insert(ctx context.Context, l ProxyAccessLog) error
	InsertBatch(ctx context.Context, logs []ProxyAccessLog) error
	ListByLink(ctx context.Context, linkID uuid.UUID, limit int) ([]ProxyAccessLog, error)
}

type LinkTerminationRepository interface {
	Create(ctx context.Context, t LinkTermination) error
	GetByLink(ctx context.Context, linkID uuid.UUID) (*LinkTermination, error)
	ListReasons(ctx context.Context) ([]RevocationReason, error)
}

type SecurityEventRepository interface {
	Create(ctx context.Context, e SecurityEvent) error
	ListByLink(ctx context.Context, linkID uuid.UUID, limit int) ([]SecurityEvent, error)
	ListRecent(ctx context.Context, limit int) ([]SecurityEvent, error)
}

// LinkStats mirrors a row of the mv_link_stats materialized view.
type LinkStats struct {
	TargetSiteID   uuid.UUID
	SiteName       string
	BaseDomain     string
	SharedLinkID   uuid.UUID
	TotalRequests  int64
	TotalBytes     int64
	AvgResponseMs  float64
	FirstRequestAt *time.Time
	LastRequestAt  *time.Time
}

type StatsRepository interface {
	GetLinkStats(ctx context.Context, linkID uuid.UUID) (*LinkStats, error)
	RefreshMaterializedView(ctx context.Context) error
}
