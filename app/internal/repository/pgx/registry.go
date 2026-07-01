package pgx

import (
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repos bundles every repository the app needs, all backed by the same
// pool. Service constructors take exactly the repositories they need out of
// this struct rather than the struct itself, keeping their dependencies
// explicit.
type Repos struct {
	Users            *UserRepo
	Devices          *DeviceRepo
	APIKeys          *APIKeyRepo
	TargetSites      *TargetSiteRepo
	OriginalSessions *OriginalSessionRepo
	SessionCookies   *SessionCookieRepo
	SessionTokens    *SessionTokenRepo
	SharedLinks      *SharedLinkRepo
	AccessPolicies   *AccessPolicyRepo
	Blacklist        *BlacklistRepo
	Guests           *GuestRepo
	GuestSessions    *GuestSessionRepo
	UsageCounters    *UsageCounterRepo
	ProxyAccessLogs  *ProxyAccessLogRepo
	LinkTerminations *LinkTerminationRepo
	SecurityEvents   *SecurityEventRepo
	Stats            *StatsRepo
}

// NewRepos wires every repository to the pool. Individual services that need
// transactional consistency across tables (e.g. link_service creating a
// shared_link plus its link_policies rows) build a second, short-lived Repos
// value over a pgx.Tx instead of using this one - see WithTx.
func NewRepos(pool *pgxpool.Pool) *Repos {
	return newRepos(pool)
}

// newRepos is the shared constructor: pool satisfies querier, and so does
// pgx.Tx, so the same function builds either the pool-backed registry used
// for the lifetime of the app or a tx-scoped registry for one transaction.
func newRepos(q querier) *Repos {
	return &Repos{
		Users:            NewUserRepo(q),
		Devices:          NewDeviceRepo(q),
		APIKeys:          NewAPIKeyRepo(q),
		TargetSites:      NewTargetSiteRepo(q),
		OriginalSessions: NewOriginalSessionRepo(q),
		SessionCookies:   NewSessionCookieRepo(q),
		SessionTokens:    NewSessionTokenRepo(q),
		SharedLinks:      NewSharedLinkRepo(q),
		AccessPolicies:   NewAccessPolicyRepo(q),
		Blacklist:        NewBlacklistRepo(q),
		Guests:           NewGuestRepo(q),
		GuestSessions:    NewGuestSessionRepo(q),
		UsageCounters:    NewUsageCounterRepo(q),
		ProxyAccessLogs:  NewProxyAccessLogRepo(q),
		LinkTerminations: NewLinkTerminationRepo(q),
		SecurityEvents:   NewSecurityEventRepo(q),
		Stats:            NewStatsRepo(q),
	}
}

// NewTxRepos builds a Repos backed by an open transaction, for callers that
// already have one (see WithTx).
func NewTxRepos(q querier) *Repos { return newRepos(q) }
