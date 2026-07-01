package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"sessionproxy/internal/domain"
	"sessionproxy/internal/pubsub"
	"sessionproxy/internal/service"
	appgrpc "sessionproxy/internal/transport/grpc"
	"sessionproxy/internal/transport/grpc/pb"
)

// startGRPCServer wires ImportService and AdminService over an in-memory
// bufconn listener (no real socket, no port collisions between test runs)
// and returns a ready-to-use client connection plus the pubsub.Hub, so
// tests can both call RPCs and publish events the AdminService should
// stream back out.
func startGRPCServer(t *testing.T, env testEnv) (*grpc.ClientConn, *pubsub.Hub) {
	t.Helper()

	hub := pubsub.NewHub()
	auth := service.NewAuthService(env.repos.Users, env.repos.APIKeys, []byte("test-jwt-secret-32-bytes-minimum"), time.Hour)
	sessionImport := service.NewSessionImportService(env.repos.TargetSites, env.repos.OriginalSessions, env.repos.SessionCookies, env.repos.SessionTokens, env.cipher)

	verify := appgrpc.APIKeyVerifier(auth.VerifyAPIKey)
	server := grpc.NewServer(
		grpc.UnaryInterceptor(appgrpc.AuthUnaryInterceptor(verify)),
		grpc.StreamInterceptor(appgrpc.AuthStreamInterceptor(verify)),
	)
	pb.RegisterImportServiceServer(server, appgrpc.NewImportServer(sessionImport))
	pb.RegisterAdminServiceServer(server, appgrpc.NewAdminServer(hub, env.repos.SharedLinks))

	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return conn, hub
}

func withAPIKey(ctx context.Context, rawKey string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+rawKey))
}

// TestGRPC_ImportSessionEncryptsCredentials proves the gRPC ImportService
// path goes through the exact same encryption as the REST endpoint: a
// cookie submitted over gRPC must never be stored as plaintext.
func TestGRPC_ImportSessionEncryptsCredentials(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)

	user, err := env.repos.Users.Create(ctx, domain.User{Email: "cli-user@example.com", PasswordHash: "irrelevant"})
	require.NoError(t, err)

	auth := service.NewAuthService(env.repos.Users, env.repos.APIKeys, []byte("test-jwt-secret-32-bytes-minimum"), time.Hour)
	rawKey, _, err := auth.CreateAPIKey(ctx, user.ID, "cli", nil, nil)
	require.NoError(t, err)

	conn, _ := startGRPCServer(t, env)
	client := pb.NewImportServiceClient(conn)

	resp, err := client.ImportSession(withAPIKey(ctx, rawKey), &pb.ImportSessionRequest{
		BaseDomain: "gitlab.com",
		SiteName:   "GitLab",
		BaseUrl:    "https://gitlab.com",
		Cookies:    []*pb.CookieInput{{Name: "session_id", Value: "grpc-plaintext-secret"}},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetOriginalSessionId())

	sessionID := mustParseUUID(t, resp.GetOriginalSessionId())
	cookies, err := env.repos.SessionCookies.ListBySession(ctx, sessionID)
	require.NoError(t, err)
	require.Len(t, cookies, 1)
	require.NotEqual(t, "grpc-plaintext-secret", cookies[0].ValueEncrypted)

	decrypted, err := env.cipher.Decrypt(cookies[0].ValueEncrypted)
	require.NoError(t, err)
	require.Equal(t, "grpc-plaintext-secret", decrypted)
}

// TestGRPC_ImportSessionRejectsMissingAuth checks the auth interceptor
// actually blocks unauthenticated calls rather than silently proceeding.
func TestGRPC_ImportSessionRejectsMissingAuth(t *testing.T) {
	env := setupEnv(t)
	conn, _ := startGRPCServer(t, env)
	client := pb.NewImportServiceClient(conn)

	_, err := client.ImportSession(context.Background(), &pb.ImportSessionRequest{
		BaseDomain: "example.com", BaseUrl: "https://example.com",
	})
	require.Error(t, err)
}

// TestGRPC_AdminServiceStreamsOwnedLinkActivity proves AdminService both
// streams events published on the shared Hub and filters them to links the
// authenticated caller actually owns - the same 404-flavored discretion as
// the REST ownership middleware, just over a stream instead of a single
// response.
func TestGRPC_AdminServiceStreamsOwnedLinkActivity(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)

	user, err := env.repos.Users.Create(ctx, domain.User{Email: "owner@example.com", PasswordHash: "irrelevant"})
	require.NoError(t, err)
	site, err := env.repos.TargetSites.Create(ctx, domain.TargetSite{BaseDomain: "example.com", Name: "Example", BaseURL: "https://example.com"})
	require.NoError(t, err)
	session, err := env.repos.OriginalSessions.Create(ctx, domain.OriginalSession{UserID: user.ID, TargetSiteID: site.ID})
	require.NoError(t, err)
	myLink, err := env.repos.SharedLinks.Create(ctx, domain.SharedLink{OriginalSessionID: session.ID, Token: "my-link-token"})
	require.NoError(t, err)

	// A second owner's link - events for it must never reach the first
	// owner's stream.
	otherUser, err := env.repos.Users.Create(ctx, domain.User{Email: "other@example.com", PasswordHash: "irrelevant"})
	require.NoError(t, err)
	otherSession, err := env.repos.OriginalSessions.Create(ctx, domain.OriginalSession{UserID: otherUser.ID, TargetSiteID: site.ID})
	require.NoError(t, err)
	otherLink, err := env.repos.SharedLinks.Create(ctx, domain.SharedLink{OriginalSessionID: otherSession.ID, Token: "other-link-token"})
	require.NoError(t, err)

	auth := service.NewAuthService(env.repos.Users, env.repos.APIKeys, []byte("test-jwt-secret-32-bytes-minimum"), time.Hour)
	rawKey, _, err := auth.CreateAPIKey(ctx, user.ID, "cli", nil, nil)
	require.NoError(t, err)

	conn, hub := startGRPCServer(t, env)
	client := pb.NewAdminServiceClient(conn)

	streamCtx, cancel := context.WithTimeout(withAPIKey(ctx, rawKey), 3*time.Second)
	defer cancel()
	stream, err := client.StreamLinkActivity(streamCtx, &pb.StreamLinkActivityRequest{})
	require.NoError(t, err)

	// Give the server-side goroutine time to subscribe before publishing,
	// otherwise the event could be published before Subscribe() runs.
	time.Sleep(100 * time.Millisecond)

	hub.Publish(pubsub.Event{Type: pubsub.EventLinkTerminated, LinkID: otherLink.ID, Message: "not yours", OccurredAt: time.Now()})
	hub.Publish(pubsub.Event{Type: pubsub.EventBlacklistViolation, LinkID: myLink.ID, Message: "GET /settings was blocked", OccurredAt: time.Now()})

	evt, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, myLink.ID.String(), evt.GetLinkId(), "must receive only events for links the caller owns")
	require.Equal(t, pb.LinkActivityEventType_LINK_ACTIVITY_EVENT_TYPE_BLACKLIST_VIOLATION, evt.GetType())
}
