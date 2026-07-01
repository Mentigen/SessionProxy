// Package grpc implements the two services described in the
// implementation plan as gRPC's content-justified use in this project (not
// a 1:1 mirror of the REST API): AdminService streams live link activity,
// and ImportService gives CLI/browser-extension clients (the reason
// api_keys exists at all, per README group 1) a typed alternative to
// POST /api/v1/sessions/import.
package grpc

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ctxKey int

const userIDKey ctxKey = 1

// UserID reads the authenticated caller's user_id, set by
// AuthUnaryInterceptor. Panics if called outside that interceptor's chain,
// same convention as middleware.UserID on the REST side.
func UserID(ctx context.Context) uuid.UUID {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	if !ok {
		panic("grpc: UserID called without AuthUnaryInterceptor in the chain")
	}
	return id
}

// APIKeyVerifier is satisfied by *service.AuthService.VerifyAPIKey.
type APIKeyVerifier func(ctx context.Context, rawKey string) (uuid.UUID, error)

// AuthUnaryInterceptor reads "authorization: Bearer spk_..." from gRPC
// metadata and verifies it as an api_keys value - never a JWT, since gRPC
// clients here are expected to hold a long-lived key, not an interactive
// browser session.
func AuthUnaryInterceptor(verify APIKeyVerifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		userID, err := authenticate(ctx, verify)
		if err != nil {
			return nil, err
		}
		return handler(context.WithValue(ctx, userIDKey, userID), req)
	}
}

// AuthStreamInterceptor is the streaming-RPC counterpart, used by
// AdminService.StreamLinkActivity.
func AuthStreamInterceptor(verify APIKeyVerifier) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		userID, err := authenticate(ss.Context(), verify)
		if err != nil {
			return err
		}
		return handler(srv, &authenticatedStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), userIDKey, userID)})
	}
}

type authenticatedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedStream) Context() context.Context { return s.ctx }

func authenticate(ctx context.Context, verify APIKeyVerifier) (uuid.UUID, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return uuid.Nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return uuid.Nil, status.Error(codes.Unauthenticated, "missing authorization metadata")
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	userID, err := verify(ctx, token)
	if err != nil {
		return uuid.Nil, status.Error(codes.Unauthenticated, "invalid api key")
	}
	return userID, nil
}
