package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sessionproxy/internal/service"
	"sessionproxy/internal/transport/grpc/pb"
)

// ImportServer implements pb.ImportServiceServer by delegating straight to
// service.SessionImportService - the exact same encrypt-then-store logic
// POST /api/v1/sessions/import uses, so a cookie submitted over gRPC is
// encrypted by the same code path as one submitted over REST.
type ImportServer struct {
	pb.UnimplementedImportServiceServer
	imports *service.SessionImportService
}

func NewImportServer(imports *service.SessionImportService) *ImportServer {
	return &ImportServer{imports: imports}
}

func (s *ImportServer) ImportSession(ctx context.Context, req *pb.ImportSessionRequest) (*pb.ImportSessionResponse, error) {
	if req.GetBaseDomain() == "" || req.GetBaseUrl() == "" {
		return nil, status.Error(codes.InvalidArgument, "base_domain and base_url are required")
	}
	siteName := req.GetSiteName()
	if siteName == "" {
		siteName = req.GetBaseDomain()
	}

	cookies := make([]service.CookieInput, 0, len(req.GetCookies()))
	for _, c := range req.GetCookies() {
		cookies = append(cookies, service.CookieInput{
			Name: c.GetName(), Value: c.GetValue(), Domain: c.GetDomain(), Path: c.GetPath(),
			Secure: c.GetSecure(), HTTPOnly: c.GetHttpOnly(), SameSite: c.GetSameSite(),
		})
	}
	tokens := make([]service.TokenInput, 0, len(req.GetTokens()))
	for _, t := range req.GetTokens() {
		tokens = append(tokens, service.TokenInput{TokenType: t.GetTokenType(), HeaderName: t.GetHeaderName(), Value: t.GetValue()})
	}

	userID := UserID(ctx)
	session, err := s.imports.Import(ctx, userID, req.GetBaseDomain(), siteName, req.GetBaseUrl(), cookies, tokens)
	if err != nil {
		return nil, status.Error(codes.Internal, "import failed")
	}

	return &pb.ImportSessionResponse{
		OriginalSessionId: session.ID.String(),
		TargetSiteId:      session.TargetSiteID.String(),
	}, nil
}
