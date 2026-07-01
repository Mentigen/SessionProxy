package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type contextKey int

const forwardTargetKey contextKey = 1

// forwardTarget carries everything Rewrite needs for one proxied request.
// It is placed on the incoming request's context by Handler before
// ReverseProxy.ServeHTTP is called, and read back out inside Rewrite -
// this keeps all repository/crypto access in Handler, so Rewrite itself
// does no I/O and cannot block on the database.
type forwardTarget struct {
	BaseURL     *url.URL
	ForwardPath string
	Plan        InjectionPlan
}

func withForwardTarget(ctx context.Context, ft forwardTarget) context.Context {
	return context.WithValue(ctx, forwardTargetKey, ft)
}

func forwardTargetFromContext(ctx context.Context) (forwardTarget, bool) {
	ft, ok := ctx.Value(forwardTargetKey).(forwardTarget)
	return ft, ok
}

// newReverseProxy builds the single httputil.ReverseProxy instance the
// Handler reuses for every guest request. Rewrite/ModifyResponse/
// ErrorHandler is the Go 1.20+ API; the older Director callback only ever
// sees the outgoing request, which is not enough to also inspect/modify
// the response for Set-Cookie stripping.
func newReverseProxy(logger *slog.Logger) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			ft, ok := forwardTargetFromContext(pr.In.Context())
			if !ok {
				// Should be unreachable: Handler always sets this before
				// calling ServeHTTP. Leaving the request unrouted would
				// proxy nowhere meaningful, so make the failure loud.
				logger.Error("proxy: missing forwardTarget in context")
				pr.Out.URL = &url.URL{Scheme: "http", Host: "invalid.invalid"}
				return
			}

			pr.Out.URL.Scheme = ft.BaseURL.Scheme
			pr.Out.URL.Host = ft.BaseURL.Host
			pr.Out.URL.Path = singleJoiningSlash(ft.BaseURL.Path, ft.ForwardPath)
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Host = ft.BaseURL.Host

			ft.Plan.Apply(pr.Out)
		},
		ModifyResponse: func(resp *http.Response) error {
			StripIdentityHeaders(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Warn("proxy: upstream error", "error", err, "path", r.URL.Path)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream target unreachable"))
		},
	}
}

// singleJoiningSlash mirrors the unexported helper of the same name in
// net/http/httputil: it joins a base path and a suffix path with exactly
// one slash between them, regardless of how many either side already has.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	default:
		return a + b
	}
}
