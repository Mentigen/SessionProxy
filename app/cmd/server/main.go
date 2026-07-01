// Command server runs the SessionProxy application: the guest-facing data
// plane (reverse proxy), the owner-facing control plane (REST/gRPC/web
// dashboard), and the background workers that keep Redis limits and
// proxy_access_logs consistent with Postgres.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	"sessionproxy/internal/config"
	"sessionproxy/internal/crypto"
	"sessionproxy/internal/limiter"
	"sessionproxy/internal/proxy"
	"sessionproxy/internal/pubsub"
	pgxrepo "sessionproxy/internal/repository/pgx"
	"sessionproxy/internal/service"
	appgrpc "sessionproxy/internal/transport/grpc"
	"sessionproxy/internal/transport/grpc/pb"
	apphttp "sessionproxy/internal/transport/http"
	"sessionproxy/internal/transport/webui"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	cipher, err := crypto.New(cfg.EncryptionKey)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxrepo.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	repos := pgxrepo.NewRepos(pool)

	redisOpts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return err
	}
	rdb := redis.NewClient(redisOpts)
	defer func() { _ = rdb.Close() }()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return err
	}
	counterStore := limiter.NewCounterStore(rdb)

	eventHub := pubsub.NewHub()

	authService := service.NewAuthService(repos.Users, repos.APIKeys, cfg.JWTSecret, cfg.AccessTokenTTL)
	sessionImportService := service.NewSessionImportService(repos.TargetSites, repos.OriginalSessions, repos.SessionCookies, repos.SessionTokens, cipher)
	linkService := service.NewLinkService(repos.OriginalSessions, repos.SharedLinks, repos.AccessPolicies, repos.Blacklist, repos.LinkTerminations)
	policyResolver := service.NewPolicyResolver(repos.AccessPolicies)
	blacklistService := service.NewBlacklistService(repos.Blacklist, slog.Default())
	enforcementService := service.NewEnforcementService(counterStore, policyResolver, blacklistService, linkService, repos.UsageCounters, repos.SecurityEvents, eventHub, slog.Default())

	syncWorker := limiter.NewSyncWorker(counterStore, repos.UsageCounters, cfg.LimiterSyncInterval, slog.Default())
	go syncWorker.Run(ctx)

	accessLogger := proxy.NewAsyncAccessLogger(repos.ProxyAccessLogs, slog.Default(), cfg.ProxyLogBatchSize, cfg.ProxyLogFlushInterval)
	go accessLogger.Run(ctx)

	proxyHandler := proxy.New(repos.SharedLinks, repos.SessionCookies, repos.SessionTokens, repos.Guests, repos.GuestSessions, cipher, accessLogger, slog.Default())
	proxyHandler.Enforcer = enforcementService

	controlPlane := &apphttp.Server{
		Logger:           slog.Default(),
		Auth:             authService,
		SessionImport:    sessionImportService,
		Links:            linkService,
		Users:            repos.Users,
		Devices:          repos.Devices,
		APIKeys:          repos.APIKeys,
		TargetSites:      repos.TargetSites,
		OriginalSessions: repos.OriginalSessions,
		SharedLinks:      repos.SharedLinks,
		AccessPolicies:   repos.AccessPolicies,
		Blacklist:        repos.Blacklist,
		Guests:           repos.Guests,
		GuestSessions:    repos.GuestSessions,
		ProxyAccessLogs:  repos.ProxyAccessLogs,
		LinkTerminations: repos.LinkTerminations,
		SecurityEvents:   repos.SecurityEvents,
		Stats:            repos.Stats,
	}

	dashboard := &webui.Server{
		Logger:        slog.Default(),
		Auth:          authService,
		SessionImport: sessionImportService,
		Links:         linkService,
		SharedLinks:   repos.SharedLinks,
		Hub:           eventHub,
	}

	mux := http.NewServeMux()
	mux.Handle(proxy.RoutePrefix, proxyHandler)
	mux.Handle("/dashboard/", http.StripPrefix("/dashboard", dashboard.Routes()))
	mux.Handle("/", controlPlane.Routes())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("db unreachable: " + err.Error()))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	grpcAuth := appgrpc.APIKeyVerifier(authService.VerifyAPIKey)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(appgrpc.AuthUnaryInterceptor(grpcAuth)),
		grpc.StreamInterceptor(appgrpc.AuthStreamInterceptor(grpcAuth)),
	)
	pb.RegisterImportServiceServer(grpcServer, appgrpc.NewImportServer(sessionImportService))
	pb.RegisterAdminServiceServer(grpcServer, appgrpc.NewAdminServer(eventHub, repos.SharedLinks))

	grpcListener, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		return err
	}

	// Kept off the public HTTP port on purpose: /metrics and /debug/pprof
	// are operational surfaces (Prometheus scraping, profiling), not part
	// of any of the three public APIs. monitoring/prometheus/prometheus.yml
	// scrapes this port directly inside the docker network.
	debugMux := http.NewServeMux()
	debugMux.Handle("/metrics", promhttp.Handler())
	debugMux.HandleFunc("/debug/pprof/", pprof.Index)
	debugMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	debugMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	debugSrv := &http.Server{Addr: ":" + cfg.DebugPort, Handler: debugMux, ReadHeaderTimeout: 5 * time.Second}

	errCh := make(chan error, 3)
	go func() {
		slog.Info("http server listening", "port", cfg.HTTPPort)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		slog.Info("grpc server listening", "port", cfg.GRPCPort)
		if err := grpcServer.Serve(grpcListener); err != nil {
			errCh <- err
		}
	}()
	go func() {
		slog.Info("debug server listening", "port", cfg.DebugPort)
		if err := debugSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
		grpcServer.GracefulStop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = debugSrv.Shutdown(shutdownCtx)
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
