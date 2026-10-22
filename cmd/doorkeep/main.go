// Command doorkeep is the self-hosted bot and abuse risk scoring server.
//
//	doorkeep serve [--config path]
//	doorkeep site create --name NAME --origin https://example.com [--origin ...] [--mode enforce|monitor|challenge_only]
//	doorkeep site list
//	doorkeep migrate
//	doorkeep version
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/iamsuriyan/doorkeep/internal/api"
	"github.com/iamsuriyan/doorkeep/internal/config"
	"github.com/iamsuriyan/doorkeep/internal/nonce"
	"github.com/iamsuriyan/doorkeep/internal/pseudo"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/scoring/rules"
	"github.com/iamsuriyan/doorkeep/internal/signals/ipintel"
	"github.com/iamsuriyan/doorkeep/internal/signals/velocity"
	"github.com/iamsuriyan/doorkeep/internal/store"
	"github.com/iamsuriyan/doorkeep/internal/store/sqlstore"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "site":
		err = site(os.Args[2:])
	case "migrate":
		err = migrate(os.Args[2:])
	case "ipdata":
		err = ipdata(os.Args[2:])
	case "admin":
		err = admin(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("doorkeep", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "doorkeep:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `doorkeep: self-hosted bot and abuse risk scoring

Usage:
  doorkeep serve [--config path]
  doorkeep site create --name NAME --origin URL [--origin URL ...] [--mode enforce|monitor|challenge_only]
  doorkeep site list
  doorkeep admin create --user NAME     (reads the password from stdin)
  doorkeep admin token --name NAME      (prints a bearer token for automation)
  doorkeep ipdata update [--config path]
  doorkeep migrate [--config path]
  doorkeep version

Configuration comes from the YAML file and DOORKEEP_* environment variables.
Secrets are generated on first run and stored in the data directory.
`)
}

func load(fs *flag.FlagSet, args []string) (*config.Config, *sqlstore.DB, error) {
	return loadWith(fs, args)
}

func loadWith(fs *flag.FlagSet, args []string) (*config.Config, *sqlstore.DB, error) {
	cfgPath := fs.String("config", os.Getenv("DOORKEEP_CONFIG"), "path to config YAML")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return nil, nil, err
	}
	var db *sqlstore.DB
	if cfg.DatabaseURL != "" {
		db, err = sqlstore.OpenPostgres(cfg.DatabaseURL)
	} else {
		db, err = sqlstore.Open(filepath.Join(cfg.DataDir, "doorkeep.db"))
	}
	if err != nil {
		return nil, nil, err
	}
	return cfg, db, nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfg, db, err := load(fs, args)
	if err != nil {
		return err
	}
	defer db.Close()
	log := newLogger(cfg.LogLevel)
	rs, err := rules.Builtin()
	if err != nil {
		return err
	}
	srv := api.New(cfg, db, rs, log)
	if cfg.RedisURL != "" {
		rv, err := velocity.NewRedis(cfg.RedisURL, nil, log)
		if err != nil {
			return fmt.Errorf("redis: %w", err)
		}
		defer rv.Close()
		srv.Vel = rv
		log.Info("cluster mode", "store", "postgres", "velocity", "redis")
	}
	loadIPData(srv.IP, cfg, log)
	if snap, err := db.LoadModels(context.Background()); err == nil && len(snap) > 0 {
		if err := srv.Models.Restore(snap); err != nil {
			log.Error("model restore", "err", err)
		} else {
			log.Info("models restored", "entries", len(snap))
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go janitor(ctx, db, cfg, log)
	go rollup(ctx, srv, log)
	go ipdataRefresher(ctx, srv.IP, cfg, log)
	go modelSaver(ctx, srv, db, log)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	if cfg.TLSEnabled() {
		tlsCfg, err := tlsConfig(cfg)
		if err != nil {
			return err
		}
		if ln, err = api.ConfigureTLS(hs, ln, tlsCfg); err != nil {
			return err
		}
	} else {
		log.Warn("TLS not terminated by doorkeep: JA4 and HTTP/2 fingerprints are only available via Doorkeep-TLS/Doorkeep-H2 headers from trusted proxies")
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("doorkeep listening", "addr", cfg.Listen, "tls", cfg.TLSEnabled(), "version", version, "data_dir", cfg.DataDir, "rules", len(rs.Rules()))
		errc <- hs.Serve(ln)
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := hs.Shutdown(sctx)
		if serr := db.SaveModels(context.Background(), srv.Models.Snapshot(), time.Now()); serr != nil {
			log.Error("model save on shutdown", "err", serr)
		}
		return err
	}
	return nil
}

// janitor purges expired nonces and events past retention.
func janitor(ctx context.Context, db store.Store, cfg *config.Config, log *slog.Logger) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		now := time.Now()
		if n, err := db.PurgeExpired(ctx, now.Add(-nonce.Retention)); err == nil && n > 0 {
			log.Debug("purged nonces", "count", n)
		}
		if n, err := db.PurgeEvents(ctx, now.Add(-cfg.EventRetention)); err == nil && n > 0 {
			log.Info("purged events past retention", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func site(args []string) error {
	if len(args) == 0 {
		return errors.New("site: expected create or list")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("site create", flag.ExitOnError)
		name := fs.String("name", "", "site name")
		mode := fs.String("mode", string(scoring.ModeEnforce), "enforce | monitor | challenge_only")
		var origins multiFlag
		fs.Var(&origins, "origin", "allowed origin, e.g. https://example.com (repeatable; * for development)")
		_, db, err := load(fs, args[1:])
		if err != nil {
			return err
		}
		defer db.Close()
		if *name == "" || len(origins) == 0 {
			return errors.New("site create: --name and at least one --origin are required")
		}
		m := scoring.SiteMode(*mode)
		if m != scoring.ModeEnforce && m != scoring.ModeMonitor && m != scoring.ModeChallengeOnly {
			return fmt.Errorf("site create: unknown mode %q", *mode)
		}
		for i, o := range origins {
			origins[i] = strings.TrimRight(o, "/")
		}
		secret := "dk_sk_" + randToken(32)
		s := &store.Site{
			ID: "site_" + randToken(9), Name: *name, SiteKey: "dk_pk_" + randToken(18),
			SecretHash: pseudo.SecretHash(secret), Origins: origins, Mode: m,
			Thresholds: scoring.DefaultThresholds,
		}
		if err := db.CreateSite(context.Background(), s); err != nil {
			return err
		}
		fmt.Printf("Site created: %s (%s)\n\n  site key (public, goes in your HTML): %s\n  secret   (server only, shown once):   %s\n\nOrigins: %s\nMode:    %s\n",
			s.Name, s.ID, s.SiteKey, secret, strings.Join(s.Origins, ", "), s.Mode)
		return nil
	case "list":
		fs := flag.NewFlagSet("site list", flag.ExitOnError)
		_, db, err := load(fs, args[1:])
		if err != nil {
			return err
		}
		defer db.Close()
		sites, err := db.ListSites(context.Background())
		if err != nil {
			return err
		}
		for _, s := range sites {
			fmt.Printf("%s\t%s\t%s\t%s\t%s\n", s.ID, s.Name, s.SiteKey, s.Mode, strings.Join(s.Origins, ","))
		}
		return nil
	}
	return fmt.Errorf("site: unknown subcommand %q", args[0])
}

func migrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	_, db, err := load(fs, args)
	if err != nil {
		return err
	}
	fmt.Println("migrations applied")
	return db.Close()
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func loadIPData(st *ipintel.Store, cfg *config.Config, log *slog.Logger) {
	db, err := ipintel.Load(cfg.IPDataDir())
	if err != nil {
		log.Error("ipdata load", "err", err)
		return
	}
	st.Set(db)
	c := db.Counts()
	if c["v4"] == 0 {
		log.Warn("no IP intelligence loaded; network signals are off until `doorkeep ipdata update` runs", "dir", cfg.IPDataDir())
		return
	}
	log.Info("ipdata loaded", "v4_ranges", c["v4"], "v6_ranges", c["v6"], "tor", c["tor"], "drop", c["drop"], "sources", db.Sources)
}

// ipdataRefresher downloads fresh data weekly (if enabled) and reloads.
func ipdataRefresher(ctx context.Context, st *ipintel.Store, cfg *config.Config, log *slog.Logger) {
	stale := func() bool {
		fi, err := os.Stat(filepath.Join(cfg.IPDataDir(), ipintel.FileASN))
		return err != nil || time.Since(fi.ModTime()) > 7*24*time.Hour
	}
	for {
		if cfg.IPDataAutoUpdate && stale() {
			uctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			err := ipintel.Update(uctx, cfg.IPDataDir(), nil)
			cancel()
			if err != nil {
				log.Warn("ipdata update incomplete", "err", err)
			}
			loadIPData(st, cfg, log)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(6 * time.Hour):
		}
	}
}

func ipdata(args []string) error {
	if len(args) == 0 || args[0] != "update" {
		return errors.New("ipdata: expected update")
	}
	fs := flag.NewFlagSet("ipdata update", flag.ExitOnError)
	cfgPath := fs.String("config", os.Getenv("DOORKEEP_CONFIG"), "path to config YAML")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	start := time.Now()
	err = ipintel.Update(context.Background(), cfg.IPDataDir(), nil)
	db, lerr := ipintel.Load(cfg.IPDataDir())
	if lerr == nil {
		c := db.Counts()
		fmt.Printf("ipdata in %s: %d v4 ranges, %d v6 ranges, %d Tor exits, %d DROP prefixes (%s)\n",
			cfg.IPDataDir(), c["v4"], c["v6"], c["tor"], c["drop"], time.Since(start).Round(time.Millisecond))
		fmt.Println("sources:", strings.Join(db.Sources, "; "))
	}
	return err
}

func tlsConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.AutocertDomains...),
		Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, "acme")),
		Email:      cfg.AutocertEmail,
	}
	t := m.TLSConfig() // includes acme-tls/1 for TLS-ALPN-01 on this listener
	t.MinVersion = tls.VersionTLS12
	t.NextProtos = append([]string{"h2", "http/1.1"}, t.NextProtos...)
	return t, nil
}

// modelSaver persists model state every five minutes.
func modelSaver(ctx context.Context, srv *api.Server, db store.Store, log *slog.Logger) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := db.SaveModels(ctx, srv.Models.Snapshot(), time.Now()); err != nil {
				log.Error("model save", "err", err)
			}
		}
	}
}

// rollup keeps hourly aggregates current (re-running recent hours so late
// labels and verifications are included).
func rollup(ctx context.Context, srv *api.Server, log *slog.Logger) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		if err := srv.Rollup(ctx, 3); err != nil && ctx.Err() == nil {
			log.Error("rollup", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func admin(args []string) error {
	if len(args) == 0 {
		return errors.New("admin: expected create or token")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("admin create", flag.ExitOnError)
		user := fs.String("user", "", "admin user name")
		_, db, err := load(fs, args[1:])
		if err != nil {
			return err
		}
		defer db.Close()
		if *user == "" {
			return errors.New("admin create: --user is required")
		}
		fmt.Fprint(os.Stderr, "Password (min 12 characters), then Enter: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		hash, err := api.HashPassword(strings.TrimRight(line, "\r\n"))
		if err != nil {
			return err
		}
		if err := db.CreateAdmin(context.Background(), *user, hash, time.Now()); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\nAdmin %q saved. Open /admin/ to sign in.\n", *user)
		return nil
	case "token":
		fs := flag.NewFlagSet("admin token", flag.ExitOnError)
		name := fs.String("name", "", "label for the token, e.g. terraform")
		_, db, err := load(fs, args[1:])
		if err != nil {
			return err
		}
		defer db.Close()
		if *name == "" {
			return errors.New("admin token: --name is required")
		}
		tok, err := api.NewAdminToken(context.Background(), db, *name, time.Now())
		if err != nil {
			return err
		}
		fmt.Println(tok)
		return nil
	}
	return fmt.Errorf("admin: unknown subcommand %q", args[0])
}
