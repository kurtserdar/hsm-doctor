// Package server exposes HSM Doctor's functionality as a local REST API and
// serves the embedded web interface.
//
// Security model: the server is designed for local, single-operator use.
// It binds to loopback by default, the PIN is provided once at startup
// (never per request, never logged) and no CORS headers are emitted, so
// browser pages from other origins cannot call the API.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/notify"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/store"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

// Server holds the shared state of one running instance.
type Server struct {
	// client is the local PKCS#11 module; nil in central mode, where all
	// scan data arrives through the ingest API.
	client  *p11.Client
	pin     string
	rules   *policy.Config
	version string
	// store persists scan history and drift events; nil disables persistence.
	store   store.Store
	metrics *metrics
	// enrollToken enables agent enrollment when non-empty (central mode).
	enrollToken string
	// auth guards the API when non-nil.
	auth *AuthConfig
	// oidc enables interactive Single Sign-On when non-nil.
	oidc *oidcProvider
	// webhook receives drift notifications when non-nil.
	webhook *webhook
	// notifier sends alert e-mails when non-nil.
	notifier *notify.Notifier
	// vendorCfg enables vendor appliance collection during scans (local
	// mode only).
	vendorCfg *vendor.File
}

// SetAuth enables API authentication. When the config includes an OIDC
// section, it also performs OIDC discovery and enables Single Sign-On;
// discovery failures are returned so startup can fail loudly.
func (s *Server) SetAuth(cfg *AuthConfig) error {
	s.auth = cfg
	if cfg != nil && cfg.OIDC != nil {
		p, err := newOIDCProvider(context.Background(), cfg.OIDC)
		if err != nil {
			return err
		}
		s.oidc = p
	}
	return nil
}

// SetVendorConfig enables vendor appliance collection during scans.
func (s *Server) SetVendorConfig(cfg *vendor.File) {
	s.vendorCfg = cfg
}

// SetWebhook enables drift notifications to the given URL.
func (s *Server) SetWebhook(url string) {
	if url != "" {
		s.webhook = newWebhook(url)
	}
}

// SetNotifier enables e-mail notifications.
func (s *Server) SetNotifier(n *notify.Notifier) {
	s.notifier = n
}

// New loads the PKCS#11 module and prepares a local-mode server. A nil
// store disables scan history and drift recording.
func New(modulePath, pin string, rules *policy.Config, version string, st store.Store) (*Server, error) {
	client, err := p11.Open(modulePath)
	if err != nil {
		return nil, err
	}
	return &Server{
		client: client, pin: pin, rules: rules, version: version,
		store: st, metrics: newMetrics(version),
	}, nil
}

// NewCentral prepares a central-mode server: no local PKCS#11 module, scan
// data is pushed by agents. An empty enrollToken disables new enrollments.
func NewCentral(version string, st store.Store, enrollToken string) *Server {
	return &Server{
		version: version, store: st,
		metrics: newMetrics(version), enrollToken: enrollToken,
	}
}

// Close releases the PKCS#11 module and the store.
func (s *Server) Close() {
	if s.client != nil {
		s.client.Close()
	}
	if s.store != nil {
		if err := s.store.Close(); err != nil {
			log.Printf("warning: closing store: %v", err)
		}
	}
}

// Handler builds the full HTTP handler: API plus embedded UI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerAPI(mux)
	s.registerHistoryAPI(mux)
	s.registerIngestAPI(mux)
	mux.Handle("GET /metrics", s.metrics.handler())
	if s.oidc != nil {
		s.oidc.registerAuth(mux)
	}
	registerUI(mux)
	return logRequests(s.authMiddleware(mux))
}

// errNoLocalModule is returned by local-scan endpoints in central mode.
var errNoLocalModule = errors.New("this server has no local PKCS#11 module (central mode); reports are pushed by agents")

// requireClient guards endpoints that need the local PKCS#11 module.
func (s *Server) requireClient(w http.ResponseWriter) bool {
	if s.client == nil {
		writeError(w, http.StatusServiceUnavailable, errNoLocalModule)
		return false
	}
	return true
}

// TLSOptions configures the server's transport security.
type TLSOptions struct {
	CertFile string
	KeyFile  string
	// ClientCAFile, when set, enables mutual TLS: clients must present a
	// certificate signed by this CA. Requires CertFile and KeyFile.
	ClientCAFile string
}

// enabled reports whether server TLS is configured.
func (o TLSOptions) enabled() bool { return o.CertFile != "" && o.KeyFile != "" }

// ListenAndServe runs the server until the process exits. It speaks TLS when
// TLSOptions has a cert and key, and requires client certificates (mTLS)
// when ClientCAFile is also set.
func (s *Server) ListenAndServe(addr string, opts TLSOptions) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	if opts.ClientCAFile != "" {
		if !opts.enabled() {
			return errors.New("--client-ca requires --tls-cert and --tls-key")
		}
		pool, err := loadCertPool(opts.ClientCAFile)
		if err != nil {
			return err
		}
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientCAs:  pool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
		log.Printf("hsmdoctor listening on https://%s (mutual TLS)", addr)
		return srv.ListenAndServeTLS(opts.CertFile, opts.KeyFile)
	}

	if opts.enabled() {
		log.Printf("hsmdoctor listening on https://%s", addr)
		return srv.ListenAndServeTLS(opts.CertFile, opts.KeyFile)
	}
	log.Printf("hsmdoctor listening on http://%s", addr)
	return srv.ListenAndServe()
}

// loadCertPool reads a PEM file of trusted CA certificates.
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

// logRequests writes one line per request: method, path, status, duration.
// Query strings are deliberately not logged.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	return r.ResponseWriter.Write(b)
}
