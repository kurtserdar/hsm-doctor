// Package server exposes HSM Doctor's functionality as a local REST API and
// serves the embedded web interface.
//
// Security model: the server is designed for local, single-operator use.
// It binds to loopback by default, the PIN is provided once at startup
// (never per request, never logged) and no CORS headers are emitted, so
// browser pages from other origins cannot call the API.
package server

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/store"
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
}

// SetAuth enables API authentication.
func (s *Server) SetAuth(cfg *AuthConfig) {
	s.auth = cfg
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

// ListenAndServe runs the server until the process exits. When certFile
// and keyFile are both set, the server speaks TLS.
func (s *Server) ListenAndServe(addr, certFile, keyFile string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if certFile != "" && keyFile != "" {
		log.Printf("hsmdoctor listening on https://%s", addr)
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
	log.Printf("hsmdoctor listening on http://%s", addr)
	return srv.ListenAndServe()
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
