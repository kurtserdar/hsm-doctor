// Package server exposes HSM Doctor's functionality as a local REST API and
// serves the embedded web interface.
//
// Security model: the server is designed for local, single-operator use.
// It binds to loopback by default, the PIN is provided once at startup
// (never per request, never logged) and no CORS headers are emitted, so
// browser pages from other origins cannot call the API.
package server

import (
	"log"
	"net/http"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/store"
)

// Server holds the shared state of one running instance.
type Server struct {
	client  *p11.Client
	pin     string
	rules   *policy.Config
	version string
	// store persists scan history and drift events; nil disables persistence.
	store store.Store
}

// New loads the PKCS#11 module and prepares the server. A nil store
// disables scan history and drift recording.
func New(modulePath, pin string, rules *policy.Config, version string, st store.Store) (*Server, error) {
	client, err := p11.Open(modulePath)
	if err != nil {
		return nil, err
	}
	return &Server{client: client, pin: pin, rules: rules, version: version, store: st}, nil
}

// Close releases the PKCS#11 module and the store.
func (s *Server) Close() {
	s.client.Close()
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
	registerUI(mux)
	return logRequests(mux)
}

// ListenAndServe runs the server until the process exits.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("hsmdoctor serve listening on http://%s", addr)
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
