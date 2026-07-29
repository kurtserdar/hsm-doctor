package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/report"
)

func (s *Server) registerIngestAPI(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/ingest/enroll", s.handleEnroll)
	mux.HandleFunc("POST /api/v1/ingest/report", s.handleIngestReport)
}

// hashToken derives the storable form of a bearer token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// handleEnroll exchanges the shared enrollment token for a permanent,
// per-agent bearer token. Re-enrolling an existing agent name rotates its
// token.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	if s.enrollToken == "" {
		writeError(w, http.StatusForbidden, errors.New("agent enrollment is disabled on this server"))
		return
	}
	var body struct {
		Name        string `json:"name"`
		EnrollToken string `json:"enroll_token"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, errors.New("agent name is required"))
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.EnrollToken), []byte(s.enrollToken)) != 1 {
		writeError(w, http.StatusUnauthorized, errors.New("invalid enrollment token"))
		return
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	token := hex.EncodeToString(raw)
	if _, err := st.UpsertAgent(body.Name, hashToken(token)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	log.Printf("agent %q enrolled", body.Name)
	writeJSON(w, http.StatusOK, map[string]string{
		"name":        body.Name,
		"agent_token": token,
	})
}

// handleIngestReport accepts a scan report pushed by an enrolled agent.
func (s *Server) handleIngestReport(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	auth := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || token == "" {
		writeError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
		return
	}
	agent, err := st.GetAgentByTokenHash(hashToken(token))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if agent == nil {
		writeError(w, http.StatusUnauthorized, errors.New("unknown agent token"))
		return
	}

	// Reports are decoded leniently: unknown fields from a newer agent
	// version must not break ingestion.
	var rep report.Report
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20))
	if err := dec.Decode(&rep); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid report body: %w", err))
		return
	}
	if rep.Inventory == nil {
		writeError(w, http.StatusBadRequest, errors.New("report has no inventory"))
		return
	}

	s.persistScan(&rep, agent.Name)
	s.metrics.observeScan(&rep)
	if err := st.TouchAgent(agent.ID); err != nil {
		log.Printf("warning: touching agent %q: %v", agent.Name, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"stored": true, "agent": agent.Name})
}
