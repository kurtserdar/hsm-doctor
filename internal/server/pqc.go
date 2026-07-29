package server

import (
	"net/http"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/pqc"
)

// pqcResponse mirrors the CLI pqc report for the REST API.
type pqcResponse struct {
	Detection *pqc.Detection   `json:"detection"`
	Exposure  *pqc.Exposure    `json:"exposure"`
	Host      *pqc.HostOpenSSL `json:"host_openssl,omitempty"`
	Tests     []pqc.SetResult  `json:"tests,omitempty"`
}

// handlePQC assesses PQC readiness of one slot. Query parameters:
// test=true runs functional probes, host=true adds the server-host
// OpenSSL check.
func (s *Server) handlePQC(w http.ResponseWriter, r *http.Request) {
	if !s.requireClient(w) {
		return
	}
	slot, err := slotFromPath(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	info, err := s.client.Info()
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	mechs, err := s.client.Mechanisms(slot)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	det := pqc.Detect(mechs)
	det.CryptokiVersion = info.CryptokiVersion

	inv, err := inventory.Collect(s.client, slot, s.pin)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	resp := &pqcResponse{Detection: det, Exposure: pqc.Assess(inv, det)}
	if r.URL.Query().Get("host") == "true" {
		resp.Host = pqc.CheckHostOpenSSL(r.Context())
	}
	if r.URL.Query().Get("test") == "true" {
		if resp.Tests, err = pqc.RunTests(s.client, slot, s.pin, det); err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
