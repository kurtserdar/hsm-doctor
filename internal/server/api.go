package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/bench"
	"github.com/kurtserdar/hsm-doctor/internal/certmon"
	"github.com/kurtserdar/hsm-doctor/internal/funtest"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/kurtserdar/hsm-doctor/internal/snapshot"
)

func (s *Server) registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/info", s.handleInfo)
	mux.HandleFunc("GET /api/v1/discover", s.handleDiscover)
	mux.HandleFunc("GET /api/v1/slots/{slot}/scan", s.handleScan)
	mux.HandleFunc("GET /api/v1/slots/{slot}/certs", s.handleCerts)
	mux.HandleFunc("GET /api/v1/slots/{slot}/snapshot", s.handleSnapshot)
	mux.HandleFunc("POST /api/v1/slots/{slot}/test", s.handleTest)
	mux.HandleFunc("POST /api/v1/slots/{slot}/bench", s.handleBench)
	mux.HandleFunc("POST /api/v1/diff", s.handleDiff)
}

// writeJSON sends v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// writeError sends a JSON error envelope. PKCS#11 error names are already
// embedded in the messages by the p11 wrapper.
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// slotFromPath parses the {slot} path segment.
func slotFromPath(r *http.Request) (uint, error) {
	raw := r.PathValue("slot")
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid slot id %q", raw)
	}
	return uint(id), nil
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	info, err := s.client.Info()
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tool":    "hsmdoctor",
		"version": s.version,
		"module":  info,
	})
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	info, err := s.client.Info()
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	slots, err := s.client.Slots()
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	out := map[string]any{"module": info, "slots": slots}
	if r.URL.Query().Get("mechanisms") == "true" {
		mechs := map[uint][]p11.Mechanism{}
		for _, sl := range slots {
			if !sl.TokenPresent {
				continue
			}
			m, err := s.client.Mechanisms(sl.ID)
			if err != nil {
				writeError(w, http.StatusBadGateway, err)
				return
			}
			mechs[sl.ID] = m
		}
		out["mechanisms"] = mechs
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	slot, err := slotFromPath(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	inv, err := inventory.Collect(s.client, slot, s.pin)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	res := policy.Evaluate(inv, s.rules, time.Now())
	rep := report.New(s.version, inv, res)
	s.persistScan(rep, "local")
	s.metrics.observeScan(rep)
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	slot, err := slotFromPath(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	warnDays := 30
	if v := r.URL.Query().Get("warn_days"); v != "" {
		if warnDays, err = strconv.Atoi(v); err != nil || warnDays < 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid warn_days %q", v))
			return
		}
	}
	inv, err := inventory.Collect(s.client, slot, s.pin)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	entries := certmon.Classify(inv, time.Now(), warnDays)
	ok, expiring, expired := certmon.Counts(entries)
	writeJSON(w, http.StatusOK, map[string]any{
		"certificates": entries,
		"counts":       map[string]int{"ok": ok, "expiring": expiring, "expired": expired},
		"warn_days":    warnDays,
	})
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	slot, err := slotFromPath(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	inv, err := inventory.Collect(s.client, slot, s.pin)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot.New(s.version, inv))
}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	slot, err := slotFromPath(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var body struct {
		Profile string `json:"profile"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Profile == "" {
		body.Profile = "sign-verify"
	}
	res, err := funtest.Run(s.client, slot, s.pin, body.Profile)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleBench(w http.ResponseWriter, r *http.Request) {
	slot, err := slotFromPath(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var body struct {
		DurationMS int `json:"duration_ms"`
		MaxOps     int `json:"max_ops"`
		Sessions   int `json:"sessions"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	opts := bench.Options{
		Duration: time.Duration(body.DurationMS) * time.Millisecond,
		MaxOps:   body.MaxOps,
		Sessions: body.Sessions,
	}
	res, err := bench.Run(s.client, slot, s.pin, opts)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Old *snapshot.Snapshot `json:"old"`
		New *snapshot.Snapshot `json:"new"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Old == nil || body.Old.Inventory == nil || body.New == nil || body.New.Inventory == nil {
		writeError(w, http.StatusBadRequest, errors.New("both old and new snapshots with inventories are required"))
		return
	}
	writeJSON(w, http.StatusOK, snapshot.Compare(body.Old.Inventory, body.New.Inventory))
}

// decodeBody parses a JSON request body; an empty body yields zero values.
func decodeBody(r *http.Request, v any) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 16<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}
