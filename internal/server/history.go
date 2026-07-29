package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/kurtserdar/hsm-doctor/internal/snapshot"
	"github.com/kurtserdar/hsm-doctor/internal/store"
)

func (s *Server) registerHistoryAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/hsms", s.handleHSMs)
	mux.HandleFunc("GET /api/v1/hsms/{id}", s.handleHSM)
	mux.HandleFunc("GET /api/v1/hsms/{id}/scans", s.handleHSMScans)
	mux.HandleFunc("GET /api/v1/hsms/{id}/scans/{scanID}", s.handleHSMScan)
	mux.HandleFunc("GET /api/v1/hsms/{id}/drift", s.handleHSMDrift)
}

// requireStore returns the store or writes a 503 when persistence is off.
func (s *Server) requireStore(w http.ResponseWriter) store.Store {
	if s.store == nil {
		writeError(w, http.StatusServiceUnavailable,
			errors.New("persistence is disabled (server started with --no-db)"))
		return nil
	}
	return s.store
}

func idFromPath(r *http.Request, segment string) (int64, error) {
	raw := r.PathValue(segment)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid %s %q", segment, raw)
	}
	return id, nil
}

func limitFromQuery(r *http.Request) int {
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 100
}

func (s *Server) handleHSMs(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	hsms, err := st.ListHSMs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if hsms == nil {
		hsms = []store.HSMSummary{}
	}
	writeJSON(w, http.StatusOK, hsms)
}

func (s *Server) handleHSM(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	id, err := idFromPath(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h, err := st.GetHSM(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if h == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("HSM %d not found", id))
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) handleHSMScans(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	id, err := idFromPath(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	scans, err := st.ListScans(id, limitFromQuery(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if scans == nil {
		scans = []store.ScanRecord{}
	}
	writeJSON(w, http.StatusOK, scans)
}

func (s *Server) handleHSMScan(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	id, err := idFromPath(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	scanID, err := idFromPath(r, "scanID")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rec, err := st.GetScan(id, scanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if rec == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("scan %d not found for HSM %d", scanID, id))
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleHSMDrift(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	id, err := idFromPath(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	events, err := st.ListDriftEvents(id, limitFromQuery(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if events == nil {
		events = []store.DriftEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

// persistScan stores a finished scan, updates the HSM row and records a
// drift event when the inventory changed since the previous scan. Storage
// problems are logged, never surfaced to the caller: the scan itself
// succeeded.
func (s *Server) persistScan(rep *report.Report, source string) {
	if s.store == nil {
		return
	}
	inv := rep.Inventory
	if inv == nil || inv.Slot.Token == nil || inv.Slot.Token.SerialNumber == "" {
		log.Printf("warning: scan not persisted: token has no serial number")
		return
	}

	t := inv.Slot.Token
	hsmID, err := s.store.UpsertHSM(&store.HSM{
		Serial:       t.SerialNumber,
		Label:        t.Label,
		Model:        t.Model,
		Manufacturer: t.Manufacturer,
		Firmware:     t.FirmwareVersion,
		ModulePath:   inv.Module.Path,
		SlotID:       inv.Slot.ID,
		Source:       source,
	})
	if err != nil {
		log.Printf("warning: persisting HSM: %v", err)
		return
	}

	prev, err := s.store.LatestScan(hsmID)
	if err != nil {
		log.Printf("warning: loading previous scan: %v", err)
	}

	blob, err := json.Marshal(rep)
	if err != nil {
		log.Printf("warning: encoding report: %v", err)
		return
	}
	rec := &store.ScanRecord{
		HSMID:        hsmID,
		TakenAt:      inv.ScannedAt,
		Score:        rep.Score,
		PrivateKeys:  rep.Counts.PrivateKeys,
		PublicKeys:   rep.Counts.PublicKeys,
		SecretKeys:   rep.Counts.SecretKeys,
		Certificates: rep.Counts.Certificates,
		Report:       blob,
	}
	for _, f := range rep.Findings {
		switch f.Severity {
		case policy.SevCritical:
			rec.Critical++
		case policy.SevHigh:
			rec.High++
		case policy.SevMedium:
			rec.Medium++
		case policy.SevLow:
			rec.Low++
		}
	}
	newID, err := s.store.InsertScan(rec)
	if err != nil {
		log.Printf("warning: persisting scan: %v", err)
		return
	}

	if prev == nil {
		return
	}
	var prevRep report.Report
	if err := json.Unmarshal(prev.Report, &prevRep); err != nil || prevRep.Inventory == nil {
		log.Printf("warning: previous report unreadable, skipping drift check")
		return
	}
	d := snapshot.Compare(prevRep.Inventory, inv)
	if d.Empty() {
		return
	}
	diffBlob, err := json.Marshal(d)
	if err != nil {
		log.Printf("warning: encoding drift diff: %v", err)
		return
	}
	event := &store.DriftEvent{
		HSMID:      hsmID,
		DetectedAt: time.Now().UTC(),
		OldScanID:  prev.ID,
		NewScanID:  newID,
		Changes:    d.Count(),
		Diff:       diffBlob,
	}
	if _, err := s.store.InsertDriftEvent(event); err != nil {
		log.Printf("warning: persisting drift event: %v", err)
		return
	}
	log.Printf("drift detected on %s (%d changes)", t.Label, d.Count())
	if s.webhook != nil {
		s.webhook.notifyDrift(&store.HSM{
			ID: hsmID, Serial: t.SerialNumber, Label: t.Label, Source: source,
		}, event)
	}
}
