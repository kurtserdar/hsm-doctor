package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/certmon"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/notify"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/regression"
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
	mux.HandleFunc("GET /api/v1/hsms/{id}/regressions", s.handleHSMRegressions)
	mux.HandleFunc("GET /api/v1/shared-keys", s.handleSharedKeys)
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

func (s *Server) handleHSMRegressions(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	id, err := idFromPath(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	events, err := st.ListRegressionEvents(id, limitFromQuery(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if events == nil {
		events = []store.RegressionEvent{}
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

	s.notifyCertExpiry(hsmID, inv)

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

	// A new inventory may change the fleet-wide shared-key picture.
	s.refreshSharedKeysMetric()

	if prev == nil {
		return
	}
	var prevRep report.Report
	if err := json.Unmarshal(prev.Report, &prevRep); err != nil || prevRep.Inventory == nil {
		log.Printf("warning: previous report unreadable, skipping drift check")
		return
	}

	// Posture regression is independent of inventory drift, so check it first.
	s.checkRegression(hsmID, t, source, prev, newID, rep, &prevRep)

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
	if s.notifier != nil {
		s.notifier.NotifyDrift(notify.DriftInfo{
			HSMID: hsmID, Serial: t.SerialNumber, Label: t.Label, Source: source,
			Changes: d.Count(), Summary: driftSummary(d),
		})
	}
}

// checkRegression compares the new scan's posture to the previous scan and,
// when it worsened (score drop or a new critical/high finding), records a
// regression event and fires the webhook, e-mail and metric. Storage or
// delivery problems are logged, never surfaced.
func (s *Server) checkRegression(hsmID int64, t *p11.TokenInfo, source string, prev *store.ScanRecord, newID int64, rep, prevRep *report.Report) {
	reg := regression.Detect(prev.Score, rep.Score, prevRep.Findings, rep.Findings, 0)
	if reg == nil {
		return
	}
	detail, err := json.Marshal(reg)
	if err != nil {
		log.Printf("warning: encoding regression detail: %v", err)
		return
	}
	event := &store.RegressionEvent{
		HSMID:      hsmID,
		DetectedAt: time.Now().UTC(),
		OldScanID:  prev.ID,
		NewScanID:  newID,
		ScoreDelta: reg.ScoreDelta,
		Detail:     detail,
	}
	if _, err := s.store.InsertRegressionEvent(event); err != nil {
		log.Printf("warning: persisting regression event: %v", err)
		return
	}
	log.Printf("posture regression on %s (score delta %+d, %d new severe finding(s))", t.Label, reg.ScoreDelta, len(reg.NewSevere))
	s.metrics.observeRegression(t.SerialNumber, t.Label)
	if s.webhook != nil {
		s.webhook.notifyRegression(&store.HSM{
			ID: hsmID, Serial: t.SerialNumber, Label: t.Label, Source: source,
		}, event)
	}
	if s.notifier != nil {
		s.notifier.NotifyRegression(notify.RegressionInfo{
			HSMID: hsmID, Serial: t.SerialNumber, Label: t.Label, Source: source,
			ScoreDelta: reg.ScoreDelta, Reasons: reg.Reasons,
		})
	}
}

// notifyCertExpiry classifies the token's certificates and asks the notifier
// to e-mail reminders for those within a warning window (deduplicated per
// certificate and threshold by the store ledger).
func (s *Server) notifyCertExpiry(hsmID int64, inv *inventory.Inventory) {
	if s.notifier == nil {
		return
	}
	entries := certmon.Classify(inv, time.Now(), s.notifier.MaxWarnDays())
	var certs []notify.CertInfo
	for _, e := range entries {
		if e.Status == certmon.StatusOK {
			continue
		}
		certs = append(certs, notify.CertInfo{
			Label: e.Label, Subject: e.Subject, DaysLeft: e.DaysLeft, NotAfter: e.NotAfter,
		})
	}
	if len(certs) > 0 {
		s.notifier.NotifyCertExpiry(hsmID, inv.Slot.TokenLabel(), certs)
	}
}

// driftSummary renders a short, human-readable list of the drift changes for
// an e-mail body.
func driftSummary(d *snapshot.Diff) []string {
	var out []string
	for _, c := range d.TokenChanges {
		out = append(out, fmt.Sprintf("%s changed %s -> %s", c.Field, c.Old, c.New))
	}
	for _, m := range d.MechanismsAdded {
		out = append(out, "mechanism "+m+" now available")
	}
	for _, m := range d.MechanismsRemoved {
		out = append(out, "mechanism "+m+" no longer available")
	}
	for _, o := range d.ObjectsAdded {
		out = append(out, o+" added")
	}
	for _, o := range d.ObjectsRemoved {
		out = append(out, o+" removed")
	}
	for _, c := range d.ObjectChanges {
		out = append(out, fmt.Sprintf("%s: %s changed %s -> %s", c.Object, c.Field, c.Old, c.New))
	}
	return out
}
