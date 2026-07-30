package store

import (
	"encoding/json"
	"testing"
	"time"
)

// freshFunc opens a Store on a clean, empty database and returns it together
// with a reopen function that connects a new Store to the SAME database
// without wiping it (for the persistence check).
type freshFunc func(t *testing.T) (s Store, reopen func() Store)

// runConformance exercises the full Store contract against any backend.
func runConformance(t *testing.T, fresh freshFunc) {
	newDB := func(t *testing.T) Store {
		s, _ := fresh(t)
		return s
	}

	t.Run("UpsertHSMIsIdempotent", func(t *testing.T) {
		db := newDB(t)
		id1, err := db.UpsertHSM(&HSM{Serial: "S1", Label: "PROD", Source: "local", Firmware: "7.8.1"})
		if err != nil {
			t.Fatalf("first upsert: %v", err)
		}
		id2, err := db.UpsertHSM(&HSM{Serial: "S1", Label: "PROD", Source: "local", Firmware: "7.8.2"})
		if err != nil {
			t.Fatalf("second upsert: %v", err)
		}
		if id1 != id2 {
			t.Errorf("upsert created a duplicate: %d != %d", id1, id2)
		}
		// Same serial, different source is a distinct row.
		id3, err := db.UpsertHSM(&HSM{Serial: "S1", Label: "PROD", Source: "agent-1"})
		if err != nil {
			t.Fatalf("third upsert: %v", err)
		}
		if id3 == id1 {
			t.Error("different source should create a distinct HSM row")
		}
		h, err := db.GetHSM(id1)
		if err != nil || h == nil {
			t.Fatalf("GetHSM: %v, %v", h, err)
		}
		if h.Firmware != "7.8.2" {
			t.Errorf("firmware not updated: %s", h.Firmware)
		}
		if h.FirstSeen.IsZero() || h.LastSeen.IsZero() {
			t.Error("timestamps not set")
		}
	})

	t.Run("ScanHistoryAndLatest", func(t *testing.T) {
		db := newDB(t)
		hsmID, err := db.UpsertHSM(&HSM{Serial: "S1", Source: "local"})
		if err != nil {
			t.Fatal(err)
		}
		base := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
		for i, score := range []int{90, 75, 60} {
			_, err := db.InsertScan(&ScanRecord{
				HSMID: hsmID, TakenAt: base.Add(time.Duration(i) * time.Hour),
				Score: score, High: i,
				Report: json.RawMessage(`{"score":` + string(rune('0'+score/10)) + `}`),
			})
			if err != nil {
				t.Fatalf("InsertScan %d: %v", i, err)
			}
		}
		latest, err := db.LatestScan(hsmID)
		if err != nil {
			t.Fatalf("LatestScan: %v", err)
		}
		if latest == nil || latest.Score != 60 || len(latest.Report) == 0 {
			t.Errorf("latest scan wrong: %+v", latest)
		}
		scans, err := db.ListScans(hsmID, 10)
		if err != nil {
			t.Fatalf("ListScans: %v", err)
		}
		if len(scans) != 3 || scans[0].Score != 60 || scans[2].Score != 90 {
			t.Errorf("scan list wrong order or count: %+v", scans)
		}
		for _, sc := range scans {
			if len(sc.Report) != 0 {
				t.Error("summaries must not carry report blobs")
			}
		}
		full, err := db.GetScan(hsmID, scans[0].ID)
		if err != nil || full == nil || len(full.Report) == 0 {
			t.Fatalf("GetScan should include the report blob: %v, %v", full, err)
		}
		hsms, err := db.ListHSMs()
		if err != nil {
			t.Fatalf("ListHSMs: %v", err)
		}
		if len(hsms) != 1 || hsms[0].LatestScore == nil || *hsms[0].LatestScore != 60 {
			t.Errorf("fleet summary wrong: %+v", hsms)
		}
	})

	t.Run("DriftEvents", func(t *testing.T) {
		db := newDB(t)
		hsmID, err := db.UpsertHSM(&HSM{Serial: "S1", Source: "local"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.InsertDriftEvent(&DriftEvent{
			HSMID: hsmID, DetectedAt: time.Now(), OldScanID: 1, NewScanID: 2,
			Changes: 3, Diff: json.RawMessage(`{"objects_added":["k1"]}`),
		}); err != nil {
			t.Fatalf("InsertDriftEvent: %v", err)
		}
		events, err := db.ListDriftEvents(hsmID, 10)
		if err != nil {
			t.Fatalf("ListDriftEvents: %v", err)
		}
		if len(events) != 1 || events[0].Changes != 3 {
			t.Errorf("drift events wrong: %+v", events)
		}
		var diff map[string]any
		if err := json.Unmarshal(events[0].Diff, &diff); err != nil {
			t.Errorf("diff blob not valid JSON: %v", err)
		}
	})

	t.Run("Agents", func(t *testing.T) {
		db := newDB(t)
		id, err := db.UpsertAgent("edge-01", "hash-aaa")
		if err != nil {
			t.Fatalf("UpsertAgent: %v", err)
		}
		// Re-enroll rotates the token hash on the same row.
		id2, err := db.UpsertAgent("edge-01", "hash-bbb")
		if err != nil || id2 != id {
			t.Fatalf("re-enroll should keep the row: id=%d id2=%d err=%v", id, id2, err)
		}
		if a, err := db.GetAgentByTokenHash("hash-aaa"); err != nil || a != nil {
			t.Errorf("rotated-out hash must not resolve: %v, %v", a, err)
		}
		a, err := db.GetAgentByTokenHash("hash-bbb")
		if err != nil || a == nil || a.Name != "edge-01" {
			t.Fatalf("current hash should resolve: %v, %v", a, err)
		}
		if err := db.TouchAgent(a.ID); err != nil {
			t.Errorf("TouchAgent: %v", err)
		}
		agents, err := db.ListAgents()
		if err != nil || len(agents) != 1 {
			t.Errorf("ListAgents: %v, %v", agents, err)
		}
	})

	t.Run("GetHSMNotFound", func(t *testing.T) {
		db := newDB(t)
		h, err := db.GetHSM(999)
		if err != nil || h != nil {
			t.Errorf("missing HSM should return nil, nil; got %v, %v", h, err)
		}
	})

	t.Run("PersistenceAcrossReopen", func(t *testing.T) {
		s, reopen := fresh(t)
		if _, err := s.UpsertHSM(&HSM{Serial: "S1", Source: "local"}); err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
		s2 := reopen()
		defer func() { _ = s2.Close() }()
		hsms, err := s2.ListHSMs()
		if err != nil || len(hsms) != 1 {
			t.Errorf("data lost after reopen: %v, %v", hsms, err)
		}
	})
}
