package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestUpsertHSMIsIdempotent(t *testing.T) {
	db := openTestDB(t)

	id1, err := db.UpsertHSM(&HSM{Serial: "S1", Label: "PROD", Source: "local", Firmware: "7.8.1"})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	// Same serial+source with changed firmware must update, not duplicate.
	id2, err := db.UpsertHSM(&HSM{Serial: "S1", Label: "PROD", Source: "local", Firmware: "7.8.2"})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if id1 != id2 {
		t.Errorf("upsert created a duplicate: %d != %d", id1, id2)
	}

	// Same serial from a different source is a separate row (two agents may
	// see the same HA-replicated token; that ambiguity is resolved later).
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
}

func TestScanHistoryAndLatest(t *testing.T) {
	db := openTestDB(t)
	hsmID, err := db.UpsertHSM(&HSM{Serial: "S1", Source: "local"})
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	for i, score := range []int{90, 75, 60} {
		_, err := db.InsertScan(&ScanRecord{
			HSMID:   hsmID,
			TakenAt: base.Add(time.Duration(i) * time.Hour),
			Score:   score,
			High:    i,
			Report:  json.RawMessage(`{"score":` + string(rune('0'+score/10)) + `}`),
		})
		if err != nil {
			t.Fatalf("InsertScan %d: %v", i, err)
		}
	}

	latest, err := db.LatestScan(hsmID)
	if err != nil {
		t.Fatalf("LatestScan: %v", err)
	}
	if latest == nil || latest.Score != 60 {
		t.Errorf("latest scan wrong: %+v", latest)
	}
	if len(latest.Report) == 0 {
		t.Error("latest scan should include the report blob")
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
	if err != nil || full == nil {
		t.Fatalf("GetScan: %v", err)
	}
	if len(full.Report) == 0 {
		t.Error("GetScan should include the report blob")
	}

	// Fleet listing carries the latest score.
	hsms, err := db.ListHSMs()
	if err != nil {
		t.Fatalf("ListHSMs: %v", err)
	}
	if len(hsms) != 1 || hsms[0].LatestScore == nil || *hsms[0].LatestScore != 60 {
		t.Errorf("fleet summary wrong: %+v", hsms)
	}
}

func TestDriftEvents(t *testing.T) {
	db := openTestDB(t)
	hsmID, err := db.UpsertHSM(&HSM{Serial: "S1", Source: "local"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.InsertDriftEvent(&DriftEvent{
		HSMID: hsmID, DetectedAt: time.Now(), OldScanID: 1, NewScanID: 2,
		Changes: 3, Diff: json.RawMessage(`{"objects_added":["k1"]}`),
	})
	if err != nil {
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
}

func TestGetHSMNotFound(t *testing.T) {
	db := openTestDB(t)
	h, err := db.GetHSM(999)
	if err != nil || h != nil {
		t.Errorf("missing HSM should return nil, nil; got %v, %v", h, err)
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db1, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := db1.UpsertHSM(&HSM{Serial: "S1", Source: "local"}); err != nil {
		t.Fatal(err)
	}
	_ = db1.Close()

	// Reopening must not re-apply migrations or lose data.
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer db2.Close()
	hsms, err := db2.ListHSMs()
	if err != nil || len(hsms) != 1 {
		t.Errorf("data lost after reopen: %v, %v", hsms, err)
	}
}
