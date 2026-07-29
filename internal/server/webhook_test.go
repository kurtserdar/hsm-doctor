package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/store"
)

func TestWebhookDeliversWithRetry(t *testing.T) {
	var attempts atomic.Int32
	received := make(chan []byte, 1)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			// First attempt fails; delivery must be retried.
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Header.Get("X-HSMDoctor-Event") != "drift_detected" {
			t.Errorf("missing event header")
		}
		body, _ := io.ReadAll(r.Body)
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	w := newWebhook(ts.URL)
	w.backoff = 10 * time.Millisecond

	w.notifyDrift(
		&store.HSM{ID: 7, Serial: "S1", Label: "PROD", Source: "edge-01"},
		&store.DriftEvent{
			DetectedAt: time.Now().UTC(),
			Changes:    2,
			Diff:       json.RawMessage(`{"objects_added":["private-key k1"]}`),
		},
	)

	select {
	case body := <-received:
		var payload struct {
			Event   string `json:"event"`
			Changes int    `json:"changes"`
			HSM     struct {
				Label  string `json:"label"`
				Source string `json:"source"`
			} `json:"hsm"`
			Diff map[string]any `json:"diff"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("payload not valid JSON: %v", err)
		}
		if payload.Event != "drift_detected" || payload.Changes != 2 ||
			payload.HSM.Label != "PROD" || payload.HSM.Source != "edge-01" {
			t.Errorf("payload wrong: %+v", payload)
		}
		if payload.Diff["objects_added"] == nil {
			t.Error("payload missing diff details")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook was not delivered within timeout")
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("want 2 delivery attempts, got %d", got)
	}
}

func TestWebhookGivesUpAfterMaxAttempts(t *testing.T) {
	var attempts atomic.Int32
	done := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 3 {
			defer close(done)
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer ts.Close()

	w := newWebhook(ts.URL)
	w.backoff = time.Millisecond
	w.notifyDrift(&store.HSM{ID: 1}, &store.DriftEvent{Diff: json.RawMessage(`{}`)})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("webhook did not exhaust its attempts")
	}
	// Give the goroutine a beat to finish; it must stop at 3 attempts.
	time.Sleep(50 * time.Millisecond)
	if got := attempts.Load(); got != 3 {
		t.Errorf("want exactly 3 attempts, got %d", got)
	}
}
