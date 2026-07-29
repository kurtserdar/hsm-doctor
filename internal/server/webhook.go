package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/store"
)

// webhook delivers drift notifications to an external HTTP endpoint
// (Slack/Teams relays, SIEM collectors, automation hooks).
type webhook struct {
	url   string
	httpc *http.Client
	// retries and backoff are fixed; a failed delivery is logged, never
	// blocks scanning and never crashes the server.
	attempts int
	backoff  time.Duration
}

func newWebhook(url string) *webhook {
	return &webhook{
		url:      url,
		httpc:    &http.Client{Timeout: 10 * time.Second},
		attempts: 3,
		backoff:  2 * time.Second,
	}
}

// driftPayload is the JSON body POSTed on drift events.
type driftPayload struct {
	Event      string          `json:"event"`
	HSM        driftHSM        `json:"hsm"`
	DetectedAt time.Time       `json:"detected_at"`
	Changes    int             `json:"changes"`
	Diff       json.RawMessage `json:"diff"`
}

type driftHSM struct {
	ID     int64  `json:"id"`
	Serial string `json:"serial"`
	Label  string `json:"label"`
	Source string `json:"source"`
}

// notifyDrift delivers the event asynchronously.
func (w *webhook) notifyDrift(h *store.HSM, e *store.DriftEvent) {
	payload := driftPayload{
		Event: "drift_detected",
		HSM: driftHSM{
			ID: h.ID, Serial: h.Serial, Label: h.Label, Source: h.Source,
		},
		DetectedAt: e.DetectedAt,
		Changes:    e.Changes,
		Diff:       e.Diff,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("warning: encoding webhook payload: %v", err)
		return
	}
	go w.deliver(body)
}

func (w *webhook) deliver(body []byte) {
	var lastErr error
	for attempt := 1; attempt <= w.attempts; attempt++ {
		if attempt > 1 {
			time.Sleep(w.backoff * time.Duration(attempt-1))
		}
		req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(body))
		if err != nil {
			log.Printf("warning: building webhook request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-HSMDoctor-Event", "drift_detected")

		resp, err := w.httpc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		lastErr = fmt.Errorf("webhook endpoint returned %d", resp.StatusCode)
	}
	log.Printf("warning: webhook delivery failed after %d attempts: %v", w.attempts, lastErr)
}
