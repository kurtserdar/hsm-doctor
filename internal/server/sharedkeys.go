package server

import (
	"encoding/json"
	"net/http"

	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/kurtserdar/hsm-doctor/internal/sharedkeys"
)

// SharedKeys correlates the latest scan of every fleet HSM and returns the
// private keys whose fingerprint appears on more than one HSM. It reads only
// stored public metadata; no private key material is involved.
func (s *Server) SharedKeys() ([]sharedkeys.SharedKey, error) {
	if s.store == nil {
		return nil, nil
	}
	hsms, err := s.store.ListHSMs()
	if err != nil {
		return nil, err
	}
	var sources []sharedkeys.Source
	for _, h := range hsms {
		rec, err := s.store.LatestScan(h.ID)
		if err != nil {
			return nil, err
		}
		if rec == nil || len(rec.Report) == 0 {
			continue
		}
		var rep report.Report
		if err := json.Unmarshal(rec.Report, &rep); err != nil {
			continue
		}
		if rep.Inventory == nil {
			continue
		}
		sources = append(sources, sharedkeys.Source{
			HSMID:     h.ID,
			HSMLabel:  h.Label,
			Serial:    h.Serial,
			Source:    h.Source,
			Inventory: rep.Inventory,
		})
	}
	return sharedkeys.Detect(sources), nil
}

func (s *Server) handleSharedKeys(w http.ResponseWriter, r *http.Request) {
	if s.requireStore(w) == nil {
		return
	}
	keys, err := s.SharedKeys()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if keys == nil {
		keys = []sharedkeys.SharedKey{}
	}
	writeJSON(w, http.StatusOK, keys)
}

// refreshSharedKeysMetric recomputes the fleet-wide shared-key count and
// updates the gauge. Best-effort: metric staleness must never break ingest.
func (s *Server) refreshSharedKeysMetric() {
	if s.store == nil || s.metrics == nil {
		return
	}
	keys, err := s.SharedKeys()
	if err != nil {
		return
	}
	s.metrics.sharedPrivateKeys.Set(float64(len(keys)))
}
