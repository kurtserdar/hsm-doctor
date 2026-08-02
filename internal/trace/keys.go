package trace

import "sort"

// operationInit lists the operation-init functions that carry a key handle in
// their Object field. Counting these tells us which keys were put to work.
var operationInit = map[string]bool{
	"C_SignInit":    true,
	"C_VerifyInit":  true,
	"C_EncryptInit": true,
	"C_DecryptInit": true,
	"C_WrapKey":     true,
	"C_UnwrapKey":   true,
}

// KeyUsage summarizes how one key — named when it could be resolved, otherwise
// an opaque handle — was exercised across a trace.
type KeyUsage struct {
	// Resolved is true when a CKA_LABEL/CKA_ID was recovered for the handle.
	Resolved bool   `json:"resolved"`
	Label    string `json:"label,omitempty"`
	KeyID    string `json:"key_id,omitempty"`
	// Handle is the object handle seen for an unresolved key.
	Handle uint64 `json:"handle,omitempty"`
	// Operations counts each operation-init function against this key.
	Operations map[string]int `json:"operations"`
	// Mechanisms lists the distinct CKM_* mechanisms used with this key.
	Mechanisms []string `json:"mechanisms,omitempty"`
	// Total is the sum of Operations.
	Total int `json:"total"`
}

// KeyUsageReport is the per-key usage summary of a trace. It reflects only what
// the trace observed: a key absent here was simply not used during the trace
// window, which is not proof it is never used.
type KeyUsageReport struct {
	Keys []KeyUsage `json:"keys"`
	// Unresolved is the number of usage records whose handle could not be
	// mapped to a named key (e.g. the key was not located via a
	// find-by-label/id in this trace).
	Unresolved int `json:"unresolved"`
}

type identity struct {
	label string
	keyID string
}

func (i identity) named() bool { return i.label != "" || i.keyID != "" }

type usageAgg struct {
	id     identity
	handle uint64
	ops    map[string]int
	mechs  map[string]bool
}

// KeyUsageOf reconstructs per-key usage from a trace. It ties a
// C_FindObjectsInit template (its CKA_LABEL/CKA_ID) to the handle returned by
// the following C_FindObjects, then attributes each later operation-init call
// on that handle to the named key. Operations on handles never resolved this
// way are grouped as unresolved.
func KeyUsageOf(events []Event) *KeyUsageReport {
	// Per session: the identity of the most recent find, and the handle→identity
	// bindings that finds have produced.
	pending := map[uint64]identity{}
	bindings := map[uint64]map[uint64]identity{}

	// Aggregate usage. Resolved keys are keyed by identity; unresolved usage is
	// keyed by handle so distinct handles stay distinct.
	byIdentity := map[identity]*usageAgg{}
	byHandle := map[uint64]*usageAgg{}

	for _, e := range events {
		sess := uint64(0)
		if e.Session != nil {
			sess = *e.Session
		}
		switch {
		case e.Function == "C_FindObjectsInit":
			pending[sess] = identity{label: e.Label, keyID: e.KeyID}
		case e.Function == "C_FindObjects":
			if e.Object == nil {
				continue
			}
			id := pending[sess]
			if !id.named() {
				continue
			}
			if bindings[sess] == nil {
				bindings[sess] = map[uint64]identity{}
			}
			bindings[sess][*e.Object] = id
		case operationInit[e.Function]:
			if e.Object == nil {
				continue
			}
			handle := *e.Object
			id, ok := bindings[sess][handle]
			var u *usageAgg
			if ok && id.named() {
				u = byIdentity[id]
				if u == nil {
					u = &usageAgg{id: id, ops: map[string]int{}, mechs: map[string]bool{}}
					byIdentity[id] = u
				}
			} else {
				u = byHandle[handle]
				if u == nil {
					u = &usageAgg{handle: handle, ops: map[string]int{}, mechs: map[string]bool{}}
					byHandle[handle] = u
				}
			}
			u.ops[e.Function]++
			if e.Mechanism != "" {
				u.mechs[e.Mechanism] = true
			}
		}
	}

	report := &KeyUsageReport{}
	appendUsage := func(u *usageAgg, resolved bool) {
		ku := KeyUsage{
			Resolved:   resolved,
			Label:      u.id.label,
			KeyID:      u.id.keyID,
			Operations: u.ops,
		}
		if !resolved {
			ku.Handle = u.handle
			report.Unresolved++
		}
		for m := range u.mechs {
			ku.Mechanisms = append(ku.Mechanisms, m)
		}
		sort.Strings(ku.Mechanisms)
		for _, n := range u.ops {
			ku.Total += n
		}
		report.Keys = append(report.Keys, ku)
	}
	for _, u := range byIdentity {
		appendUsage(u, true)
	}
	for _, u := range byHandle {
		appendUsage(u, false)
	}
	// Resolved keys first, then by label, key ID, handle for stable output.
	sort.SliceStable(report.Keys, func(i, j int) bool {
		a, b := report.Keys[i], report.Keys[j]
		if a.Resolved != b.Resolved {
			return a.Resolved
		}
		if a.Label != b.Label {
			return a.Label < b.Label
		}
		if a.KeyID != b.KeyID {
			return a.KeyID < b.KeyID
		}
		return a.Handle < b.Handle
	})
	return report
}
