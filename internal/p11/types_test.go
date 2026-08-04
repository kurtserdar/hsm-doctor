package p11

import "testing"

func TestSessionCapacity(t *testing.T) {
	cases := []struct {
		name      string
		max, cur  uint
		wantFree  uint
		wantKnown bool
	}{
		{"headroom", 100, 40, 60, true},
		{"full", 10, 10, 0, true},
		{"over", 10, 12, 0, true},
		{"unlimited-max-zero", 0, 5, 0, false},
		{"unavailable-max", sessionInfoUnavailable, 5, 0, false},
		{"unavailable-count", 100, sessionInfoUnavailable, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ti := &TokenInfo{MaxSessionCount: c.max, SessionCount: c.cur}
			free, known := ti.SessionCapacity()
			if free != c.wantFree || known != c.wantKnown {
				t.Errorf("got free=%d known=%v, want free=%d known=%v", free, known, c.wantFree, c.wantKnown)
			}
		})
	}
}
