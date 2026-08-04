package preflight

import (
	"testing"

	vendor "github.com/kurtserdar/hsm-doctor/internal/vendors"
)

func TestCheckVendorTamperPostpones(t *testing.T) {
	r := &Result{}
	r.checkVendor(&vendor.Info{Tamper: &vendor.TamperStatus{Tampered: true, Detail: "lid opened"}})
	r.finalize()
	if r.Ready {
		t.Fatal("a tampered device must not be ready")
	}
	if len(r.Reasons) != 1 || r.Reasons[0] != "lid opened" {
		t.Errorf("expected tamper reason, got %v", r.Reasons)
	}
}

func TestCheckVendorHAMemberDownPostpones(t *testing.T) {
	r := &Result{}
	r.checkVendor(&vendor.Info{HA: &vendor.HAStatus{Members: []vendor.HAMember{
		{Name: "node1", Up: true},
		{Name: "node2", Up: false},
	}}})
	r.finalize()
	if r.Ready {
		t.Fatal("a down HA member must postpone")
	}
	if len(r.Reasons) != 1 || r.Reasons[0] != "HA member(s) unavailable: node2" {
		t.Errorf("expected HA reason, got %v", r.Reasons)
	}
}

func TestCheckVendorAllHealthyStaysReady(t *testing.T) {
	inSync := true
	r := &Result{}
	r.checkVendor(&vendor.Info{
		Tamper: &vendor.TamperStatus{Tampered: false},
		HA: &vendor.HAStatus{InSync: &inSync, Members: []vendor.HAMember{
			{Name: "node1", Up: true},
			{Name: "node2", Up: true},
		}},
	})
	r.finalize()
	if !r.Ready || r.Verdict != "ready" {
		t.Errorf("healthy vendor state should stay ready: %+v", r)
	}
}

func TestFinalizeVerdict(t *testing.T) {
	r := &Result{}
	r.add("ok-check", LevelOK, "fine")
	r.add("warn-check", LevelWarn, "unknown")
	r.finalize()
	if !r.Ready {
		t.Error("warnings alone must not postpone")
	}
	r.add("bad-check", LevelFail, "broken")
	r.finalize()
	if r.Ready || r.Verdict != "postpone" {
		t.Error("a failed check must postpone")
	}
}
