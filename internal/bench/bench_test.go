package bench

import (
	"testing"
	"time"
)

func TestNormalizeAppliesDefaults(t *testing.T) {
	o := Options{}.Normalize()
	if o.Duration != DefaultDuration || o.MaxOps != DefaultMaxOps || o.Sessions != DefaultSessions {
		t.Errorf("defaults not applied: %+v", o)
	}
}

func TestNormalizeClampsToSafetyLimits(t *testing.T) {
	o := Options{
		Duration: 10 * time.Minute,
		MaxOps:   50_000_000,
		Sessions: 500,
	}.Normalize()
	if o.Duration != MaxDuration {
		t.Errorf("duration not clamped: %v", o.Duration)
	}
	if o.MaxOps != HardMaxOps {
		t.Errorf("max ops not clamped: %d", o.MaxOps)
	}
	if o.Sessions != MaxSessions {
		t.Errorf("sessions not clamped: %d", o.Sessions)
	}
}

func TestNormalizeNegativeValues(t *testing.T) {
	o := Options{Duration: -1, MaxOps: -5, Sessions: -2}.Normalize()
	if o.Duration != DefaultDuration || o.MaxOps != DefaultMaxOps || o.Sessions != DefaultSessions {
		t.Errorf("negative values not normalized: %+v", o)
	}
}
