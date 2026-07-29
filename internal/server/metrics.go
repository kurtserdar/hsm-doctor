package server

import (
	"net/http"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/certmon"
	"github.com/kurtserdar/hsm-doctor/internal/pqc"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metrics holds the Prometheus instruments, refreshed on every scan.
// Label cardinality stays bounded: one series set per (serial, label).
type metrics struct {
	registry *prometheus.Registry

	healthScore  *prometheus.GaugeVec
	findings     *prometheus.GaugeVec
	objects      *prometheus.GaugeVec
	certMinDays  *prometheus.GaugeVec
	lastScanTime *prometheus.GaugeVec
	scansTotal   *prometheus.CounterVec

	pqcAdvertised *prometheus.GaugeVec
	pqcVulnerable *prometheus.GaugeVec
	pqcHNDL       *prometheus.GaugeVec
}

func newMetrics(version string) *metrics {
	reg := prometheus.NewRegistry()
	m := &metrics{
		registry: reg,
		healthScore: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hsmdoctor_health_score",
			Help: "Security posture health score (0-100) from the most recent scan.",
		}, []string{"serial", "label"}),
		findings: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hsmdoctor_findings",
			Help: "Number of findings by severity from the most recent scan.",
		}, []string{"serial", "label", "severity"}),
		objects: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hsmdoctor_objects",
			Help: "Number of token objects by class from the most recent scan.",
		}, []string{"serial", "label", "class"}),
		certMinDays: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hsmdoctor_certificate_min_days_to_expiry",
			Help: "Days until the soonest certificate expiry (negative when already expired).",
		}, []string{"serial", "label"}),
		lastScanTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hsmdoctor_last_scan_timestamp_seconds",
			Help: "Unix timestamp of the most recent scan.",
		}, []string{"serial", "label"}),
		scansTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hsmdoctor_scans_total",
			Help: "Total number of scans performed since process start.",
		}, []string{"serial", "label"}),
		pqcAdvertised: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hsmdoctor_pqc_family_advertised",
			Help: "1 when the token advertises the PQC family's mechanisms (ML-KEM, ML-DSA, SLH-DSA).",
		}, []string{"serial", "label", "family"}),
		pqcVulnerable: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hsmdoctor_pqc_quantum_vulnerable_keys",
			Help: "Number of private keys using quantum-vulnerable algorithms.",
		}, []string{"serial", "label"}),
		pqcHNDL: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hsmdoctor_pqc_hndl_exposed_keys",
			Help: "Quantum-vulnerable private keys able to decrypt or unwrap (harvest-now-decrypt-later exposure).",
		}, []string{"serial", "label"}),
	}
	reg.MustRegister(m.healthScore, m.findings, m.objects, m.certMinDays, m.lastScanTime, m.scansTotal,
		m.pqcAdvertised, m.pqcVulnerable, m.pqcHNDL)

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hsmdoctor_build_info",
		Help: "Build information; the value is always 1.",
	}, []string{"version"})
	reg.MustRegister(buildInfo)
	buildInfo.WithLabelValues(version).Set(1)
	return m
}

// handler serves the metrics endpoint.
func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// observeScan refreshes all per-HSM series from a finished scan report.
func (m *metrics) observeScan(rep *report.Report) {
	inv := rep.Inventory
	if inv == nil || inv.Slot.Token == nil {
		return
	}
	serial, label := inv.Slot.Token.SerialNumber, inv.Slot.Token.Label

	m.healthScore.WithLabelValues(serial, label).Set(float64(rep.Score))
	m.lastScanTime.WithLabelValues(serial, label).Set(float64(inv.ScannedAt.Unix()))
	m.scansTotal.WithLabelValues(serial, label).Inc()

	bySeverity := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, f := range rep.Findings {
		bySeverity[string(f.Severity)]++
	}
	for severity, count := range bySeverity {
		m.findings.WithLabelValues(serial, label, severity).Set(float64(count))
	}

	c := rep.Counts
	m.objects.WithLabelValues(serial, label, "private-key").Set(float64(c.PrivateKeys))
	m.objects.WithLabelValues(serial, label, "public-key").Set(float64(c.PublicKeys))
	m.objects.WithLabelValues(serial, label, "secret-key").Set(float64(c.SecretKeys))
	m.objects.WithLabelValues(serial, label, "certificate").Set(float64(c.Certificates))

	entries := certmon.Classify(inv, time.Now(), 30)
	if len(entries) > 0 {
		min := entries[0].DaysLeft
		for _, e := range entries[1:] {
			if e.DaysLeft < min {
				min = e.DaysLeft
			}
		}
		m.certMinDays.WithLabelValues(serial, label).Set(float64(min))
	}

	// PQC readiness series come from the same scan data.
	det := pqc.Detect(inv.Mechanisms)
	for _, f := range det.Families {
		v := 0.0
		if f.Advertised {
			v = 1.0
		}
		m.pqcAdvertised.WithLabelValues(serial, label, f.Family).Set(v)
	}
	exposure := pqc.Assess(inv, det)
	m.pqcVulnerable.WithLabelValues(serial, label).Set(float64(exposure.ClassicalPrivateKeys))
	m.pqcHNDL.WithLabelValues(serial, label).Set(float64(exposure.HarvestNowDecryptLater))
}
