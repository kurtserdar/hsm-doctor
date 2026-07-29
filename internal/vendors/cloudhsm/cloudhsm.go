// Package cloudhsm is an EXPERIMENTAL provider for AWS CloudHSM.
//
// It shells out to the AWS CLI ("aws cloudhsmv2 describe-clusters") and maps
// cluster and HSM state into vendor findings. It has NOT been validated
// against a live AWS account; the JSON shape follows the public API docs.
package cloudhsm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

type provider struct {
	runner vendor.Runner
}

func init() {
	vendor.Register(&provider{runner: vendor.ExecRunner{}})
}

func (p *provider) Name() string { return "cloudhsm" }

func (p *provider) Detect(module p11.ModuleInfo, token *p11.TokenInfo) bool {
	hay := strings.ToLower(module.Manufacturer + " " + module.Description)
	if token != nil {
		hay += " " + strings.ToLower(token.Manufacturer+" "+token.Model)
	}
	return strings.Contains(hay, "cloudhsm") || strings.Contains(hay, "cavium")
}

// describeClustersResponse is the subset of the AWS API we consume.
type describeClustersResponse struct {
	Clusters []struct {
		ClusterID string `json:"ClusterId"`
		State     string `json:"State"`
		HSMs      []struct {
			HsmID string `json:"HsmId"`
			State string `json:"State"`
			AZ    string `json:"AvailabilityZone"`
		} `json:"Hsms"`
	} `json:"Clusters"`
}

func (p *provider) Collect(ctx context.Context, cfg vendor.Config) (*vendor.Info, error) {
	clusterID := cfg["cluster_id"]
	if clusterID == "" {
		return nil, vendor.ErrNotConfigured
	}

	args := []string{"cloudhsmv2", "describe-clusters", "--output", "json",
		"--filters", "clusterIds=" + clusterID}
	if region := cfg["region"]; region != "" {
		args = append(args, "--region", region)
	}
	if profile := cfg["profile"]; profile != "" {
		args = append(args, "--profile", profile)
	}
	out, err := p.runner.Run(ctx, "aws", args...)
	if err != nil {
		return nil, fmt.Errorf("aws cloudhsmv2 describe-clusters: %w", err)
	}
	return parseClusters(out, clusterID)
}

func parseClusters(out, clusterID string) (*vendor.Info, error) {
	var resp describeClustersResponse
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parsing describe-clusters JSON: %w", err)
	}
	info := &vendor.Info{Provider: "cloudhsm", Experimental: true, Extra: map[string]string{}}

	for _, c := range resp.Clusters {
		if c.ClusterID != clusterID {
			continue
		}
		info.Extra["cluster_id"] = c.ClusterID
		info.Extra["cluster_state"] = c.State
		if c.State != "ACTIVE" {
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "CLOUDHSM-001",
				Title:    "Cluster is not ACTIVE",
				Severity: policy.SevHigh,
				Detail:   "cluster state: " + c.State,
			})
		}

		// CloudHSM clusters need at least two HSMs across AZs for HA.
		ha := &vendor.HAStatus{Group: c.ClusterID}
		degraded := 0
		for _, h := range c.HSMs {
			up := h.State == "ACTIVE"
			if !up {
				degraded++
			}
			ha.Members = append(ha.Members, vendor.HAMember{
				Name: h.HsmID + " (" + h.AZ + ")", Status: h.State, Up: up,
			})
		}
		info.HA = ha
		if len(c.HSMs) < 2 {
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "CLOUDHSM-002",
				Title:    "Cluster has no high-availability redundancy",
				Severity: policy.SevMedium,
				Detail:   fmt.Sprintf("cluster has %d HSM(s); use at least two across availability zones", len(c.HSMs)),
			})
		}
		if degraded > 0 {
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "CLOUDHSM-003",
				Title:    "Cluster has degraded HSMs",
				Severity: policy.SevHigh,
				Detail:   fmt.Sprintf("%d of %d HSMs are not ACTIVE", degraded, len(c.HSMs)),
			})
		}
		return info, nil
	}
	return nil, fmt.Errorf("cluster %q not found in describe-clusters output", clusterID)
}
