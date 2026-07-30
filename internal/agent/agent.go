// Package agent implements the push client: it scans local PKCS#11 tokens
// and ships the reports to a central HSM Doctor server.
//
// The PIN never leaves the agent host; only finished reports (metadata,
// findings, scores) are transmitted.
package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

// Client talks to a central HSM Doctor server.
type Client struct {
	ServerURL string
	Token     string
	HTTP      *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// apiError extracts the JSON error envelope from a failed response.
func apiError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var envelope struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Error != "" {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, envelope.Error)
	}
	return fmt.Errorf("server returned %d", resp.StatusCode)
}

// Enroll exchanges the shared enrollment token for a permanent agent token.
func Enroll(httpc *http.Client, serverURL, name, enrollToken string) (string, error) {
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	body, err := json.Marshal(map[string]string{"name": name, "enroll_token": enrollToken})
	if err != nil {
		return "", err
	}
	resp, err := httpc.Post(serverURL+"/api/v1/ingest/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("enrolling with %s: %w", serverURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", apiError(resp)
	}
	var out struct {
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decoding enrollment response: %w", err)
	}
	if out.AgentToken == "" {
		return "", fmt.Errorf("server returned an empty agent token")
	}
	return out.AgentToken, nil
}

// Push uploads one report.
func (c *Client) Push(rep *report.Report) error {
	blob, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.ServerURL+"/api/v1/ingest/report", bytes.NewReader(blob))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("pushing report to %s: %w", c.ServerURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiError(resp)
	}
	return nil
}

// VendorCollector optionally enriches each report with vendor appliance
// data. The agent package stays decoupled from concrete providers: the CLI
// supplies this hook.
type VendorCollector func(module p11.ModuleInfo, token *p11.TokenInfo) *vendor.Info

// CollectReports scans the module and returns one report per token-bearing
// slot. When slot is non-nil only that slot is scanned. vendorFn may be nil.
func CollectReports(modulePath, pin string, slot *uint, rules *policy.Config, version string, vendorFn VendorCollector) ([]*report.Report, error) {
	client, err := p11.Open(modulePath)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var slotIDs []uint
	if slot != nil {
		slotIDs = []uint{*slot}
	} else {
		slots, err := client.Slots()
		if err != nil {
			return nil, err
		}
		for _, s := range slots {
			// Uninitialized tokens (e.g. SoftHSM's spare "free" slot)
			// cannot be scanned and are not interesting for the fleet.
			if s.TokenPresent && s.Token != nil && s.Token.Initialized {
				slotIDs = append(slotIDs, s.ID)
			}
		}
	}

	// One failing slot must not prevent the others from being reported.
	var reports []*report.Report
	var errs []error
	for _, id := range slotIDs {
		inv, err := inventory.Collect(client, id, pin)
		if err != nil {
			errs = append(errs, fmt.Errorf("scanning slot %d: %w", id, err))
			continue
		}
		res := policy.Evaluate(inv, rules, time.Now())
		rep := report.New(version, inv, res)
		rep.RulePacks = rules.SourcePacks
		if vendorFn != nil {
			if vinfo := vendorFn(inv.Module, inv.Slot.Token); vinfo != nil {
				rep.Vendor = vinfo
				res.AddFindings(vinfo.Findings...)
				rep.Score = res.Score
			}
		}
		reports = append(reports, rep)
	}
	return reports, errors.Join(errs...)
}
