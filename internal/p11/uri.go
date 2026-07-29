package p11

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// URI is a parsed RFC 7512 PKCS#11 URI. Only the attributes relevant for
// locating a token and authenticating are extracted; unrecognized
// attributes are ignored as the RFC prescribes.
type URI struct {
	Token        string
	Serial       string
	Manufacturer string
	Model        string
	SlotID       *uint

	// Query attributes.
	ModulePath string
	PINValue   string
	PINSource  string
}

// ParseURI parses a pkcs11: URI.
func ParseURI(raw string) (*URI, error) {
	rest, ok := strings.CutPrefix(raw, "pkcs11:")
	if !ok {
		return nil, fmt.Errorf("not a PKCS#11 URI (missing pkcs11: scheme): %q", raw)
	}

	pathPart := rest
	queryPart := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		pathPart, queryPart = rest[:i], rest[i+1:]
	}

	u := &URI{}
	if pathPart != "" {
		for _, attr := range strings.Split(pathPart, ";") {
			key, value, found := strings.Cut(attr, "=")
			if !found {
				return nil, fmt.Errorf("malformed URI attribute %q", attr)
			}
			decoded, err := url.PathUnescape(value)
			if err != nil {
				return nil, fmt.Errorf("decoding URI attribute %q: %w", key, err)
			}
			switch key {
			case "token":
				u.Token = decoded
			case "serial":
				u.Serial = decoded
			case "manufacturer":
				u.Manufacturer = decoded
			case "model":
				u.Model = decoded
			case "slot-id":
				id, err := strconv.ParseUint(decoded, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid slot-id %q", decoded)
				}
				slot := uint(id)
				u.SlotID = &slot
			}
			// Other path attributes (object, type, id, ...) are not needed
			// for token addressing and are intentionally ignored.
		}
	}

	if queryPart != "" {
		values, err := url.ParseQuery(queryPart)
		if err != nil {
			return nil, fmt.Errorf("parsing URI query: %w", err)
		}
		u.ModulePath = values.Get("module-path")
		u.PINValue = values.Get("pin-value")
		u.PINSource = values.Get("pin-source")
	}
	return u, nil
}

// PIN resolves the PIN referenced by the URI: pin-value wins, then
// pin-source (read as a file). Empty when the URI carries neither.
func (u *URI) PIN() (string, error) {
	if u.PINValue != "" {
		return u.PINValue, nil
	}
	if u.PINSource != "" {
		data, err := os.ReadFile(u.PINSource)
		if err != nil {
			return "", fmt.Errorf("reading pin-source: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", nil
}

// MatchSlot finds the single slot whose token matches every attribute set
// in the URI. It fails when no token or more than one token matches.
func (u *URI) MatchSlot(slots []SlotInfo) (uint, error) {
	if u.SlotID != nil {
		return *u.SlotID, nil
	}
	var matches []SlotInfo
	for _, s := range slots {
		if !s.TokenPresent || s.Token == nil {
			continue
		}
		t := s.Token
		if u.Token != "" && t.Label != u.Token {
			continue
		}
		if u.Serial != "" && t.SerialNumber != u.Serial {
			continue
		}
		if u.Manufacturer != "" && t.Manufacturer != u.Manufacturer {
			continue
		}
		if u.Model != "" && t.Model != u.Model {
			continue
		}
		matches = append(matches, s)
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("no token matches URI (token=%q serial=%q)", u.Token, u.Serial)
	case 1:
		return matches[0].ID, nil
	default:
		labels := make([]string, len(matches))
		for i, m := range matches {
			labels[i] = fmt.Sprintf("slot %d (%s)", m.ID, m.Token.Label)
		}
		return 0, fmt.Errorf("URI matches %d tokens (%s); add serial= to disambiguate",
			len(matches), strings.Join(labels, ", "))
	}
}
