package kmip

import (
	"fmt"
	"sort"
	"time"

	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
)

// Object is a KMIP managed object with the attributes we read.
type Object struct {
	ID          string     `json:"id"`
	Type        string     `json:"type,omitempty"`
	Algorithm   string     `json:"algorithm,omitempty"`
	Length      int        `json:"length,omitempty"`
	State       string     `json:"state,omitempty"`
	UsageMask   []string   `json:"usage_mask,omitempty"`
	Names       []string   `json:"names,omitempty"`
	InitialDate *time.Time `json:"initial_date,omitempty"`
}

// Inventory is a snapshot of a KMIP server's managed objects.
type Inventory struct {
	Endpoint        string    `json:"endpoint"`
	ProtocolVersion string    `json:"protocol_version"`
	ScannedAt       time.Time `json:"scanned_at"`
	Objects         []Object  `json:"objects"`
}

// discoverVersions asks the server for its supported protocol versions and
// negotiates the highest one the client also understands (1.0–1.4).
func (c *Client) discoverVersions() error {
	payload, err := c.roundTrip(kmip14.OperationDiscoverVersions, struct{}{})
	if err != nil {
		return err
	}
	bestMajor, bestMinor := 0, 0
	for t := payload.ValueStructure(); len(t) > 0; t = t.Next() {
		if t.Tag() != kmip14.TagProtocolVersion {
			continue
		}
		major, minor := 0, 0
		for v := t.ValueStructure(); len(v) > 0; v = v.Next() {
			switch v.Tag() {
			case kmip14.TagProtocolVersionMajor:
				major = int(v.ValueInteger())
			case kmip14.TagProtocolVersionMinor:
				minor = int(v.ValueInteger())
			}
		}
		// Consider only versions we can speak (1.x), keep the highest.
		if major == 1 && minor <= 4 && (major > bestMajor || (major == bestMajor && minor > bestMinor)) {
			bestMajor, bestMinor = major, minor
		}
	}
	if bestMajor != 0 {
		c.major, c.minor = bestMajor, bestMinor
	}
	return nil
}

// locateAll returns the unique identifiers of every managed object. An empty
// Locate request payload asks the server for all objects.
func (c *Client) locateAll() ([]string, error) {
	payload, err := c.roundTrip(kmip14.OperationLocate, struct{}{})
	if err != nil {
		return nil, err
	}
	var ids []string
	for t := payload.ValueStructure(); len(t) > 0; t = t.Next() {
		if t.Tag() == kmip14.TagUniqueIdentifier {
			ids = append(ids, t.ValueTextString())
		}
	}
	return ids, nil
}

// getAttributesRequest is the GetAttributes request payload. With no attribute
// names, the server returns all of the object's attributes.
type getAttributesRequest struct {
	UniqueIdentifier string
}

// getObject reads one object's attributes.
func (c *Client) getObject(id string) (Object, error) {
	payload, err := c.roundTrip(kmip14.OperationGetAttributes, getAttributesRequest{UniqueIdentifier: id})
	if err != nil {
		return Object{}, err
	}
	obj := Object{ID: id}
	for t := payload.ValueStructure(); len(t) > 0; t = t.Next() {
		if t.Tag() != kmip14.TagAttribute {
			continue
		}
		name, value := attributeParts(t)
		applyAttribute(&obj, name, value)
	}
	return obj, nil
}

// attributeParts splits an Attribute structure into its name and value TTLV.
func attributeParts(attr ttlv.TTLV) (name string, value ttlv.TTLV) {
	for f := attr.ValueStructure(); len(f) > 0; f = f.Next() {
		switch f.Tag() {
		case kmip14.TagAttributeName:
			name = f.ValueTextString()
		case kmip14.TagAttributeValue:
			value = f
		}
	}
	return name, value
}

// applyAttribute maps one KMIP attribute onto the object.
func applyAttribute(obj *Object, name string, value ttlv.TTLV) {
	if len(value) == 0 {
		return
	}
	switch name {
	case "Cryptographic Algorithm":
		obj.Algorithm = kmip14.CryptographicAlgorithm(value.ValueEnumeration()).String()
	case "Cryptographic Length":
		obj.Length = int(value.ValueInteger())
	case "State":
		obj.State = kmip14.State(value.ValueEnumeration()).String()
	case "Object Type":
		obj.Type = kmip14.ObjectType(value.ValueEnumeration()).String()
	case "Cryptographic Usage Mask":
		obj.UsageMask = usageMaskNames(uint32(value.ValueInteger()))
	case "Name":
		// Name value is itself a structure with a Name Value text field.
		for n := value.ValueStructure(); len(n) > 0; n = n.Next() {
			if n.Tag() == kmip14.TagNameValue {
				obj.Names = append(obj.Names, n.ValueTextString())
			}
		}
	case "Initial Date":
		d := value.ValueDateTime()
		obj.InitialDate = &d
	}
}

// usageMask lists the cryptographic usage-mask flags we surface, in bit order.
var usageMask = []struct {
	bit  uint32
	name string
}{
	{uint32(kmip14.CryptographicUsageMaskSign), "Sign"},
	{uint32(kmip14.CryptographicUsageMaskVerify), "Verify"},
	{uint32(kmip14.CryptographicUsageMaskEncrypt), "Encrypt"},
	{uint32(kmip14.CryptographicUsageMaskDecrypt), "Decrypt"},
	{uint32(kmip14.CryptographicUsageMaskWrapKey), "WrapKey"},
	{uint32(kmip14.CryptographicUsageMaskUnwrapKey), "UnwrapKey"},
}

func usageMaskNames(mask uint32) []string {
	var out []string
	for _, u := range usageMask {
		if mask&u.bit != 0 {
			out = append(out, u.name)
		}
	}
	return out
}

// Collect connects the whole read-only flow: discover versions, locate every
// object and read its attributes.
func Collect(cfg Config, now time.Time) (*Inventory, error) {
	c, err := Dial(cfg)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	if err := c.discoverVersions(); err != nil {
		return nil, fmt.Errorf("discover versions: %w", err)
	}
	ids, err := c.locateAll()
	if err != nil {
		return nil, fmt.Errorf("locate: %w", err)
	}
	inv := &Inventory{
		Endpoint:        cfg.Endpoint,
		ProtocolVersion: c.ProtocolVersion(),
		ScannedAt:       now,
	}
	for _, id := range ids {
		obj, err := c.getObject(id)
		if err != nil {
			return nil, fmt.Errorf("get attributes for %s: %w", id, err)
		}
		inv.Objects = append(inv.Objects, obj)
	}
	sort.SliceStable(inv.Objects, func(i, j int) bool { return inv.Objects[i].ID < inv.Objects[j].ID })
	return inv, nil
}
