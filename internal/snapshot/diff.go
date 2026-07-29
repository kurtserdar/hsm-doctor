package snapshot

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
)

// Diff is the drift between two snapshots of the same token.
type Diff struct {
	OldScannedAt time.Time `json:"old_scanned_at"`
	NewScannedAt time.Time `json:"new_scanned_at"`

	TokenChanges      []FieldChange `json:"token_changes,omitempty"`
	MechanismsAdded   []string      `json:"mechanisms_added,omitempty"`
	MechanismsRemoved []string      `json:"mechanisms_removed,omitempty"`
	ObjectsAdded      []string      `json:"objects_added,omitempty"`
	ObjectsRemoved    []string      `json:"objects_removed,omitempty"`
	ObjectChanges     []FieldChange `json:"object_changes,omitempty"`
}

// FieldChange records one changed value, optionally tied to an object.
type FieldChange struct {
	Object string `json:"object,omitempty"`
	Field  string `json:"field"`
	Old    string `json:"old"`
	New    string `json:"new"`
}

// Empty reports whether no drift was detected.
func (d *Diff) Empty() bool {
	return len(d.TokenChanges) == 0 &&
		len(d.MechanismsAdded) == 0 && len(d.MechanismsRemoved) == 0 &&
		len(d.ObjectsAdded) == 0 && len(d.ObjectsRemoved) == 0 &&
		len(d.ObjectChanges) == 0
}

// Count returns the total number of recorded changes.
func (d *Diff) Count() int {
	return len(d.TokenChanges) + len(d.MechanismsAdded) + len(d.MechanismsRemoved) +
		len(d.ObjectsAdded) + len(d.ObjectsRemoved) + len(d.ObjectChanges)
}

// objectKey identifies an object across scans: class + label + CKA_ID.
func objectKey(o *inventory.Object) string {
	return o.Class + "\x00" + o.Label + "\x00" + o.ID
}

// objectRef renders the human-readable form of an object key.
func objectRef(o *inventory.Object) string {
	ref := o.Class
	if o.Label != "" {
		ref += " " + o.Label
	}
	if o.ID != "" {
		ref += " (id " + o.ID + ")"
	}
	return ref
}

// Compare computes the drift from old to new.
func Compare(oldInv, newInv *inventory.Inventory) *Diff {
	d := &Diff{OldScannedAt: oldInv.ScannedAt, NewScannedAt: newInv.ScannedAt}

	compareToken(oldInv, newInv, d)
	compareMechanisms(oldInv, newInv, d)
	compareObjects(oldInv, newInv, d)
	return d
}

func compareToken(oldInv, newInv *inventory.Inventory, d *Diff) {
	ot, nt := oldInv.Slot.Token, newInv.Slot.Token
	if ot == nil || nt == nil {
		return
	}
	pairs := []struct{ field, o, n string }{
		{"token label", ot.Label, nt.Label},
		{"serial number", ot.SerialNumber, nt.SerialNumber},
		{"model", ot.Model, nt.Model},
		{"firmware version", ot.FirmwareVersion, nt.FirmwareVersion},
		{"hardware version", ot.HardwareVersion, nt.HardwareVersion},
	}
	for _, p := range pairs {
		if p.o != p.n {
			d.TokenChanges = append(d.TokenChanges, FieldChange{Field: p.field, Old: p.o, New: p.n})
		}
	}
}

func compareMechanisms(oldInv, newInv *inventory.Inventory, d *Diff) {
	oldSet := map[string]bool{}
	newSet := map[string]bool{}
	for _, m := range oldInv.Mechanisms {
		oldSet[m.Name] = true
	}
	for _, m := range newInv.Mechanisms {
		newSet[m.Name] = true
	}
	for name := range newSet {
		if !oldSet[name] {
			d.MechanismsAdded = append(d.MechanismsAdded, name)
		}
	}
	for name := range oldSet {
		if !newSet[name] {
			d.MechanismsRemoved = append(d.MechanismsRemoved, name)
		}
	}
	sort.Strings(d.MechanismsAdded)
	sort.Strings(d.MechanismsRemoved)
}

func compareObjects(oldInv, newInv *inventory.Inventory, d *Diff) {
	oldByKey := map[string][]*inventory.Object{}
	newByKey := map[string][]*inventory.Object{}
	for i := range oldInv.Objects {
		o := &oldInv.Objects[i]
		oldByKey[objectKey(o)] = append(oldByKey[objectKey(o)], o)
	}
	for i := range newInv.Objects {
		o := &newInv.Objects[i]
		newByKey[objectKey(o)] = append(newByKey[objectKey(o)], o)
	}

	keys := map[string]bool{}
	for k := range oldByKey {
		keys[k] = true
	}
	for k := range newByKey {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, k := range sorted {
		olds, news := oldByKey[k], newByKey[k]
		switch {
		case len(olds) == 0:
			for _, o := range news {
				d.ObjectsAdded = append(d.ObjectsAdded, objectRef(o))
			}
		case len(news) == 0:
			for _, o := range olds {
				d.ObjectsRemoved = append(d.ObjectsRemoved, objectRef(o))
			}
		default:
			// Attribute drift is only comparable for unambiguous 1:1 matches.
			if len(olds) == 1 && len(news) == 1 {
				compareAttrs(olds[0], news[0], d)
			}
			for i := len(olds); i < len(news); i++ {
				d.ObjectsAdded = append(d.ObjectsAdded, objectRef(news[i])+" (duplicate)")
			}
			for i := len(news); i < len(olds); i++ {
				d.ObjectsRemoved = append(d.ObjectsRemoved, objectRef(olds[i])+" (duplicate)")
			}
		}
	}
}

// fmtBool renders a tri-state attribute for change reports.
func fmtBool(b *bool) string {
	if b == nil {
		return "(not exposed)"
	}
	return fmt.Sprintf("%v", *b)
}

func compareAttrs(o, n *inventory.Object, d *Diff) {
	ref := objectRef(n)
	add := func(field, oldV, newV string) {
		if oldV != newV {
			d.ObjectChanges = append(d.ObjectChanges, FieldChange{Object: ref, Field: field, Old: oldV, New: newV})
		}
	}

	add("key type", o.KeyType, n.KeyType)
	add("key size", fmt.Sprintf("%d", o.KeyBits), fmt.Sprintf("%d", n.KeyBits))
	add("curve", o.Curve, n.Curve)

	bools := []struct {
		name string
		o, n *bool
	}{
		{"CKA_SENSITIVE", o.Sensitive, n.Sensitive},
		{"CKA_EXTRACTABLE", o.Extractable, n.Extractable},
		{"CKA_SIGN", o.Sign, n.Sign},
		{"CKA_VERIFY", o.Verify, n.Verify},
		{"CKA_ENCRYPT", o.Encrypt, n.Encrypt},
		{"CKA_DECRYPT", o.Decrypt, n.Decrypt},
		{"CKA_WRAP", o.Wrap, n.Wrap},
		{"CKA_UNWRAP", o.Unwrap, n.Unwrap},
		{"CKA_DERIVE", o.Derive, n.Derive},
		{"CKA_MODIFIABLE", o.Modifiable, n.Modifiable},
	}
	for _, b := range bools {
		add(b.name, fmtBool(b.o), fmtBool(b.n))
	}

	if o.Certificate != nil && n.Certificate != nil {
		add("certificate subject", o.Certificate.Subject, n.Certificate.Subject)
		add("certificate expiry", o.Certificate.NotAfter.Format("2006-01-02"), n.Certificate.NotAfter.Format("2006-01-02"))
		add("certificate serial", o.Certificate.SerialNumber, n.Certificate.SerialNumber)
	}
}

// Text renders the diff in a compact, drift-report style.
func (d *Diff) Text(w io.Writer) {
	fmt.Fprintf(w, "Old scan: %s\n", d.OldScannedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "New scan: %s\n\n", d.NewScannedAt.Format("2006-01-02 15:04:05 MST"))

	if d.Empty() {
		fmt.Fprintln(w, "No drift detected.")
		return
	}
	for _, c := range d.TokenChanges {
		fmt.Fprintf(w, "! %s changed %s -> %s\n", c.Field, c.Old, c.New)
	}
	for _, m := range d.MechanismsAdded {
		fmt.Fprintf(w, "+ mechanism %s now available\n", m)
	}
	for _, m := range d.MechanismsRemoved {
		fmt.Fprintf(w, "- mechanism %s no longer available\n", m)
	}
	for _, o := range d.ObjectsAdded {
		fmt.Fprintf(w, "+ %s added\n", o)
	}
	for _, o := range d.ObjectsRemoved {
		fmt.Fprintf(w, "- %s removed\n", o)
	}
	for _, c := range d.ObjectChanges {
		fmt.Fprintf(w, "! %s: %s changed %s -> %s\n", c.Object, c.Field, c.Old, c.New)
	}
	fmt.Fprintf(w, "\n%d change(s) detected.\n", d.Count())
}
