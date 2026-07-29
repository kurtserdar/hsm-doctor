// Package rules embeds the default security posture rule set and the named
// policy packs so the binary works out of the box without external files.
package rules

import (
	"embed"
	"path"
	"sort"
	"strings"
)

// Default is the built-in rules file (default.yaml).
//
//go:embed default.yaml
var Default []byte

//go:embed packs/*.yaml
var packsFS embed.FS

// Pack is one embedded policy pack.
type Pack struct {
	Name string
	Data []byte
}

// Packs returns the embedded policy packs sorted by name. "default" is not
// included; it is exposed separately as Default.
func Packs() []Pack {
	entries, err := packsFS.ReadDir("packs")
	if err != nil {
		// The embedded FS layout is fixed at compile time.
		panic(err)
	}
	packs := make([]Pack, 0, len(entries))
	for _, e := range entries {
		data, err := packsFS.ReadFile(path.Join("packs", e.Name()))
		if err != nil {
			panic(err)
		}
		packs = append(packs, Pack{
			Name: strings.TrimSuffix(e.Name(), ".yaml"),
			Data: data,
		})
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Name < packs[j].Name })
	return packs
}

// PackData returns the raw YAML of a named embedded pack. "default" resolves
// to the built-in default rule set.
func PackData(name string) ([]byte, bool) {
	if name == "default" {
		return Default, true
	}
	data, err := packsFS.ReadFile(path.Join("packs", name+".yaml"))
	if err != nil {
		return nil, false
	}
	return data, true
}
