// Command gendocs generates shell completions and man pages for hsmdoctor into
// an output directory. It is a build-time tool, not shipped in the binary:
//
//	go run ./cmd/gendocs dist/docs
//
// produces dist/docs/completions/{hsmdoctor.bash,_hsmdoctor,hsmdoctor.fish} and
// dist/docs/man/*.1. Everything is derived from the command tree, so it stays
// in sync with the CLI automatically.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kurtserdar/hsm-doctor/internal/cli"
	"github.com/spf13/cobra/doc"
)

func main() {
	outDir := "dist/docs"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := run(outDir); err != nil {
		fmt.Fprintln(os.Stderr, "gendocs:", err)
		os.Exit(1)
	}
}

func run(outDir string) error {
	root := cli.RootCmd()
	root.DisableAutoGenTag = true

	compDir := filepath.Join(outDir, "completions")
	manDir := filepath.Join(outDir, "man")
	for _, d := range []string{compDir, manDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	completions := []struct {
		file string
		gen  func(io.Writer) error
	}{
		{"hsmdoctor.bash", func(w io.Writer) error { return root.GenBashCompletionV2(w, true) }},
		{"_hsmdoctor", func(w io.Writer) error { return root.GenZshCompletion(w) }},
		{"hsmdoctor.fish", func(w io.Writer) error { return root.GenFishCompletion(w, true) }},
	}
	for _, c := range completions {
		if err := writeFile(filepath.Join(compDir, c.file), c.gen); err != nil {
			return err
		}
	}

	// Man pages (section 1).
	header := &doc.GenManHeader{Title: "HSMDOCTOR", Section: "1", Source: "HSM Doctor"}
	if err := doc.GenManTree(root, header, manDir); err != nil {
		return err
	}

	fmt.Printf("wrote completions to %s and man pages to %s\n", compDir, manDir)
	return nil
}

// writeFile creates path and lets gen write it, returning any write or close
// error so a partial file is never silently accepted.
func writeFile(path string, gen func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := gen(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
