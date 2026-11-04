package rules

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed packs/*.yaml
var builtinPacks embed.FS

// BuiltinPacks returns the rule packs compiled into the binary.
func BuiltinPacks() ([]Pack, error) {
	return loadFS(builtinPacks, "packs")
}

// LoadDir reads every *.yaml / *.yml pack in dir (user-supplied rules).
func LoadDir(dir string) ([]Pack, error) {
	return loadFS(os.DirFS(dir), ".")
}

func loadFS(fsys fs.FS, dir string) ([]Pack, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var packs []Pack
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if e.IsDir() || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		// path.Join, not dir+"/": "./x.yaml" is an invalid fs.FS path.
		data, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		p, err := ParsePack(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		packs = append(packs, p)
	}
	return packs, nil
}

// ParsePack decodes one YAML pack, rejecting unknown fields so typos in
// community rules fail loudly instead of silently matching nothing.
func ParsePack(data []byte) (Pack, error) {
	var p Pack
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Pack{}, err
	}
	if p.Provider == "" {
		return Pack{}, fmt.Errorf("missing provider")
	}
	return p, nil
}
