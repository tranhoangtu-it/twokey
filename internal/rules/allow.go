package rules

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Allow pre-approves matches by rule id and resource, e.g. "deleting
// pr-*-preview Vercel projects is fine in this repo". Both fields are globs
// where * matches any characters (including '/').
type Allow struct {
	Rule     string `yaml:"rule"`
	Resource string `yaml:"resource"`
	Reason   string `yaml:"reason"`

	rule, resource *regexp.Regexp
}

type allowFile struct {
	Allow []Allow `yaml:"allow"`
}

// LoadAllow reads an allow file. A missing file is not an error.
func LoadAllow(path string) ([]Allow, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseAllow(data)
}

// ParseAllow decodes and validates allow entries (unknown fields rejected).
func ParseAllow(data []byte) ([]Allow, error) {
	var f allowFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	out := make([]Allow, 0, len(f.Allow))
	for i, a := range f.Allow {
		if a.Rule == "" {
			return nil, fmt.Errorf("allow[%d]: rule is required", i)
		}
		if a.Resource == "" {
			// Never let an entry silently allow every resource: be explicit.
			return nil, fmt.Errorf("allow[%d] (%s): resource is required (use \"*\" to allow all)", i, a.Rule)
		}
		a.rule, a.resource = globRegexp(a.Rule), globRegexp(a.Resource)
		out = append(out, a)
	}
	return out, nil
}

func globRegexp(glob string) *regexp.Regexp {
	// (?s): '*' also spans newlines, which request-derived text may contain.
	return regexp.MustCompile("(?s)^" + strings.ReplaceAll(regexp.QuoteMeta(glob), `\*`, ".*") + "$")
}

// Allowed reports which allow entry (if any) covers m. A match with an
// unknown resource is never covered, not even by resource "*": nobody can
// have pre-approved a target that cannot be named.
func Allowed(m Match, allows []Allow) (Allow, bool) {
	if m.Resource == "" {
		return Allow{}, false
	}
	for _, a := range allows {
		if a.rule == nil { // constructed outside ParseAllow
			a.rule, a.resource = globRegexp(a.Rule), globRegexp(a.Resource)
		}
		if !a.rule.MatchString(m.RuleID) {
			continue
		}
		if a.resource.MatchString(m.Resource) {
			return a, true
		}
	}
	return Allow{}, false
}

// ApplyAllow removes pre-approved matches from v. Uninspectable verdicts are
// never allowed. It returns the remaining verdict and the allowed matches.
func ApplyAllow(v Verdict, allows []Allow) (Verdict, []Match) {
	if len(allows) == 0 || v.Uninspectable != "" {
		return v, nil
	}
	var remaining, allowed []Match
	for _, m := range v.Matches {
		if _, ok := Allowed(m, allows); ok {
			allowed = append(allowed, m)
		} else {
			remaining = append(remaining, m)
		}
	}
	return Verdict{Matches: remaining}, allowed
}
