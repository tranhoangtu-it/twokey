package rules

import (
	"strings"
)

// pathTemplate matches URL paths like "/repos/{owner}/{repo}".
// "{name}" captures one segment; "{name...}" (last segment only) captures
// the rest of the path including slashes. Paths are matched already
// percent-decoded, so captured values are used as is (decoding them again
// would show a resource that differs from what the server acts on).
type pathTemplate struct {
	segments []string
}

func parsePathTemplate(p string) *pathTemplate {
	return &pathTemplate{segments: splitPath(p)}
}

func (t *pathTemplate) match(p string) (map[string]string, bool) {
	parts := splitPath(p)
	vars := map[string]string{}
	for i, seg := range t.segments {
		name, isVar := strings.CutPrefix(seg, "{")
		if isVar {
			name = strings.TrimSuffix(name, "}")
			if greedy, ok := strings.CutSuffix(name, "..."); ok && i == len(t.segments)-1 {
				if i >= len(parts) {
					return nil, false
				}
				vars[greedy] = strings.Join(parts[i:], "/")
				return vars, true
			}
		}
		if i >= len(parts) {
			return nil, false
		}
		if isVar {
			vars[name] = parts[i]
		} else if !strings.EqualFold(seg, parts[i]) {
			return nil, false
		}
	}
	return vars, len(parts) == len(t.segments)
}

// splitPath drops empty segments so "/a//b/" == "/a/b"; "/" has no segments.
func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
