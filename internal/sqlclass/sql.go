// Package sqlclass finds destructive SQL statements (DROP, TRUNCATE,
// DELETE/UPDATE without WHERE, ALTER … DROP) for the Postgres and MySQL
// guards. It is a dialect-aware lexer, not a full parser.
package sqlclass

import (
	"strings"
	"unicode"
)

// Finding is one destructive statement.
type Finding struct {
	Kind      string // e.g. "DROP TABLE", "TRUNCATE", "DELETE without WHERE"
	Target    string // table / object name when known
	Statement string // the statement text (trimmed, possibly truncated)
}

// maxStatementShown bounds statement text shown to humans.
const maxStatementShown = 200

// Classify returns the destructive statements in sql. It is a lexer, not a
// parser: comments, string literals, dollar-quoted bodies and quoted
// identifiers are understood so "SELECT 'drop table x'" is not flagged.
func Classify(sql string) []Finding { return classify(sql, false) }

// ClassifyMySQL is Classify for MySQL syntax: # comments, `backtick`
// identifiers, "double-quoted" strings and backslash escapes.
func ClassifyMySQL(sql string) []Finding { return classify(sql, true) }

func classify(sql string, mysql bool) []Finding {
	var out []Finding
	for _, st := range splitStatements(sql, mysql) {
		if f, ok := classifyStatement(st); ok {
			out = append(out, f)
		}
	}
	return out
}

type token struct {
	word   string // lowercased keyword/identifier, or "" for punctuation
	quoted bool   // "Quoted" identifier (never a keyword)
	raw    string
}

type statement struct {
	text   string
	tokens []token
}

// splitStatements tokenizes and splits on top-level semicolons.
func splitStatements(sql string, mysql bool) []statement {
	var stmts []statement
	var cur statement
	var text strings.Builder
	flush := func() {
		cur.text = strings.TrimSpace(text.String())
		if len(cur.tokens) > 0 {
			stmts = append(stmts, cur)
		}
		cur = statement{}
		text.Reset()
	}
	rs := []rune(sql)
	for i := 0; i < len(rs); {
		r := rs[i]
		switch {
		case (r == '-' && i+1 < len(rs) && rs[i+1] == '-') || (mysql && r == '#'):
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
			text.WriteRune(' ')
		case r == '/' && i+1 < len(rs) && rs[i+1] == '*':
			depth := 0 // Postgres block comments nest
			for i < len(rs) {
				if rs[i] == '/' && i+1 < len(rs) && rs[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if rs[i] == '*' && i+1 < len(rs) && rs[i+1] == '/' {
					depth--
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				i++
			}
			text.WriteRune(' ')
		case r == '\'' || (mysql && r == '"'):
			start := i
			i++
			for i < len(rs) {
				if mysql && rs[i] == '\\' { // MySQL backslash escape
					i += 2
					continue
				}
				if rs[i] == r {
					if i+1 < len(rs) && rs[i+1] == r { // '' escape
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			text.WriteString(string(rs[start:i]))
			cur.tokens = append(cur.tokens, token{raw: "'…'"})
		case r == '"' || (mysql && r == '`'):
			start := i
			i++
			for i < len(rs) && rs[i] != r {
				i++
			}
			if i < len(rs) {
				i++
			}
			raw := string(rs[start:i])
			text.WriteString(raw)
			cur.tokens = append(cur.tokens, token{word: strings.Trim(raw, "\"`"), quoted: true, raw: raw})
		case r == '$' && dollarTag(rs, i) != "":
			tag := []rune(dollarTag(rs, i))
			start := i
			i += len(tag)
			for i < len(rs) && !hasPrefix(rs[i:], tag) {
				i++
			}
			i = min(i+len(tag), len(rs))
			text.WriteString(string(rs[start:i]))
			cur.tokens = append(cur.tokens, token{raw: "$…$"})
		case r == ';':
			i++
			flush()
		case unicode.IsLetter(r) || r == '_':
			start := i
			for i < len(rs) && (unicode.IsLetter(rs[i]) || unicode.IsDigit(rs[i]) || rs[i] == '_' || rs[i] == '$' || rs[i] == '.') {
				i++
			}
			raw := string(rs[start:i])
			text.WriteString(raw)
			cur.tokens = append(cur.tokens, token{word: strings.ToLower(raw), raw: raw})
		default:
			text.WriteRune(r)
			if !unicode.IsSpace(r) {
				cur.tokens = append(cur.tokens, token{raw: string(r)})
			}
			i++
		}
	}
	flush()
	return stmts
}

func hasPrefix(rs, prefix []rune) bool {
	if len(rs) < len(prefix) {
		return false
	}
	for i := range prefix {
		if rs[i] != prefix[i] {
			return false
		}
	}
	return true
}

// dollarTag returns "$tag$" if a dollar-quote starts at rs[i].
func dollarTag(rs []rune, i int) string {
	j := i + 1
	for j < len(rs) && (unicode.IsLetter(rs[j]) || rs[j] == '_' || (j > i+1 && unicode.IsDigit(rs[j]))) {
		j++
	}
	if j < len(rs) && rs[j] == '$' {
		return string(rs[i : j+1])
	}
	return ""
}

// dropObjects are the object kinds whose DROP is held.
var dropObjects = map[string]bool{
	"table": true, "database": true, "schema": true, "view": true, "index": true,
	"materialized": true, "sequence": true, "function": true, "procedure": true,
	"type": true, "extension": true, "trigger": true, "role": true, "user": true,
	"owned": true, "publication": true, "subscription": true, "tablespace": true,
}

func classifyStatement(st statement) (Finding, bool) {
	toks := st.tokens
	kw := func(i int) string {
		if i < len(toks) && !toks[i].quoted {
			return toks[i].word
		}
		return ""
	}
	show := st.text
	if len([]rune(show)) > maxStatementShown {
		show = string([]rune(show)[:maxStatementShown]) + "…"
	}
	// Skip a leading CTE: "WITH x AS (...) DELETE FROM t".
	start := 0
	if kw(0) == "with" {
		depth := 0
		for i, t := range toks {
			switch t.raw {
			case "(":
				depth++
			case ")":
				depth--
			}
			if depth == 0 && i > 0 && (kw(i) == "delete" || kw(i) == "update" || kw(i) == "truncate") {
				start = i
				break
			}
		}
	}
	switch kw(start) {
	case "drop":
		obj := kw(start + 1)
		if !dropObjects[obj] {
			return Finding{}, false
		}
		kind := "DROP " + strings.ToUpper(obj)
		i := start + 2
		if obj == "materialized" {
			kind, i = "DROP MATERIALIZED VIEW", start+3
		}
		return Finding{Kind: kind, Target: targetAfter(toks, i), Statement: show}, true
	case "truncate":
		return Finding{Kind: "TRUNCATE", Target: targetAfter(toks, start+1), Statement: show}, true
	case "delete":
		if !hasTopLevel(toks[start:], "where") {
			return Finding{Kind: "DELETE without WHERE", Target: targetAfter(toks, start+2), Statement: show}, true
		}
	case "update":
		if !hasTopLevel(toks[start:], "where") {
			return Finding{Kind: "UPDATE without WHERE", Target: targetAfter(toks, start+1), Statement: show}, true
		}
	case "alter":
		if kw(start+1) == "table" && dropsData(toks[start:]) {
			return Finding{Kind: "ALTER TABLE … DROP", Target: targetAfter(toks, start+2), Statement: show}, true
		}
	}
	return Finding{}, false
}

// targetAfter returns the first object name at or after i, skipping
// modifiers such as IF EXISTS, ONLY, CONCURRENTLY, TABLE, FROM.
func targetAfter(toks []token, i int) string {
	skip := map[string]bool{"if": true, "exists": true, "only": true, "concurrently": true,
		"table": true, "from": true, "view": true, "cascade": true, "restrict": true}
	for ; i < len(toks); i++ {
		t := toks[i]
		if t.word == "" {
			continue
		}
		if !t.quoted && skip[t.word] {
			continue
		}
		return t.raw
	}
	return ""
}

// dropsData reports whether an ALTER TABLE contains a top-level DROP that
// removes data or structure (DROP COLUMN/CONSTRAINT/...), as opposed to
// DROP DEFAULT / DROP NOT NULL / DROP IDENTITY / DROP EXPRESSION.
func dropsData(toks []token) bool {
	harmless := map[string]bool{"default": true, "not": true, "identity": true, "expression": true}
	depth := 0
	for i, t := range toks {
		switch t.raw {
		case "(":
			depth++
		case ")":
			depth--
		}
		if depth != 0 || t.quoted || t.word != "drop" {
			continue
		}
		if i+1 >= len(toks) || toks[i+1].quoted || !harmless[toks[i+1].word] {
			return true
		}
	}
	return false
}

// hasTopLevel reports whether keyword appears outside parentheses.
func hasTopLevel(toks []token, keyword string) bool {
	depth := 0
	for _, t := range toks {
		switch t.raw {
		case "(":
			depth++
		case ")":
			depth--
		}
		if depth == 0 && !t.quoted && t.word == keyword {
			return true
		}
	}
	return false
}
