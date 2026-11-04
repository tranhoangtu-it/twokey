// Package sqlclass finds destructive SQL statements (DROP, TRUNCATE,
// DELETE/UPDATE without WHERE, ALTER … DROP, MERGE … DELETE) for the
// Postgres and MySQL guards, including statements nested in CTEs, EXPLAIN
// ANALYZE, COPY, PREPARE and routine bodies. Code it cannot see (DO blocks,
// CALL, dynamic SQL, text it cannot tokenize) is reported as uninspectable.
// It is a dialect-aware lexer, not a full parser.
package sqlclass

import "fmt"

// Dialect selects the lexical rules of a server.
type Dialect int

const (
	// Postgres: nesting block comments, E'…' and $tag$ strings, "idents".
	Postgres Dialect = iota
	// MySQL: # and "-- " comments, non-nesting and executable /*! */
	// comments, backslash escapes, "strings" and `idents`.
	MySQL
)

// KindUninspectable marks code the guard cannot see into; Reason says why.
const KindUninspectable = "UNINSPECTABLE"

// MaxInspect is the largest statement text classified; anything longer is
// reported as uninspectable (classification cost grows with the input).
const MaxInspect = 1 << 20

// maxNesting bounds recursion into routine bodies and prepared text.
const maxNesting = 4

// Finding is one destructive (or uninspectable) statement.
type Finding struct {
	Kind      string // e.g. "DROP TABLE", "TRUNCATE", "DELETE without WHERE", KindUninspectable
	Target    string // object name when known; one finding per object
	Statement string // the statement text (comments removed, possibly truncated)
	Reason    string // why it could not be inspected (KindUninspectable only)
}

// maxStatementShown bounds statement text shown to humans.
const maxStatementShown = 200

// Classify returns the destructive statements in Postgres sql.
func Classify(sql string) []Finding { return ClassifyDialect(sql, Postgres) }

// ClassifyMySQL is Classify for MySQL syntax.
func ClassifyMySQL(sql string) []Finding { return ClassifyDialect(sql, MySQL) }

// ClassifyDialect returns the destructive statements in sql. Literals
// whose extent depends on a server setting (a backslash in a plain string:
// standard_conforming_strings, NO_BACKSLASH_ESCAPES) are lexed both ways
// and the findings united.
func ClassifyDialect(sql string, d Dialect) []Finding {
	return classifyText(sql, d, 0, false)
}

func classifyText(sql string, d Dialect, nest int, inBody bool) []Finding {
	if len(sql) > MaxInspect {
		return []Finding{uninspectable(fmt.Sprintf("statement text is larger than %d bytes", MaxInspect), clip([]rune(sql[:4*maxStatementShown])))}
	}
	if nest > maxNesting {
		return []Finding{uninspectable("statements nested too deeply to inspect", clip([]rune(sql)))}
	}
	rs := []rune(sql)
	primary := lexOpts{dialect: d, plainBackslash: d == MySQL}
	res := lex(rs, primary)
	out := classifyStatements(rs, res.stmts, d, nest, inBody)
	if res.bad != "" {
		out = append(out, uninspectable(res.bad, clip(rs)))
	}
	if res.ambiguous {
		alt := lex(rs, lexOpts{dialect: d, plainBackslash: !primary.plainBackslash})
		stmts := alt.stmts
		if alt.bad != "" {
			// Under this interpretation a literal never ends, so the server
			// rejects the statement holding it (the last one). Postgres
			// parses the whole message first, so nothing runs; MySQL runs
			// the statements before it.
			if d == Postgres {
				stmts = nil
			} else if len(stmts) > 0 {
				stmts = stmts[:len(stmts)-1]
			}
		}
		out = union(out, classifyStatements(rs, stmts, d, nest, inBody))
	}
	return out
}

func classifyStatements(rs []rune, stmts [][]token, d Dialect, nest int, inBody bool) []Finding {
	var out []Finding
	for _, toks := range stmts {
		st := &stmt{rs: rs, toks: toks, d: d, nest: nest, inBody: inBody}
		out = append(out, st.classify()...)
	}
	return out
}

func uninspectable(reason, statement string) Finding {
	return Finding{Kind: KindUninspectable, Reason: reason, Statement: statement}
}

// union appends the findings of b that are not already in a.
func union(a, b []Finding) []Finding {
	seen := map[Finding]bool{}
	for _, f := range a {
		seen[f] = true
	}
	for _, f := range b {
		if !seen[f] {
			seen[f] = true
			a = append(a, f)
		}
	}
	return a
}

// clip trims and truncates text shown to humans.
func clip(rs []rune) string {
	i, j := 0, len(rs)
	for i < j && isSQLSpace(rs[i]) {
		i++
	}
	for j > i && isSQLSpace(rs[j-1]) {
		j--
	}
	if j-i > maxStatementShown {
		return string(rs[i:i+maxStatementShown]) + "…"
	}
	return string(rs[i:j])
}
