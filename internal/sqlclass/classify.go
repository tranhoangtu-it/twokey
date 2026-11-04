package sqlclass

import "strings"

// stmt is one ';'-separated statement being classified.
type stmt struct {
	rs     []rune
	toks   []token
	d      Dialect
	nest   int
	inBody bool // inside a routine body (plpgsql): EXECUTE is dynamic SQL
	shown  string
}

// verbs start a statement that can destroy data.
var verbs = map[string]bool{"drop": true, "truncate": true, "delete": true, "update": true, "alter": true, "merge": true}

// startAfter are words after which a verb starts a nested statement:
// routine bodies (BEGIN, THEN, ELSE, LOOP, REPEAT, BEGIN ATOMIC), trigger
// bodies (FOR EACH ROW), rules (DO INSTEAD/ALSO), RETURN QUERY.
var startAfter = map[string]bool{
	"begin": true, "then": true, "else": true, "loop": true, "repeat": true, "atomic": true,
	"row": true, "instead": true, "also": true, "query": true,
}

// harmlessDrops are DROP forms that destroy no data: MySQL DROP PREPARE
// (deallocates a prepared statement), MySQL DROP TEMPORARY TABLE (session
// scratch tables) and DROP POLICY.
var harmlessDrops = map[string]bool{"prepare": true, "temporary": true, "policy": true}

// dropKindWords are object kinds named by more than one word.
var dropKindWords = map[string][]string{
	"materialized": {"view"}, "foreign": {"table", "data"}, "event": {"trigger"}, "text": {"search"},
	"access": {"method"}, "user": {"mapping"}, "operator": {"class", "family"},
}

func (s *stmt) kw(i int) string {
	if i >= 0 && i < len(s.toks) && s.toks[i].kind == tWord {
		return s.toks[i].word
	}
	return ""
}

func (s *stmt) isPunct(i int, p rune) bool {
	return i >= 0 && i < len(s.toks) && s.toks[i].kind == tPunct && s.toks[i].p == p
}

func (s *stmt) raw(i int) string {
	t := s.toks[i]
	return string(s.rs[t.start:t.end])
}

// show is the statement text for humans: tokens joined, comments removed.
func (s *stmt) show() string {
	if s.shown != "" {
		return s.shown
	}
	var b []rune
	for i, t := range s.toks {
		if i > 0 && t.start != s.toks[i-1].end {
			b = append(b, ' ')
		}
		b = append(b, s.rs[t.start:t.end]...)
		if len(b) > maxStatementShown {
			break
		}
	}
	s.shown = clip(b)
	return s.shown
}

func (s *stmt) classify() []Finding {
	if len(s.toks) == 0 {
		return nil
	}
	if fs, ok := s.opaque(); ok {
		return fs
	}
	var out []Finding
	if s.d == Postgres && s.kw(0) == "create" && s.definesRoutine() {
		out = append(out, s.routineBodies()...)
	}
	if s.inBody {
		out = append(out, s.dynamicSQL()...)
	}
	explain := s.kw(0) == "explain" || s.kw(0) == "describe" || s.kw(0) == "desc"
	for i, t := range s.toks {
		if t.kind != tWord || !verbs[t.word] {
			continue
		}
		start := s.startsStatement(i)
		if explain && t.depth == 0 {
			start, explain = true, false
		}
		if start {
			out = append(out, s.sub(i)...)
		}
	}
	return out
}

// opaque reports statements that run code the guard cannot see.
func (s *stmt) opaque() ([]Finding, bool) {
	switch k := s.kw(0); {
	case k == "do" && s.d == Postgres:
		return s.one("DO block runs procedural code twokey cannot inspect")
	case k == "call":
		return s.one("CALL runs a stored procedure twokey cannot inspect")
	case k == "copy" && s.d == Postgres && s.hasWordAt(0, "program", 0):
		return s.one("COPY … PROGRAM runs a shell command on the database server")
	case k == "prepare" && s.d == MySQL:
		return s.mysqlPrepare()
	}
	return nil, false
}

func (s *stmt) one(reason string) ([]Finding, bool) {
	return []Finding{uninspectable(reason, s.show())}, true
}

// mysqlPrepare handles PREPARE name FROM <text>: a string literal is
// classified; a variable or expression cannot be seen.
func (s *stmt) mysqlPrepare() ([]Finding, bool) {
	i := 3 // PREPARE name FROM …
	if s.kw(2) != "from" {
		return s.one("PREPARE statement twokey cannot parse")
	}
	if strings.HasPrefix(s.kw(i), "_") { // charset introducer: _utf8mb4'…'
		i++
	}
	if i == len(s.toks)-1 && s.toks[i].kind == tString {
		return classifyText(s.literal(i), MySQL, s.nest+1, false), true
	}
	return s.one("PREPARE from a variable or expression cannot be inspected")
}

// dynamicSQL finds plpgsql EXECUTE in a routine body: a literal is
// classified, anything else (variables, concatenation, format()) is
// dynamic SQL the guard cannot see.
func (s *stmt) dynamicSQL() []Finding {
	var out []Finding
	for i := range s.toks {
		if s.kw(i) != "execute" || s.kw(i-1) == "function" || s.kw(i-1) == "procedure" {
			continue
		}
		next := i + 1
		if next < len(s.toks) && (s.toks[next].kind == tString || s.toks[next].kind == tDollar) &&
			(next+1 == len(s.toks) || s.kw(next+1) == "using" || s.kw(next+1) == "into") {
			out = append(out, classifyText(s.literal(next), s.d, s.nest+1, true)...)
			continue
		}
		out = append(out, uninspectable("dynamic SQL (EXECUTE of a computed string) cannot be inspected", s.show()))
	}
	return out
}

// definesRoutine: CREATE [OR REPLACE] FUNCTION/PROCEDURE.
func (s *stmt) definesRoutine() bool {
	for i := 1; i < len(s.toks) && i < 4; i++ {
		if k := s.kw(i); k == "function" || k == "procedure" {
			return true
		}
	}
	return false
}

// routineBodies classifies the string/dollar-quoted bodies of a routine.
func (s *stmt) routineBodies() []Finding {
	var out []Finding
	for i, t := range s.toks {
		if t.depth == 0 && (t.kind == tString || t.kind == tDollar) {
			out = append(out, classifyText(s.literal(i), Postgres, s.nest+1, true)...)
		}
	}
	return out
}

// literal returns the text inside a string or dollar-quoted token.
func (s *stmt) literal(i int) string {
	t := s.toks[i]
	raw := s.rs[t.start:t.end]
	if t.kind == tDollar {
		tl := dollarTagLen(raw, 0)
		if len(raw) < 2*tl {
			return string(raw[min(tl, len(raw)):])
		}
		return string(raw[tl : len(raw)-tl])
	}
	q := 0
	for q < len(raw) && raw[q] != '\'' && raw[q] != '"' {
		q++ // skip an E prefix
	}
	if q >= len(raw) {
		return ""
	}
	quote := raw[q]
	body := raw[q+1:]
	if len(body) > 0 && body[len(body)-1] == quote {
		body = body[:len(body)-1]
	}
	var b strings.Builder
	for j := 0; j < len(body); j++ {
		c := body[j]
		switch {
		case c == '\\' && t.backslash && j+1 < len(body):
			j++
			b.WriteRune(unescape(body[j]))
		case c == quote && j+1 < len(body) && body[j+1] == quote:
			j++
			b.WriteRune(quote)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

func unescape(c rune) rune {
	switch c {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case '0':
		return 0
	case 'b':
		return '\b'
	case 'Z':
		return 0x1a
	}
	return c
}

// startsStatement reports whether the verb at i begins a statement: at the
// start, after '(' (CTE, subquery, COPY (…)), after ')' (the body of a
// WITH, EXPLAIN (…) options, a routine body after its parameter list), or
// after a body keyword.
func (s *stmt) startsStatement(i int) bool {
	if i == 0 || s.isPunct(i-1, '(') || s.isPunct(i-1, ')') {
		return true
	}
	prev := s.kw(i - 1)
	switch {
	case startAfter[prev]:
		return true
	case prev == "as":
		return s.kw(0) == "prepare" || s.kw(0) == "create"
	case prev == "do": // MySQL CREATE EVENT … DO, CREATE RULE … DO
		return !s.hasWordAt(0, "conflict", s.toks[i].depth) // INSERT … ON CONFLICT DO UPDATE is an upsert
	}
	return false
}

// hasWordAt reports whether word occurs at parenthesis depth from token i.
func (s *stmt) hasWordAt(from int, word string, depth int32) bool {
	for j := from; j < len(s.toks); j++ {
		if s.toks[j].depth == depth && s.kw(j) == word {
			return true
		}
	}
	return false
}

// span returns the end of the statement starting at i: the ')' closing
// its enclosing parenthesis, or the end of the statement.
func (s *stmt) span(i int) int {
	base := s.toks[i].depth
	for j := i + 1; j < len(s.toks); j++ {
		if s.toks[j].depth < base {
			return j
		}
	}
	return len(s.toks)
}

// within reports whether word occurs at the depth of token i in [i, end).
func (s *stmt) within(i, end int, word string) int {
	base := s.toks[i].depth
	for j := i + 1; j < end; j++ {
		if s.toks[j].depth == base && s.kw(j) == word {
			return j
		}
	}
	return -1
}

// sub classifies the statement starting with the verb at i.
func (s *stmt) sub(i int) []Finding {
	end := s.span(i)
	switch s.kw(i) {
	case "drop":
		return s.drop(i, end)
	case "truncate":
		if i+1 < end && (s.toks[i+1].kind == tWord || s.toks[i+1].kind == tQuoted) {
			return s.findings("TRUNCATE", s.names(skipWords(s, i+1, "table", "only"), end))
		}
	case "delete":
		from := s.within(i, end, "from")
		if from < 0 || s.within(i, end, "where") >= 0 {
			return nil // no FROM: MERGE … THEN DELETE, GRANT; WHERE: scoped
		}
		names := s.names(skipWords(s, i+1, "low_priority", "quick", "ignore"), from)
		if len(names) == 0 {
			names = s.names(skipWords(s, from+1, "only"), end)
		}
		return s.findings("DELETE without WHERE", names)
	case "update":
		if s.isMergeAction(i) || s.within(i, end, "set") < 0 || s.within(i, end, "where") >= 0 {
			return nil
		}
		return s.findings("UPDATE without WHERE", s.names(skipWords(s, i+1, "only", "low_priority", "ignore"), end))
	case "alter":
		return s.alter(i, end)
	case "merge":
		if s.kw(i+1) == "into" && s.mergeDeletes(i, end) {
			target := s.names(skipWords(s, i+2, "only"), end)
			if len(target) > 1 {
				target = target[:1]
			}
			return s.findings("MERGE … DELETE", target)
		}
	}
	return nil
}

// isMergeAction: WHEN … THEN UPDATE inside a MERGE (not flagged).
func (s *stmt) isMergeAction(i int) bool {
	if s.kw(i-1) != "then" {
		return false
	}
	for j := i - 1; j >= 0; j-- {
		if s.kw(j) == "merge" && s.toks[j].depth == s.toks[i].depth {
			return true
		}
	}
	return false
}

func (s *stmt) mergeDeletes(i, end int) bool {
	base := s.toks[i].depth
	for j := i + 1; j+1 < end; j++ {
		if s.toks[j].depth == base && s.kw(j) == "then" && s.kw(j+1) == "delete" {
			return true
		}
	}
	return false
}

func (s *stmt) drop(i, end int) []Finding {
	obj := s.kw(i + 1)
	if obj == "" || harmlessDrops[obj] {
		return nil
	}
	words := []string{obj}
	j := i + 2
	for _, w := range dropKindWords[obj] {
		if s.kw(j) == w {
			words = append(words, w)
			j++
			if w == "data" && s.kw(j) == "wrapper" {
				words = append(words, "wrapper")
				j++
			}
			break
		}
	}
	kind := "DROP"
	if plainWords(words) {
		kind = "DROP " + strings.ToUpper(strings.Join(words, " "))
	}
	return s.findings(kind, s.names(skipWords(s, j, "if", "exists", "concurrently", "by"), end))
}

// alter flags ALTER TABLE that drops columns/constraints/partitions or
// truncates partitions (MySQL).
func (s *stmt) alter(i, end int) []Finding {
	t := i + 1
	if s.kw(t) == "ignore" {
		t++
	}
	if s.kw(t) != "table" {
		return nil
	}
	target := s.names(skipWords(s, t+1, "if", "exists", "only"), end)
	if len(target) > 1 {
		target = target[:1]
	}
	base := s.toks[i].depth
	for j := t + 1; j < end; j++ {
		if s.toks[j].depth != base {
			continue
		}
		switch s.kw(j) {
		case "drop":
			if !s.harmlessColumnDrop(j) {
				return s.findings("ALTER TABLE … DROP", target)
			}
		case "truncate":
			if s.kw(j+1) == "partition" {
				return s.findings("ALTER TABLE … TRUNCATE", target)
			}
		}
	}
	return nil
}

// harmlessColumnDrop: ALTER [COLUMN] c DROP DEFAULT / NOT NULL / IDENTITY /
// EXPRESSION changes a column without removing data. Outside that form
// "DROP identity" drops a column named identity.
func (s *stmt) harmlessColumnDrop(j int) bool {
	switch s.kw(j + 1) {
	case "default", "not", "identity", "expression":
	default:
		return false
	}
	return s.kw(j-2) == "alter" || (s.kw(j-3) == "alter" && s.kw(j-2) == "column")
}

// skipWords advances past any of the given modifier words.
func skipWords(s *stmt, i int, words ...string) int {
	for i < len(s.toks) {
		k := s.kw(i)
		found := false
		for _, w := range words {
			if k == w {
				found = true
				break
			}
		}
		if !found {
			return i
		}
		i++
	}
	return i
}

// names reads a comma-separated list of object names starting at i:
// "a, b", "f(int), g()", "t *". It stops at anything else.
func (s *stmt) names(i, end int) []string {
	var out []string
	for i < end {
		t := s.toks[i]
		if t.kind != tWord && t.kind != tQuoted {
			break
		}
		if t.kind == tWord && listEnd[t.word] {
			break
		}
		out = append(out, s.raw(i))
		i++
		if s.isPunct(i, '(') { // argument list of a routine
			depth := t.depth
			i++
			for i < end && s.toks[i].depth > depth {
				i++
			}
			i++ // the closing ')'
		}
		if s.isPunct(i, '*') { // TRUNCATE t * (descendants)
			i++
		}
		if !s.isPunct(i, ',') {
			break
		}
		i++
	}
	return out
}

// listEnd are words that end an object-name list.
var listEnd = map[string]bool{
	"cascade": true, "restrict": true, "on": true, "from": true, "where": true, "set": true,
	"using": true, "restart": true, "continue": true, "force": true, "returning": true, "as": true,
}

// findings returns one finding per target (or one without a target).
func (s *stmt) findings(kind string, targets []string) []Finding {
	if len(targets) == 0 {
		return []Finding{{Kind: kind, Statement: s.show()}}
	}
	out := make([]Finding, 0, len(targets))
	for _, t := range targets {
		out = append(out, Finding{Kind: kind, Target: t, Statement: s.show()})
	}
	return out
}

func plainWords(words []string) bool {
	for _, w := range words {
		for _, r := range w {
			if (r < 'a' || r > 'z') && r != '_' {
				return false
			}
		}
	}
	return true
}
