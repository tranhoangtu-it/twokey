package sqlclass

type tokKind uint8

const (
	tWord   tokKind = iota // keyword or unquoted identifier
	tQuoted                // "quoted" or `backtick` identifier
	tString                // string literal ('…', E'…', MySQL "…")
	tDollar                // Postgres $tag$ … $tag$ body
	tPunct                 // any other single character
)

// token is one lexical unit. Offsets index the rune slice being lexed.
type token struct {
	kind       tokKind
	p          rune   // the character, for tPunct
	backslash  bool   // tString: backslash escapes applied inside it
	depth      int32  // parenthesis depth; '(' and ')' carry the outer depth
	start, end int32  // raw text is rs[start:end]
	word       string // tWord: lowercased text
}

type lexOpts struct {
	dialect Dialect
	// plainBackslash: backslash escapes apply to plain '…' literals (and
	// "…" literals in MySQL). True for MySQL by default, and for Postgres
	// with standard_conforming_strings=off.
	plainBackslash bool
}

type lexResult struct {
	stmts [][]token // tokens of each statement (split on ';')
	// bad explains why the input could not be tokenized ("" when it could):
	// the guard cannot tell where the text it did not understand ends.
	bad string
	// ambiguous: a plain literal contained a backslash, so its extent
	// depends on a server setting (classify under both interpretations).
	ambiguous bool
}

// lex tokenizes rs. It never indexes past len(rs).
func lex(rs []rune, o lexOpts) lexResult {
	var res lexResult
	var cur []token
	var depth int32
	inExec := false // inside a MySQL /*! … */ executable comment
	my := o.dialect == MySQL
	n := len(rs)
	add := func(t token) {
		t.depth = depth
		cur = append(cur, t)
	}
	fail := func(why string) {
		if res.bad == "" {
			res.bad = why
		}
	}
	for i := 0; i < n; {
		r := rs[i]
		switch {
		case isSQLSpace(r):
			i++
		case r == '-' && i+1 < n && rs[i+1] == '-' && (!my || i+2 >= n || isMySQLDashSpace(rs[i+2])),
			my && r == '#':
			i = lineEnd(rs, i)
		case r == '/' && i+1 < n && rs[i+1] == '*':
			if my {
				if j, ok := mysqlExecOpener(rs, i); ok {
					inExec = true
					i = j
					continue
				}
				j := indexPair(rs, i+2, '*', '/')
				if j < 0 {
					fail("unterminated comment")
					i = n
					continue
				}
				i = j + 2
				continue
			}
			j, ok := pgCommentEnd(rs, i)
			if !ok {
				fail("unterminated comment")
			}
			i = j
		case my && inExec && r == '*' && i+1 < n && rs[i+1] == '/':
			inExec = false
			i += 2
		case r == '\'' || (my && r == '"'):
			end, ok, sawBS := scanLiteral(rs, i, r, o.plainBackslash)
			if sawBS {
				res.ambiguous = true
			}
			if !ok {
				fail("unterminated string literal")
			}
			add(token{kind: tString, backslash: o.plainBackslash, start: int32(i), end: int32(end)})
			i = end
		case r == '"' || (my && r == '`'):
			end, ok, _ := scanLiteral(rs, i, r, false)
			if !ok {
				fail("unterminated quoted identifier")
			}
			add(token{kind: tQuoted, start: int32(i), end: int32(end)})
			i = end
		case !my && r == '$' && dollarTagLen(rs, i) > 0:
			tl := dollarTagLen(rs, i)
			j := indexRunes(rs, i+tl, rs[i:i+tl])
			end := j + tl
			if j < 0 {
				fail("unterminated dollar-quoted string")
				end = n
			}
			add(token{kind: tDollar, start: int32(i), end: int32(end)})
			i = end
		case r == ';':
			if len(cur) > 0 {
				res.stmts = append(res.stmts, cur)
			}
			cur, depth = nil, 0
			i++
		case isIdentStart(r):
			j := i + 1
			for j < n && isIdentCont(rs[j]) {
				j++
			}
			// Postgres E'…' (only a lone e/E directly before the quote)
			// always uses backslash escapes.
			if !my && j == i+1 && (r == 'e' || r == 'E') && j < n && rs[j] == '\'' {
				end, ok, _ := scanLiteral(rs, j, '\'', true)
				if !ok {
					fail("unterminated string literal")
				}
				add(token{kind: tString, backslash: true, start: int32(i), end: int32(end)})
				i = end
				continue
			}
			add(token{kind: tWord, start: int32(i), end: int32(j), word: lowerASCII(rs[i:j])})
			i = j
		case r == '(':
			add(token{kind: tPunct, p: r, start: int32(i), end: int32(i + 1)})
			depth++
			i++
		case r == ')':
			if depth > 0 {
				depth--
			}
			add(token{kind: tPunct, p: r, start: int32(i), end: int32(i + 1)})
			i++
		default:
			add(token{kind: tPunct, p: r, start: int32(i), end: int32(i + 1)})
			i++
		}
	}
	if len(cur) > 0 {
		res.stmts = append(res.stmts, cur)
	}
	return res
}

// scanLiteral scans a literal opened by quote at rs[i], where a doubled
// quote is an escaped quote and, with backslash, \x escapes x. It returns
// the end offset (past the closing quote), whether it was closed, and
// whether a backslash occurred inside.
func scanLiteral(rs []rune, i int, quote rune, backslash bool) (end int, ok, sawBackslash bool) {
	n := len(rs)
	for j := i + 1; j < n; j++ {
		switch rs[j] {
		case '\\':
			sawBackslash = true
			if backslash {
				j++ // skip the escaped character
			}
		case quote:
			if j+1 < n && rs[j+1] == quote {
				j++
				continue
			}
			return j + 1, true, sawBackslash
		}
	}
	return n, false, sawBackslash
}

// pgCommentEnd returns the offset past a (nesting) Postgres block comment
// starting at rs[i].
func pgCommentEnd(rs []rune, i int) (int, bool) {
	depth := 0
	n := len(rs)
	for i < n {
		switch {
		case rs[i] == '/' && i+1 < n && rs[i+1] == '*':
			depth++
			i += 2
		case rs[i] == '*' && i+1 < n && rs[i+1] == '/':
			depth--
			i += 2
			if depth == 0 {
				return i, true
			}
		default:
			i++
		}
	}
	return n, false
}

// mysqlExecOpener recognizes /*! , /*!NNNNN , /*M! and /*M!NNNNNN (MySQL
// and MariaDB executable comments, whose body the server runs) and
// returns the offset of the body.
func mysqlExecOpener(rs []rune, i int) (int, bool) {
	j := i + 2
	n := len(rs)
	switch {
	case j < n && rs[j] == '!':
		j++
	case j+1 < n && (rs[j] == 'M' || rs[j] == 'm') && rs[j+1] == '!':
		j += 2
	default:
		return 0, false
	}
	for j < n && rs[j] >= '0' && rs[j] <= '9' {
		j++
	}
	return j, true
}

// lineEnd returns the offset of the line break ending a -- or # comment.
// Both \n and \r end it (ending early only makes the guard read more code).
func lineEnd(rs []rune, i int) int {
	for i < len(rs) && rs[i] != '\n' && rs[i] != '\r' {
		i++
	}
	return i
}

// dollarTagLen returns the length of a $tag$ opener at rs[i], or 0.
func dollarTagLen(rs []rune, i int) int {
	j := i + 1
	for j < len(rs) && (isIdentStart(rs[j]) || (j > i+1 && rs[j] >= '0' && rs[j] <= '9')) {
		j++
	}
	if j < len(rs) && rs[j] == '$' {
		return j + 1 - i
	}
	return 0
}

// indexPair finds the first a followed by b at or after i, or -1.
func indexPair(rs []rune, i int, a, b rune) int {
	for ; i+1 < len(rs); i++ {
		if rs[i] == a && rs[i+1] == b {
			return i
		}
	}
	return -1
}

// indexRunes finds sub in rs at or after i, or -1.
func indexRunes(rs []rune, i int, sub []rune) int {
	for ; i+len(sub) <= len(rs); i++ {
		match := true
		for k := range sub {
			if rs[i+k] != sub[k] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// isSQLSpace is the whitespace both servers skip between tokens.
func isSQLSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

// isMySQLDashSpace: MySQL starts a -- comment only when a whitespace or
// control character follows the dashes.
func isMySQLDashSpace(r rune) bool { return r <= ' ' || r == 0x7f }

// Identifiers: letters, '_' and any non-ASCII character start them (both
// servers treat bytes >= 0x80 as identifier characters); '.' is kept so
// qualified names stay one token.
func isIdentStart(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r >= 0x80
}

func isIdentCont(r rune) bool {
	return isIdentStart(r) || (r >= '0' && r <= '9') || r == '$' || r == '.'
}

func lowerASCII(rs []rune) string {
	b := make([]rune, len(rs))
	for i, r := range rs {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b[i] = r
	}
	return string(b)
}
