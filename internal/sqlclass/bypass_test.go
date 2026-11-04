package sqlclass

import (
	"fmt"
	"strings"
	"testing"
)

// kinds returns the finding kinds, in order, for compact assertions.
func kinds(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Kind)
	}
	return out
}

func hasKind(fs []Finding, kind string) bool {
	for _, f := range fs {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

// TestLexerBypasses are statements a real server runs as destructive SQL
// but that an earlier lexer hid inside a string, comment or quoted body.
func TestLexerBypasses(t *testing.T) {
	tests := []struct {
		name    string
		dialect Dialect
		sql     string
		want    string // a kind that must be reported
	}{
		{"pg E-string backslash quote", Postgres, `SELECT E'\''; DROP TABLE users; --`, "DROP TABLE"},
		{"pg e-string lowercase", Postgres, `SELECT e'\''; DROP TABLE users; --`, "DROP TABLE"},
		{"pg plain string, standard_conforming_strings=off", Postgres, `SELECT '\''; DROP TABLE users; --'`, "DROP TABLE"},
		{"pg plain string, standard_conforming_strings=on", Postgres, `SELECT 'a\'; DROP TABLE users; -- '`, "DROP TABLE"},
		{"mysql block comments do not nest", MySQL, "/* /* */ DROP TABLE x /* */", "DROP TABLE"},
		{"mysql executable comment", MySQL, "/*! DROP TABLE x */", "DROP TABLE"},
		{"mysql versioned executable comment", MySQL, "/*!50000 DROP TABLE x */", "DROP TABLE"},
		{"mysql mariadb executable comment", MySQL, "/*M!100100 DROP TABLE x */", "DROP TABLE"},
		{"mysql -- needs whitespace", MySQL, "SELECT 1--1; DROP TABLE x", "DROP TABLE"},
		{"mysql has no dollar quoting", MySQL, "SELECT 1 AS $a$; DROP TABLE x; SELECT 2 AS $a$", "DROP TABLE"},
		{"mysql NO_BACKSLASH_ESCAPES", MySQL, `SELECT 'a\'; DROP TABLE x; -- '`, "DROP TABLE"},
		{"mysql double-quoted string ends at backslash-free quote", MySQL, `SELECT "a\"; DROP TABLE x; -- "`, "DROP TABLE"},
		{"pg quoted identifier with doubled quote", Postgres, `SELECT 1 AS "a""b"; DROP TABLE x`, "DROP TABLE"},
	}
	for _, tc := range tests {
		got := ClassifyDialect(tc.sql, tc.dialect)
		if !hasKind(got, tc.want) {
			t.Errorf("%s: %q: got %v, want %s", tc.name, tc.sql, kinds(got), tc.want)
		}
	}
}

// TestStillSafe guards against the bypass fixes flagging ordinary SQL.
func TestStillSafe(t *testing.T) {
	tests := []struct {
		dialect Dialect
		sql     string
	}{
		{Postgres, `SELECT E'it\'s fine'`},
		{Postgres, `SELECT 'C:\path\to'`},
		{Postgres, "SELECT 1 -- DROP TABLE x"},
		{Postgres, "SELECT $tag$ DROP TABLE x $tag$"},
		{MySQL, "SELECT 1 -- DROP TABLE x"},
		{MySQL, "SELECT 1 /* DROP TABLE x */"},
		{MySQL, "SELECT 1 /*+ DROP TABLE x */"},
		{MySQL, `SELECT 'it\'s; DROP TABLE x'`},
		{Postgres, "INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET n = 1"},
		{MySQL, "INSERT INTO t (id) VALUES (1) ON DUPLICATE KEY UPDATE n = 1"},
		{Postgres, "SELECT * FROM t WHERE id = 1 FOR UPDATE"},
		{Postgres, "WITH a AS (SELECT 1) SELECT * FROM t FOR UPDATE"},
		{Postgres, "CREATE TABLE c (p int REFERENCES p ON DELETE CASCADE ON UPDATE CASCADE)"},
		{Postgres, "GRANT SELECT, UPDATE, DELETE ON t TO app"},
		{Postgres, "EXPLAIN SELECT * FROM t"},
		{Postgres, "PREPARE p AS SELECT * FROM t WHERE id = $1"},
		{Postgres, "EXECUTE p(1)"},
		{MySQL, "PREPARE s FROM 'SELECT * FROM t WHERE id = ?'"},
		{MySQL, "EXECUTE s USING @id"},
		{Postgres, "WITH u AS (UPDATE t SET n = 1 WHERE id = 2 RETURNING *) SELECT * FROM u"},
		{Postgres, "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET n = s.n WHEN NOT MATCHED THEN INSERT VALUES (s.id)"},
		{Postgres, "ALTER TABLE t ALTER COLUMN c DROP IDENTITY IF EXISTS"},
		{Postgres, "ALTER TABLE t ALTER c DROP EXPRESSION"},
		{MySQL, "DROP PREPARE s"},
		{MySQL, "DROP TEMPORARY TABLE IF EXISTS scratch"},
		{Postgres, "CREATE TABLE t (note text DEFAULT 'DROP TABLE x')"},
	}
	for _, tc := range tests {
		if got := ClassifyDialect(tc.sql, tc.dialect); len(got) != 0 {
			t.Errorf("%q: want no finding, got %+v", tc.sql, got)
		}
	}
}

// TestNestedStatements: destructive statements wrapped in other statements.
func TestNestedStatements(t *testing.T) {
	tests := []struct {
		dialect Dialect
		sql     string
		want    string
	}{
		{Postgres, "EXPLAIN ANALYZE DELETE FROM users", "DELETE without WHERE"},
		{Postgres, "EXPLAIN (ANALYZE, BUFFERS) UPDATE users SET a = 1", "UPDATE without WHERE"},
		{MySQL, "EXPLAIN ANALYZE DELETE FROM users", "DELETE without WHERE"},
		{Postgres, "WITH d AS (DELETE FROM users RETURNING *) SELECT 1", "DELETE without WHERE"},
		{Postgres, "WITH d AS MATERIALIZED (UPDATE users SET a = 1 RETURNING *) SELECT 1", "UPDATE without WHERE"},
		{Postgres, "WITH a AS (SELECT 1), d AS (DELETE FROM users) SELECT 1", "DELETE without WHERE"},
		{Postgres, "COPY (DELETE FROM users RETURNING *) TO STDOUT", "DELETE without WHERE"},
		{Postgres, "MERGE INTO users u USING src s ON u.id = s.id WHEN MATCHED THEN DELETE", "MERGE … DELETE"},
		{Postgres, "PREPARE p AS DELETE FROM users", "DELETE without WHERE"},
		{Postgres, "PREPARE p (int) AS DROP TABLE users", "DROP TABLE"},
		{MySQL, "CREATE PROCEDURE p() BEGIN DELETE FROM t; END", "DELETE without WHERE"},
		{MySQL, "CREATE TRIGGER g AFTER INSERT ON a FOR EACH ROW DELETE FROM b", "DELETE without WHERE"},
		{MySQL, "CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO DELETE FROM logs", "DELETE without WHERE"},
		{MySQL, "CREATE PROCEDURE p() BEGIN IF 1 THEN DROP TABLE t; END IF; END", "DROP TABLE"},
		{Postgres, "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN DELETE FROM t; END $$", "DELETE without WHERE"},
		{Postgres, "CREATE FUNCTION f() RETURNS void LANGUAGE sql AS 'TRUNCATE t'", "TRUNCATE"},
		{Postgres, "CREATE PROCEDURE p() LANGUAGE sql BEGIN ATOMIC DELETE FROM t; END", "DELETE without WHERE"},
		{MySQL, "PREPARE s FROM 'DROP TABLE x'", "DROP TABLE"},
		{MySQL, "ALTER TABLE t TRUNCATE PARTITION p0", "ALTER TABLE … TRUNCATE"},
		{MySQL, "ALTER TABLE t DROP identity", "ALTER TABLE … DROP"},
		{Postgres, "ALTER TABLE t DROP identity", "ALTER TABLE … DROP"},
		{Postgres, "DROP EVENT TRIGGER audit_ddl", "DROP EVENT TRIGGER"},
		{Postgres, "DROP DOMAIN money_amount CASCADE", "DROP DOMAIN"},
		{MySQL, "DROP EVENT nightly_cleanup", "DROP EVENT"},
		{Postgres, "DROP RULE r ON t", "DROP RULE"},
		{Postgres, "DROP FOREIGN TABLE remote_users", "DROP FOREIGN TABLE"},
	}
	for _, tc := range tests {
		got := ClassifyDialect(tc.sql, tc.dialect)
		if !hasKind(got, tc.want) {
			t.Errorf("%q: got %v, want %s", tc.sql, kinds(got), tc.want)
		}
	}
}

// TestOpaqueExecutionIsUninspectable: code twokey cannot see is held.
func TestOpaqueExecutionIsUninspectable(t *testing.T) {
	tests := []struct {
		dialect Dialect
		sql     string
	}{
		{Postgres, "DO $$ BEGIN DELETE FROM users; END $$"},
		{Postgres, "DO 'BEGIN NULL; END'"},
		{Postgres, "CALL cleanup()"},
		{MySQL, "CALL cleanup()"},
		{MySQL, "PREPARE p FROM @s"},
		{MySQL, "PREPARE p FROM CONCAT('DR', 'OP TABLE x')"},
		{Postgres, "COPY t TO PROGRAM 'rm -rf /'"},
		{Postgres, "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE 'DR' || 'OP TABLE x'; END $$"},
		{Postgres, "SELECT 'unterminated"},
		{Postgres, "SELECT $a$ unterminated"},
		{Postgres, "SELECT 1 /* unterminated"},
		{Postgres, `SELECT "unterminated`},
		{MySQL, "SELECT `unterminated"},
		{Postgres, strings.Repeat("x", MaxInspect+1)},
	}
	for _, tc := range tests {
		got := ClassifyDialect(tc.sql, tc.dialect)
		if !hasKind(got, KindUninspectable) {
			short := tc.sql
			if len(short) > 60 {
				short = short[:60]
			}
			t.Errorf("%q: got %v, want %s", short, kinds(got), KindUninspectable)
			continue
		}
		for _, f := range got {
			if f.Kind == KindUninspectable && f.Reason == "" {
				t.Errorf("%q: uninspectable finding without a reason", tc.sql)
			}
		}
	}
}

// TestMultiTargetReportsEveryObject: an allow rule for one object must not
// let a statement that also drops another object through.
func TestMultiTargetReportsEveryObject(t *testing.T) {
	tests := []struct {
		dialect Dialect
		sql     string
		kind    string
		targets []string
	}{
		{Postgres, "DROP TABLE tmp_a, prod_b", "DROP TABLE", []string{"tmp_a", "prod_b"}},
		{Postgres, "DROP TABLE IF EXISTS tmp_a, public.prod_b CASCADE", "DROP TABLE", []string{"tmp_a", "public.prod_b"}},
		{Postgres, "TRUNCATE tmp_a, prod_b RESTART IDENTITY", "TRUNCATE", []string{"tmp_a", "prod_b"}},
		{MySQL, "DROP TABLE `tmp_a`, `prod_b`", "DROP TABLE", []string{"`tmp_a`", "`prod_b`"}},
		{Postgres, "DROP FUNCTION f(int, text), g()", "DROP FUNCTION", []string{"f", "g"}},
	}
	for _, tc := range tests {
		got := ClassifyDialect(tc.sql, tc.dialect)
		var targets []string
		for _, f := range got {
			if f.Kind != tc.kind {
				t.Errorf("%q: unexpected kind %q", tc.sql, f.Kind)
			}
			targets = append(targets, f.Target)
		}
		if fmt.Sprint(targets) != fmt.Sprint(tc.targets) {
			t.Errorf("%q: targets %q, want %q", tc.sql, targets, tc.targets)
		}
	}
}

// TestTrailingBackslashNoPanic sweeps lengths so the rune slice capacity
// hits every allocator size class (an index past len panicked only for
// some lengths).
func TestTrailingBackslashNoPanic(t *testing.T) {
	for n := 2; n <= 4096; n++ {
		for _, d := range []Dialect{Postgres, MySQL} {
			sql := strings.Repeat("a", n-2) + "'\\"
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("dialect %d, length %d: panic %v", d, n, r)
					}
				}()
				ClassifyDialect(sql, d)
			}()
		}
	}
}

func TestDialectWrappersMatch(t *testing.T) {
	sql := "SELECT 1; DROP TABLE a"
	if fmt.Sprint(Classify(sql)) != fmt.Sprint(ClassifyDialect(sql, Postgres)) {
		t.Fatal("Classify must be the Postgres dialect")
	}
	if fmt.Sprint(ClassifyMySQL(sql)) != fmt.Sprint(ClassifyDialect(sql, MySQL)) {
		t.Fatal("ClassifyMySQL must be the MySQL dialect")
	}
}
