package sqlclass

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		sql        string
		wantKind   string // "" = must not be flagged
		wantTarget string
	}{
		{"DROP TABLE users", "DROP TABLE", "users"},
		{"drop table if exists public.orders cascade", "DROP TABLE", "public.orders"},
		{"DROP DATABASE prod", "DROP DATABASE", "prod"},
		{"DROP SCHEMA billing CASCADE", "DROP SCHEMA", "billing"},
		{"DROP MATERIALIZED VIEW IF EXISTS mv", "DROP MATERIALIZED VIEW", "mv"},
		{`DROP TABLE "Users"`, "DROP TABLE", `"Users"`},
		{"TRUNCATE TABLE sessions", "TRUNCATE", "sessions"},
		{"truncate only audit_log", "TRUNCATE", "audit_log"},
		{"DELETE FROM users", "DELETE without WHERE", "users"},
		{"delete from users where id = 1", "", ""},
		{"DELETE FROM a USING b WHERE a.id = b.id", "", ""},
		{"DELETE FROM t WHERE id IN (SELECT id FROM t2)", "", ""},
		{"DELETE FROM t RETURNING (SELECT 1 WHERE true)", "DELETE without WHERE", "t"},
		{"UPDATE accounts SET balance = 0", "UPDATE without WHERE", "accounts"},
		{"UPDATE accounts SET balance = 0 WHERE id = 7", "", ""},
		{"WITH old AS (SELECT id FROM t WHERE x) DELETE FROM t", "DELETE without WHERE", "t"},
		{"ALTER TABLE users DROP COLUMN email", "ALTER TABLE … DROP", "users"},
		{"ALTER TABLE users ALTER COLUMN email DROP NOT NULL", "", ""},
		{"ALTER TABLE users ALTER COLUMN n DROP DEFAULT", "", ""},
		{"ALTER TABLE users ADD COLUMN drop_me int", "", ""},
		{"SELECT 'drop table users'", "", ""},
		{"SELECT 1 -- drop table users", "", ""},
		{"SELECT 1 /* drop /* nested */ table users */", "", ""},
		{"SELECT $$ drop table users; $$", "", ""},
		{"SELECT $fn$ truncate x $fn$", "", ""},
		{`SELECT "drop" FROM t`, "", ""},
		{"CREATE TABLE t (id int)", "", ""},
		{"DROP POLICY p ON t", "", ""}, // not data-destroying
	}
	for _, tc := range tests {
		got := Classify(tc.sql)
		if tc.wantKind == "" {
			if len(got) != 0 {
				t.Errorf("%q: want no finding, got %+v", tc.sql, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Kind != tc.wantKind || got[0].Target != tc.wantTarget {
			t.Errorf("%q: got %+v, want %s on %s", tc.sql, got, tc.wantKind, tc.wantTarget)
		}
	}
}

func TestClassifyMySQL(t *testing.T) {
	tests := []struct {
		sql        string
		wantKind   string
		wantTarget string
	}{
		{"DROP TABLE `orders`", "DROP TABLE", "`orders`"},
		{"# cleanup\nDROP DATABASE shop", "DROP DATABASE", "shop"},
		{"TRUNCATE TABLE sessions", "TRUNCATE", "sessions"},
		{"DELETE FROM users", "DELETE without WHERE", "users"},
		{"SELECT \"drop table users\"", "", ""},   // double quotes are strings in MySQL
		{"SELECT 'it\\'s; drop table x'", "", ""}, // backslash escape keeps the string open
		{"SELECT `drop` FROM t", "", ""},          // backtick identifier
		{"SELECT 1 # drop table users", "", ""},   // # comment
		{"UPDATE accounts SET balance = 0 WHERE id = 1", "", ""},
	}
	for _, tc := range tests {
		got := ClassifyMySQL(tc.sql)
		if tc.wantKind == "" {
			if len(got) != 0 {
				t.Errorf("%q: want no finding, got %+v", tc.sql, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Kind != tc.wantKind || got[0].Target != tc.wantTarget {
			t.Errorf("%q: got %+v, want %s on %s", tc.sql, got, tc.wantKind, tc.wantTarget)
		}
	}
}

func TestClassifyMultipleStatements(t *testing.T) {
	got := Classify("SELECT 1; DROP TABLE a; UPDATE b SET x = 1 WHERE y; TRUNCATE c")
	if len(got) != 2 || got[0].Target != "a" || got[1].Target != "c" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Statement != "DROP TABLE a" {
		t.Fatalf("statement text = %q", got[0].Statement)
	}
}
