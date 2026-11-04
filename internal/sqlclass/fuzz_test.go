package sqlclass

import (
	"reflect"
	"testing"
)

// fuzzSeeds are the bypass shapes found in review plus ordinary SQL.
var fuzzSeeds = []string{
	"SELECT 1",
	`SELECT E'\''; DROP TABLE users; --`,
	`SELECT '\''; DROP TABLE users; --'`,
	"/* /* */ DROP TABLE x /* */",
	"/*!50000 DROP TABLE x */",
	"/*M! DROP TABLE x */",
	"SELECT 1--1; DROP TABLE x",
	"SELECT 1 AS $a$; DROP TABLE x; SELECT 2 AS $a$",
	"EXPLAIN ANALYZE DELETE FROM users",
	"WITH d AS (DELETE FROM users RETURNING *) SELECT 1",
	"COPY (DELETE FROM users RETURNING *) TO STDOUT",
	"DO $$ BEGIN DELETE FROM users; END $$",
	"PREPARE p FROM @s",
	"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
	"CREATE PROCEDURE p() BEGIN DELETE FROM t; END",
	"DROP TABLE tmp_a, prod_b",
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\\",
	`SELECT "a""b", 'c''d', $q$x$q$, U&'\0041'`,
}

// appended is a destructive statement added after arbitrary input.
const appended = "\n;DROP TABLE twokey_fuzz_target"

// fuzzClassify checks, for any input s:
//   - no panic, and the result is deterministic;
//   - s followed by a new statement that drops a table is never classified
//     safe. The newline ends any line comment and the ';' ends any
//     statement, so the only way the appended statement is not code is
//     that s leaves a literal, quoted identifier, dollar body or block
//     comment open — which the classifier must report as uninspectable.
//     Either way the result is non-empty.
func fuzzClassify(t *testing.T, d Dialect, s string) {
	first := ClassifyDialect(s, d)
	if again := ClassifyDialect(s, d); !reflect.DeepEqual(first, again) {
		t.Fatalf("non-deterministic: %+v vs %+v", first, again)
	}
	if got := ClassifyDialect(s+appended, d); len(got) == 0 {
		t.Fatalf("%q followed by a DROP was classified safe", s)
	}
}

func FuzzClassifyPostgres(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { fuzzClassify(t, Postgres, s) })
}

func FuzzClassifyMySQL(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { fuzzClassify(t, MySQL, s) })
}
