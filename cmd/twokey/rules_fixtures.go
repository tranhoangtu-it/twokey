package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// cmdRulesTest checks user rule packs against their .http fixtures, the
// same way CI checks the builtin packs.
func cmdRulesTest(args []string) error {
	fs := flag.NewFlagSet("rules test", flag.ContinueOnError)
	dir := fs.String("rules", "", "rule pack directory to test (required)")
	fixtures := fs.String("fixtures", "", "directory of <rule-id>.http fixtures (default: --rules)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("usage: twokey rules test --rules DIR [--fixtures DIR]")
	}
	return rulesTest(os.Stdout, *dir, *fixtures)
}

func rulesTest(w io.Writer, dir, fixtures string) error {
	if fixtures == "" {
		fixtures = dir
	}
	packs, err := rules.LoadDir(dir)
	if err != nil {
		return fmt.Errorf("rules in %s: %w", dir, err)
	}
	engine, err := loadEngine(dir) // builtin + user: overlaps are caught too
	if err != nil {
		return err
	}
	var ids []string
	for _, p := range packs {
		for _, r := range p.Rules {
			ids = append(ids, r.ID)
		}
	}
	fails := rules.CheckFixtureDir(engine, os.DirFS(fixtures), ids)
	failed := map[string]bool{}
	for _, f := range fails {
		failed[f.Rule] = true
		fmt.Fprintf(w, "✗ %s: %s\n", f.Rule, f.Problem)
	}
	ok := 0
	for _, id := range ids {
		if !failed[id] {
			ok++
		}
	}
	fmt.Fprintf(w, "%d/%d rules verified by fixtures\n", ok, len(ids))
	if len(fails) > 0 {
		return errors.New("rule fixtures failed")
	}
	return nil
}
