package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// gqlCall is one top-level mutation field selection. Aliases are ignored on
// purpose: `keep: volumeDelete(...)` is still a volumeDelete.
type gqlCall struct {
	name string
	args map[string]string // flattened: "volumeId", "input.id", "ids.0"
}

type graphqlCalls struct {
	mutations []gqlCall
}

type graphqlPayload struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName"`
	Variables     map[string]any `json:"variables"`
}

// errNoPayload means the request carries no GraphQL operation at all (e.g. a
// bare GET or an empty body), so there is nothing to hold.
var errNoPayload = errors.New("no GraphQL payload")

// maxFragmentDepth bounds fragment recursion on hostile input.
const maxFragmentDepth = 10

// maxSelections bounds the top-level selections visited per operation once
// fragments are expanded: fragments that each spread the next one many
// times fan out exponentially (CPU exhaustion) long before the depth cap.
const maxSelections = 10000

// maxArgValues bounds the flattened argument values across all selections:
// one large variable referenced by thousands of fields is the same fan-out.
const maxArgValues = 100000

// parseGraphQLBody extracts every mutation field the request would execute.
// It accepts a single JSON payload, a batched JSON array, a raw
// application/graphql body, or GraphQL-over-GET query parameters. Anything it
// cannot fully read is an error (other than errNoPayload) so the caller can
// fail closed.
func parseGraphQLBody(req Request) (*graphqlCalls, error) {
	payloads, err := graphqlPayloads(req)
	if err != nil {
		return nil, err
	}
	out := &graphqlCalls{}
	for _, p := range payloads {
		if p.Query == "" {
			return nil, errors.New("no query text (persisted query?)")
		}
		calls, err := mutationCalls(p)
		if err != nil {
			return nil, err
		}
		out.mutations = append(out.mutations, calls...)
	}
	return out, nil
}

func graphqlPayloads(req Request) ([]graphqlPayload, error) {
	body := bytes.TrimSpace(req.Body)
	if len(body) == 0 {
		p, err := payloadFromQuery(req.Query)
		if err != nil {
			return nil, err
		}
		return []graphqlPayload{p}, nil
	}
	switch body[0] {
	case '{':
		var p graphqlPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		return []graphqlPayload{p}, nil
	case '[':
		var ps []graphqlPayload
		if err := json.Unmarshal(body, &ps); err != nil {
			return nil, fmt.Errorf("invalid JSON batch: %w", err)
		}
		return ps, nil
	default:
		return []graphqlPayload{{Query: string(body)}}, nil
	}
}

// payloadFromQuery reads GraphQL over GET: ?query=...&operationName=...&variables={...}
func payloadFromQuery(rawQuery string) (graphqlPayload, error) {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return graphqlPayload{}, fmt.Errorf("invalid query string: %w", err)
	}
	if q.Get("query") == "" {
		if q.Has("extensions") {
			return graphqlPayload{}, errors.New("no query text (persisted query?)")
		}
		return graphqlPayload{}, errNoPayload
	}
	p := graphqlPayload{Query: q.Get("query"), OperationName: q.Get("operationName")}
	if v := q.Get("variables"); v != "" {
		if err := json.Unmarshal([]byte(v), &p.Variables); err != nil {
			return graphqlPayload{}, fmt.Errorf("invalid variables: %w", err)
		}
	}
	return p, nil
}

func mutationCalls(p graphqlPayload) ([]gqlCall, error) {
	doc, err := parser.ParseQuery(&ast.Source{Input: p.Query})
	if err != nil {
		return nil, fmt.Errorf("invalid GraphQL: %v", err)
	}
	var calls []gqlCall
	for _, op := range doc.Operations {
		if op.Operation != ast.Mutation {
			continue
		}
		// With several operations, the server runs only operationName.
		if p.OperationName != "" && len(doc.Operations) > 1 && op.Name != p.OperationName {
			continue
		}
		w := &selectionWalker{frags: doc.Fragments, vars: p.Variables}
		calls, err = w.appendFieldCalls(calls, op.SelectionSet, 0)
		if err != nil {
			return nil, err
		}
	}
	return calls, nil
}

// selectionWalker expands the top-level selections of one operation.
type selectionWalker struct {
	frags   ast.FragmentDefinitionList
	vars    map[string]any
	visited int
	values  int
}

func (w *selectionWalker) appendFieldCalls(calls []gqlCall, set ast.SelectionSet, depth int) ([]gqlCall, error) {
	if depth > maxFragmentDepth {
		return nil, fmt.Errorf("fragments nested deeper than %d", maxFragmentDepth)
	}
	var err error
	for _, sel := range set {
		if w.visited++; w.visited > maxSelections {
			return nil, fmt.Errorf("more than %d selections once fragments are expanded", maxSelections)
		}
		switch s := sel.(type) {
		case *ast.Field:
			args := map[string]string{}
			for _, a := range s.Arguments {
				flattenGraphQLValue(a.Name, a.Value, w.vars, args)
			}
			if w.values += len(args); w.values > maxArgValues {
				return nil, fmt.Errorf("more than %d argument values", maxArgValues)
			}
			calls = append(calls, gqlCall{name: s.Name, args: args})
		case *ast.InlineFragment:
			calls, err = w.appendFieldCalls(calls, s.SelectionSet, depth+1)
		case *ast.FragmentSpread:
			f := w.frags.ForName(s.Name)
			if f == nil {
				return nil, fmt.Errorf("unknown fragment %q", s.Name)
			}
			calls, err = w.appendFieldCalls(calls, f.SelectionSet, depth+1)
		}
		if err != nil {
			return nil, err
		}
	}
	return calls, nil
}

func flattenGraphQLValue(prefix string, v *ast.Value, vars map[string]any, out map[string]string) {
	if v == nil {
		return
	}
	switch v.Kind {
	case ast.Variable:
		flattenJSON(prefix, vars[v.Raw], out)
	case ast.ObjectValue:
		for _, c := range v.Children {
			flattenGraphQLValue(prefix+"."+c.Name, c.Value, vars, out)
		}
	case ast.ListValue:
		for i, c := range v.Children {
			flattenGraphQLValue(prefix+"."+strconv.Itoa(i), c.Value, vars, out)
		}
	default:
		out[prefix] = v.Raw
	}
}

// flattenJSON turns decoded JSON into dotted keys ("input.id", "ids.0").
func flattenJSON(prefix string, v any, out map[string]string) {
	join := func(k string) string {
		if prefix == "" {
			return k
		}
		return prefix + "." + k
	}
	switch t := v.(type) {
	case nil:
	case map[string]any:
		for k, child := range t {
			flattenJSON(join(k), child, out)
		}
	case []any:
		for i, child := range t {
			flattenJSON(join(strconv.Itoa(i)), child, out)
		}
	case string:
		out[prefix] = t
	default:
		out[prefix] = fmt.Sprint(t)
	}
}
