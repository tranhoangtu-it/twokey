package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

// parseGraphQLBody extracts every mutation field the request would execute.
// It accepts a single JSON payload, a batched JSON array, or a raw
// application/graphql body. Any request it cannot fully read is an error so
// the caller can fail closed.
func parseGraphQLBody(req Request) (*graphqlCalls, error) {
	body := bytes.TrimSpace(req.Body)
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}

	var payloads []graphqlPayload
	switch body[0] {
	case '{':
		var p graphqlPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		payloads = []graphqlPayload{p}
	case '[':
		if err := json.Unmarshal(body, &payloads); err != nil {
			return nil, fmt.Errorf("invalid JSON batch: %w", err)
		}
	default:
		payloads = []graphqlPayload{{Query: string(body)}}
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
		calls = appendFieldCalls(calls, op.SelectionSet, doc.Fragments, p.Variables, 0)
	}
	return calls, nil
}

// maxFragmentDepth bounds fragment recursion on hostile input.
const maxFragmentDepth = 10

func appendFieldCalls(calls []gqlCall, set ast.SelectionSet, frags ast.FragmentDefinitionList, vars map[string]any, depth int) []gqlCall {
	if depth > maxFragmentDepth {
		return calls
	}
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			args := map[string]string{}
			for _, a := range s.Arguments {
				flattenGraphQLValue(a.Name, a.Value, vars, args)
			}
			calls = append(calls, gqlCall{name: s.Name, args: args})
		case *ast.InlineFragment:
			calls = appendFieldCalls(calls, s.SelectionSet, frags, vars, depth+1)
		case *ast.FragmentSpread:
			if f := frags.ForName(s.Name); f != nil {
				calls = appendFieldCalls(calls, f.SelectionSet, frags, vars, depth+1)
			}
		}
	}
	return calls
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
