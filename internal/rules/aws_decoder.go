package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type awsCall struct {
	// actions holds every action name the request carries. Servers differ
	// on which of several Action values wins, so all of them are evaluated.
	actions []string
	params  map[string]string
}

// parseAWSCall identifies the AWS API actions of a request:
//   - JSON protocol (DynamoDB, ECS, ...): header "X-Amz-Target: Service_Version.Action"
//   - Query protocol (RDS, EC2, IAM, CloudFormation, ...): "Action=" in the
//     form body or in the query string.
//
// REST-style AWS services (S3, Lambda, EKS) are matched with path rules. A
// query string or form body that does not decode is an error so the caller
// fails closed: an Action could hide behind the malformed part.
func parseAWSCall(req Request) (*awsCall, error) {
	call := &awsCall{params: map[string]string{}}
	seen := map[string]bool{}
	addAction := func(a string) {
		if a = strings.TrimSpace(a); a != "" && !seen[a] {
			seen[a] = true
			call.actions = append(call.actions, a)
		}
	}

	body := bytes.TrimSpace(req.Body)
	targets := req.Header.Values("X-Amz-Target")
	for _, target := range targets {
		for _, t := range strings.Split(target, ",") {
			addAction(t[strings.LastIndexByte(t, '.')+1:])
		}
	}
	if len(targets) > 0 {
		var v any
		if json.Unmarshal(body, &v) == nil {
			flattenJSON("", v, call.params)
		}
	}

	values, err := url.ParseQuery(req.Query)
	if err != nil {
		return nil, fmt.Errorf("query string: %w", err)
	}
	// Query-protocol bodies are forms; don't trust Content-Type (raw HTTP
	// clients may omit it). JSON/XML bodies are skipped.
	if len(body) > 0 && body[0] != '{' && body[0] != '[' && body[0] != '<' {
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, fmt.Errorf("form body: %w", err)
		}
		for k, vs := range form {
			values[k] = append(values[k], vs...)
		}
	}
	for _, a := range values["Action"] {
		addAction(a)
	}
	for k, vs := range values {
		if len(vs) == 0 || k == "Action" {
			continue
		}
		prev, inJSON := call.params[k]
		if !allEqual(vs) || (inJSON && prev != vs[0]) {
			delete(call.params, k)
			continue
		}
		call.params[k] = vs[0]
	}
	return call, nil
}

// allEqual reports whether every value is the same; a parameter given twice
// with different values must not be shown to the approver as "the" target.
func allEqual(vs []string) bool {
	for _, v := range vs[1:] {
		if v != vs[0] {
			return false
		}
	}
	return true
}
