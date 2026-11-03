package rules

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
)

type awsCall struct {
	action string
	params map[string]string
}

// parseAWSCall identifies the AWS API action of a request:
//   - JSON protocol (DynamoDB, ECS, ...): header "X-Amz-Target: Service_Version.Action"
//   - Query protocol (RDS, EC2, IAM, CloudFormation, ...): "Action=" in the
//     form body or in the query string.
//
// REST-style AWS services (S3, Lambda, EKS) are matched with path rules.
func parseAWSCall(req Request) *awsCall {
	call := &awsCall{params: map[string]string{}}

	if target := req.Header.Get("X-Amz-Target"); target != "" {
		call.action = target[strings.LastIndexByte(target, '.')+1:]
		var body any
		if json.Unmarshal(bytes.TrimSpace(req.Body), &body) == nil {
			flattenJSON("", body, call.params)
		}
		return call
	}

	values, _ := url.ParseQuery(req.Query)
	// Query-protocol bodies are forms; don't trust Content-Type (raw HTTP
	// clients may omit it). JSON/XML bodies are skipped.
	body := bytes.TrimSpace(req.Body)
	if len(body) > 0 && body[0] != '{' && body[0] != '[' && body[0] != '<' {
		if form, err := url.ParseQuery(string(body)); err == nil {
			for k, v := range form {
				values[k] = v
			}
		}
	}
	for k, v := range values {
		if len(v) > 0 {
			call.params[k] = v[0]
		}
	}
	call.action = call.params["Action"]
	return call
}
