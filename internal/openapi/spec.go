// Specs are the OpenTrust consumer and management OpenAPI 3.1 documents,
// vendored from /openapi.json and /api/admin/openapi.json.
package openapi

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

//go:embed consumer.openapi.json
var consumerSpec []byte

//go:embed management.openapi.json
var managementSpec []byte

// Operation is one OpenAPI operation exposed as a CLI command.
type Operation struct {
	ID           string
	Command      string
	Method       string
	Path         string
	Summary      string
	Description  string
	Scope        string
	Anonymous    bool
	Params       []Param
	JSON         bool
	File         bool
	Form         []Field
	BodyRequired bool
}

// Param is a path or query parameter.
type Param struct {
	Name        string
	Flag        string
	In          string
	Description string
}

// Field is a multipart form field other than the file.
type Field struct {
	Name     string
	Flag     string
	Required bool
}

// Load returns the operations for the consumer API or the management API.
// audience is "consumer" or "admin".
func Load(audience string) ([]Operation, error) {
	switch audience {
	case "consumer":
		return parse(consumerSpec)
	case "admin":
		return parse(managementSpec)
	default:
		return nil, fmt.Errorf("unknown API %q", audience)
	}
}

type openAPIDoc struct {
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Schemas map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
}

type operationObject struct {
	OperationID string `json:"operationId"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Parameters  []struct {
		Name        string `json:"name"`
		In          string `json:"in"`
		Description string `json:"description"`
	} `json:"parameters"`
	RequestBody *struct {
		Required bool `json:"required"`
		Content  map[string]struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
	Security    []map[string]json.RawMessage `json:"security"`
	APIKeyScope string                       `json:"x-api-key-scope"`
}

func parse(raw []byte) ([]Operation, error) {
	var doc openAPIDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var ops []Operation
	seen := map[string]struct{}{}
	for path, methods := range doc.Paths {
		for method, rawOp := range methods {
			var item operationObject
			if err := json.Unmarshal(rawOp, &item); err != nil {
				return nil, fmt.Errorf("%s %s: %w", method, path, err)
			}
			if item.OperationID == "" {
				return nil, fmt.Errorf("%s %s has no operationId", method, path)
			}
			op := Operation{
				ID:          item.OperationID,
				Command:     kebab(item.OperationID),
				Method:      strings.ToUpper(method),
				Path:        path,
				Summary:     item.Summary,
				Description: item.Description,
				Scope:       item.APIKeyScope,
			}
			if op.Summary == "" {
				op.Summary = item.OperationID
			}
			for _, requirement := range item.Security {
				if len(requirement) == 0 {
					op.Anonymous = true
				}
			}
			for _, param := range item.Parameters {
				if param.In != "path" && param.In != "query" {
					continue
				}
				op.Params = append(op.Params, Param{
					Name:        param.Name,
					Flag:        kebab(param.Name),
					In:          param.In,
					Description: param.Description,
				})
			}
			if item.RequestBody != nil {
				op.BodyRequired = item.RequestBody.Required
				if _, ok := item.RequestBody.Content["application/json"]; ok {
					op.JSON = true
				}
				if multipart, ok := item.RequestBody.Content["multipart/form-data"]; ok {
					op.File = true
					fields, err := doc.formFields(multipart.Schema)
					if err != nil {
						return nil, fmt.Errorf("%s: %w", item.OperationID, err)
					}
					op.Form = fields
				}
			}
			if _, ok := seen[op.Command]; ok {
				return nil, fmt.Errorf("duplicate command %s", op.Command)
			}
			seen[op.Command] = struct{}{}
			if err := checkFlags(op); err != nil {
				return nil, err
			}
			ops = append(ops, op)
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].Command < ops[j].Command })
	return ops, nil
}

func checkFlags(op Operation) error {
	reserved := map[string]bool{
		"body": true, "body-file": true, "file": true,
		"out": true, "api-key": true, "base-url": true, "help": true,
	}
	seen := map[string]struct{}{}
	for _, param := range op.Params {
		if reserved[param.Flag] {
			return fmt.Errorf("%s flag --%s is reserved", op.Command, param.Flag)
		}
		if _, ok := seen[param.Flag]; ok {
			return fmt.Errorf("%s has duplicate flag --%s", op.Command, param.Flag)
		}
		seen[param.Flag] = struct{}{}
	}
	for _, field := range op.Form {
		if reserved[field.Flag] || field.Flag == "file" {
			return fmt.Errorf("%s form field --%s collides with a reserved flag", op.Command, field.Flag)
		}
		if _, ok := seen[field.Flag]; ok {
			return fmt.Errorf("%s has duplicate flag --%s", op.Command, field.Flag)
		}
		seen[field.Flag] = struct{}{}
	}
	return nil
}

type schemaObject struct {
	Ref        string                     `json:"$ref"`
	Properties map[string]json.RawMessage `json:"properties"`
	Required   []string                   `json:"required"`
}

func (d openAPIDoc) formFields(raw json.RawMessage) ([]Field, error) {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" {
		return nil, nil
	}
	var schema schemaObject
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	if schema.Ref != "" {
		name := strings.TrimPrefix(schema.Ref, "#/components/schemas/")
		resolved, ok := d.Components.Schemas[name]
		if !ok {
			return nil, fmt.Errorf("missing schema %s", name)
		}
		return d.formFields(resolved)
	}
	required := map[string]bool{}
	for _, name := range schema.Required {
		required[name] = true
	}
	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		if name == "file" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	fields := make([]Field, 0, len(names))
	for _, name := range names {
		fields = append(fields, Field{Name: name, Flag: kebab(name), Required: required[name]})
	}
	return fields, nil
}

func kebab(name string) string {
	var b strings.Builder
	for i, r := range name {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('-')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}
