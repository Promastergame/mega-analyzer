package mcpclient

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
)

// Check the common object/array/primitive subset before sending a call. The MCP
// server remains responsible for its complete JSON Schema (refs, unions, etc.).
func validateArguments(raw json.RawMessage, args map[string]any) error {
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil || schema == nil {
		return fmt.Errorf("invalid tool inputSchema")
	}
	if schema["type"] != "object" {
		return fmt.Errorf("tool inputSchema must have type object")
	}
	b, err := json.Marshal(args)
	if err != nil {
		return err
	}
	var value any
	if err = json.Unmarshal(b, &value); err != nil {
		return err
	}
	return validateValue(schema, value, "arguments", 0)
}

func validateValue(s map[string]any, v any, path string, depth int) error {
	if depth > 32 {
		return fmt.Errorf("arguments nesting too deep")
	}
	if values, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range values {
			if reflect.DeepEqual(x, v) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("%s: value outside enum", path)
		}
	}
	typ, _ := s["type"].(string)
	valid := true
	switch typ {
	case "object":
		obj, ok := v.(map[string]any)
		if !ok {
			valid = false
			break
		}
		if req, ok := s["required"].([]any); ok {
			for _, key := range req {
				if k, ok := key.(string); ok {
					if _, exists := obj[k]; !exists {
						return fmt.Errorf("%s.%s is required", path, k)
					}
				}
			}
		}
		props, _ := s["properties"].(map[string]any)
		for key, value := range obj {
			child, exists := props[key]
			if !exists && s["additionalProperties"] == false {
				return fmt.Errorf("%s.%s is not allowed", path, key)
			}
			if sub, ok := child.(map[string]any); ok {
				if err := validateValue(sub, value, path+"."+key, depth+1); err != nil {
					return err
				}
			}
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			valid = false
			break
		}
		if sub, ok := s["items"].(map[string]any); ok {
			for i, value := range a {
				if err := validateValue(sub, value, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
					return err
				}
			}
		}
	case "string":
		_, valid = v.(string)
	case "boolean":
		_, valid = v.(bool)
	case "number":
		_, valid = v.(float64)
	case "integer":
		n, ok := v.(float64)
		valid = ok && n == math.Trunc(n)
	case "null":
		valid = v == nil
	}
	if !valid {
		return fmt.Errorf("%s must be %s", path, typ)
	}
	return nil
}
