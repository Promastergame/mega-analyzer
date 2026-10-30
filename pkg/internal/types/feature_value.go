package types

import (
	"encoding/json"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE VALUE — ОПТИМИЗИРОВАННАЯ СЕРИАЛИЗАЦИЯ (фикс #8)
// ═══════════════════════════════════════════════════════════════════════════════

type FeatureValueType uint8

const (
	FeatureValueNone FeatureValueType = iota
	FeatureValueBool
	FeatureValueInt
	FeatureValueFloat
	FeatureValueString
	FeatureValueStrings
)

var featureValueTypeNames = [6]string{"none", "bool", "int", "float", "string", "strings"}

func (t FeatureValueType) String() string {
	if int(t) < len(featureValueTypeNames) {
		return featureValueTypeNames[t]
	}
	return "none"
}

// FeatureValue — типобезопасный union.
type FeatureValue struct {
	Type    FeatureValueType `json:"-"`
	Bool    bool             `json:"-"`
	Int     int64            `json:"-"`
	Float   float64          `json:"-"`
	String  string           `json:"-"`
	Strings []string         `json:"-"`
}

// Конструкторы
func BoolValue(v bool) FeatureValue     { return FeatureValue{Type: FeatureValueBool, Bool: v} }
func IntValue(v int64) FeatureValue     { return FeatureValue{Type: FeatureValueInt, Int: v} }
func FloatValue(v float64) FeatureValue { return FeatureValue{Type: FeatureValueFloat, Float: v} }
func StringValue(v string) FeatureValue { return FeatureValue{Type: FeatureValueString, String: v} }

// StringsValue — с копированием slice (фикс #14).
func StringsValue(v []string) FeatureValue {
	cp := make([]string, len(v))
	copy(cp, v)
	return FeatureValue{Type: FeatureValueStrings, Strings: cp}
}

func (f FeatureValue) IsEmpty() bool { return f.Type == FeatureValueNone }

func (f FeatureValue) AsInterface() interface{} {
	switch f.Type {
	case FeatureValueBool:
		return f.Bool
	case FeatureValueInt:
		return f.Int
	case FeatureValueFloat:
		return f.Float
	case FeatureValueString:
		return f.String
	case FeatureValueStrings:
		return f.Strings
	default:
		return nil
	}
}

// featureValueJSON — struct вместо map (фикс #8: меньше аллокаций).
type featureValueJSON struct {
	Type  string      `json:"type"`
	Value interface{} `json:"value,omitempty"`
}

func (f FeatureValue) MarshalJSON() ([]byte, error) {
	var fv featureValueJSON
	switch f.Type {
	case FeatureValueBool:
		fv = featureValueJSON{Type: "bool", Value: f.Bool}
	case FeatureValueInt:
		fv = featureValueJSON{Type: "int", Value: f.Int}
	case FeatureValueFloat:
		fv = featureValueJSON{Type: "float", Value: f.Float}
	case FeatureValueString:
		fv = featureValueJSON{Type: "string", Value: f.String}
	case FeatureValueStrings:
		fv = featureValueJSON{Type: "strings", Value: f.Strings}
	default:
		fv = featureValueJSON{Type: "none"}
	}
	return json.Marshal(fv)
}

func (f *FeatureValue) UnmarshalJSON(data []byte) error {
	var raw struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch raw.Type {
	case "bool":
		f.Type = FeatureValueBool
		return json.Unmarshal(raw.Value, &f.Bool)
	case "int":
		f.Type = FeatureValueInt
		return json.Unmarshal(raw.Value, &f.Int)
	case "float":
		f.Type = FeatureValueFloat
		return json.Unmarshal(raw.Value, &f.Float)
	case "string":
		f.Type = FeatureValueString
		return json.Unmarshal(raw.Value, &f.String)
	case "strings":
		f.Type = FeatureValueStrings
		return json.Unmarshal(raw.Value, &f.Strings)
	default:
		f.Type = FeatureValueNone
	}
	return nil
}
