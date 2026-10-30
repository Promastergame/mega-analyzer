package vulnscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Clone gives each probe its own body and headers; captured requests are immutable.
func (b *BaseRequest) Clone() *BaseRequest {
	if b == nil {
		return nil
	}
	c := *b
	c.Body = bytes.Clone(b.Body)
	c.Headers = make(map[string]string, len(b.Headers))
	for k, v := range b.Headers {
		c.Headers[k] = v
	}
	c.HeaderValues = b.HeaderValues.Clone()
	return &c
}

func (b *BaseRequest) HTTPRequest(ctx context.Context) (*http.Request, error) {
	if b == nil || b.Incomplete {
		return nil, fmt.Errorf("cannot replay an incomplete request")
	}
	r, err := http.NewRequestWithContext(ctx, b.Method, b.URL, bytes.NewReader(b.Body))
	if err != nil {
		return nil, err
	}
	for k, v := range b.Headers {
		r.Header.Set(k, v)
	}
	for k, v := range b.HeaderValues {
		r.Header[k] = append([]string(nil), v...)
	}
	// Framing belongs to net/http, not to the captured request.
	r.Header.Del("Content-Length")
	r.Header.Del("Transfer-Encoding")
	return r, nil
}

func baseHeader(b *BaseRequest, name string) string {
	if v := b.HeaderValues.Get(name); v != "" {
		return v
	}
	for k, v := range b.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// FormFromRequest discovers query, nested JSON (RFC 6901 pointers), form and
// multipart fields without discarding the request that produced them.
func FormFromRequest(b *BaseRequest) (Form, error) {
	if b == nil {
		return Form{}, fmt.Errorf("nil request template")
	}
	f := Form{Action: b.URL, Method: strings.ToUpper(b.Method), Enctype: baseHeader(b, "Content-Type"), Request: b.Clone()}
	u, err := url.Parse(b.URL)
	if err != nil {
		return f, err
	}
	addValues := func(v url.Values, loc PointLocation) {
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for i, value := range v[k] {
				f.Points = append(f.Points, InjectionPoint{Name: k, Location: loc, DataType: InferInputType(k), Original: value, Index: i})
			}
		}
	}
	addValues(u.Query(), LocationQueryParam)
	ct, params, _ := mime.ParseMediaType(f.Enctype)
	switch {
	case ct == "application/json" || strings.HasSuffix(ct, "+json"):
		var data any
		dec := json.NewDecoder(bytes.NewReader(b.Body))
		dec.UseNumber()
		if err := dec.Decode(&data); err != nil {
			return f, fmt.Errorf("decode JSON request: %w", err)
		}
		if dec.Decode(new(any)) != io.EOF {
			return f, fmt.Errorf("JSON request contains trailing data")
		}
		var walk func(any, string, int)
		walk = func(v any, path string, depth int) {
			if depth > 32 || len(f.Points) >= 512 {
				f.Request.Incomplete = true
				return
			}
			switch x := v.(type) {
			case map[string]any:
				keys := make([]string, 0, len(x))
				for k := range x {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					walk(x[k], path+"/"+pointerEscape(k), depth+1)
				}
			case []any:
				for i, value := range x {
					walk(value, path+"/"+strconv.Itoa(i), depth+1)
				}
			default:
				original := fmt.Sprint(v)
				if v == nil {
					original = "null"
				}
				kind := InferInputType(path)
				if _, ok := v.(json.Number); ok {
					kind = TypeNumeric
				}
				f.Points = append(f.Points, InjectionPoint{Name: path, Location: LocationJSONField, DataType: kind, Original: original})
			}
		}
		walk(data, "", 0)
	case ct == "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(b.Body))
		if err != nil {
			return f, err
		}
		addValues(values, LocationBody)
	case ct == "multipart/form-data":
		reader := multipart.NewReader(bytes.NewReader(b.Body), params["boundary"])
		counts := map[string]int{}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return f, err
			}
			data, err := io.ReadAll(io.LimitReader(part, 5<<20))
			if err != nil {
				return f, err
			}
			if name := part.FormName(); name != "" {
				if part.FileName() == "" {
					f.Points = append(f.Points, InjectionPoint{Name: name, Location: LocationBody, DataType: InferInputType(name), Original: string(data), Index: counts[name]})
				}
				counts[name]++
			}
			part.Close()
		}
	}
	for _, p := range f.Points {
		f.Inputs = append(f.Inputs, p.Name)
	}
	return f, nil
}

func pointerEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
func pointerParts(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("expected JSON pointer, got %q", path)
	}
	p := strings.Split(path[1:], "/")
	for i := range p {
		p[i] = strings.ReplaceAll(strings.ReplaceAll(p[i], "~1", "/"), "~0", "~")
	}
	return p, nil
}

func jsonPointer(data any, path string) (any, error) {
	parts, err := pointerParts(path)
	if err != nil {
		return nil, err
	}
	for _, p := range parts {
		switch x := data.(type) {
		case map[string]any:
			var ok bool
			data, ok = x[p]
			if !ok {
				return nil, fmt.Errorf("JSON pointer %q not found", path)
			}
		case []any:
			i, e := strconv.Atoi(p)
			if e != nil || i < 0 || i >= len(x) {
				return nil, fmt.Errorf("invalid JSON array index")
			}
			data = x[i]
		default:
			return nil, fmt.Errorf("JSON pointer traverses a scalar")
		}
	}
	return data, nil
}

func setJSONPointer(data any, path string, value string) (any, error) {
	parts, err := pointerParts(path)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return value, nil
	}
	parent := data
	for _, p := range parts[:len(parts)-1] {
		parent, err = jsonPointer(parent, "/"+pointerEscape(p))
		if err != nil {
			return nil, err
		}
	}
	key := parts[len(parts)-1]
	switch x := parent.(type) {
	case map[string]any:
		if _, ok := x[key]; !ok {
			return nil, fmt.Errorf("missing JSON field")
		}
		x[key] = value
	case []any:
		i, e := strconv.Atoi(key)
		if e != nil || i < 0 || i >= len(x) {
			return nil, fmt.Errorf("invalid JSON array index")
		}
		x[i] = value
	default:
		return nil, fmt.Errorf("JSON pointer parent is a scalar")
	}
	return data, nil
}

// MutateRequest changes exactly one injection point. Sibling fields, duplicate
// values, binary uploads and request headers survive unchanged.
func MutateRequest(ctx context.Context, base *BaseRequest, point InjectionPoint, value string) (*http.Request, error) {
	b := base.Clone()
	if b == nil || b.Incomplete {
		return nil, fmt.Errorf("cannot mutate an incomplete request")
	}
	u, err := url.Parse(b.URL)
	if err != nil {
		return nil, err
	}
	setValue := func(v url.Values) error {
		values, ok := v[point.Name]
		if !ok || point.Index < 0 || point.Index >= len(values) {
			return fmt.Errorf("parameter %q occurrence %d missing", point.Name, point.Index)
		}
		values[point.Index] = value
		return nil
	}
	switch point.Location {
	case LocationQueryParam:
		v := u.Query()
		if err = setValue(v); err != nil {
			return nil, err
		}
		u.RawQuery = v.Encode()
		b.URL = u.String()
	case LocationJSONField:
		var data any
		dec := json.NewDecoder(bytes.NewReader(b.Body))
		dec.UseNumber()
		if err = dec.Decode(&data); err != nil {
			return nil, err
		}
		data, err = setJSONPointer(data, point.Name, value)
		if err != nil {
			return nil, err
		}
		b.Body, err = json.Marshal(data)
		if err != nil {
			return nil, err
		}
	case LocationBody:
		ct, params, _ := mime.ParseMediaType(baseHeader(b, "Content-Type"))
		if ct == "multipart/form-data" {
			reader := multipart.NewReader(bytes.NewReader(b.Body), params["boundary"])
			var buf bytes.Buffer
			writer := multipart.NewWriter(&buf)
			// Retaining the boundary also preserves the Content-Type header.
			if err = writer.SetBoundary(params["boundary"]); err != nil {
				return nil, err
			}
			index := 0
			found := false
			for {
				p, e := reader.NextRawPart()
				if e == io.EOF {
					break
				}
				if e != nil {
					return nil, e
				}
				dst, e := writer.CreatePart(p.Header)
				if e != nil {
					return nil, e
				}
				if p.FormName() == point.Name {
					if index == point.Index {
						_, err = io.WriteString(dst, value)
						found = true
					} else {
						_, err = io.Copy(dst, p)
					}
					index++
				} else {
					_, err = io.Copy(dst, p)
				}
				p.Close()
				if err != nil {
					return nil, err
				}
			}
			if !found {
				return nil, fmt.Errorf("multipart field missing")
			}
			if err = writer.Close(); err != nil {
				return nil, err
			}
			b.Body = buf.Bytes()
		} else {
			v, e := url.ParseQuery(string(b.Body))
			if e != nil {
				return nil, e
			}
			if err = setValue(v); err != nil {
				return nil, err
			}
			b.Body = []byte(v.Encode())
		}
	case LocationHeader:
		if b.HeaderValues == nil {
			b.HeaderValues = http.Header{}
		}
		b.HeaderValues.Set(point.Name, value)
	case LocationCookie:
		r, e := b.HTTPRequest(ctx)
		if e != nil {
			return nil, e
		}
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		found := false
		for _, c := range cookies {
			if c.Name == point.Name {
				c.Value = value
				found = true
			}
			r.AddCookie(c)
		}
		if !found {
			return nil, fmt.Errorf("cookie missing")
		}
		b.HeaderValues = r.Header
	case LocationPathSegment:
		parts := strings.Split(u.EscapedPath(), "/")
		i, e := strconv.Atoi(point.Name)
		if e != nil || i < 0 || i >= len(parts) {
			return nil, fmt.Errorf("invalid path segment")
		}
		parts[i] = url.PathEscape(value)
		u.RawPath = strings.Join(parts, "/")
		u.Path, err = url.PathUnescape(u.RawPath)
		if err != nil {
			return nil, err
		}
		b.URL = u.String()
	default:
		return nil, fmt.Errorf("unsupported injection location %s", point.Location)
	}
	return b.HTTPRequest(ctx)
}

func (s *Scanner) formProbe(form Form, input, value string) (*http.Request, error) {
	if form.Request != nil {
		for _, p := range form.Points {
			if p.Name == input {
				return MutateRequest(s.context(), form.Request, p, value)
			}
		}
		return nil, fmt.Errorf("unknown captured parameter %q", input)
	}
	method := form.Method
	if method == "" {
		method = http.MethodGet
	}
	v := url.Values{}
	for _, name := range form.Inputs {
		v.Set(name, "test")
	}
	v.Set(input, value)
	u, err := url.Parse(form.Action)
	if err != nil {
		return nil, err
	}
	if method == "GET" || method == "HEAD" {
		q := u.Query()
		for k, values := range v {
			q[k] = values
		}
		u.RawQuery = q.Encode()
		return http.NewRequestWithContext(s.context(), method, u.String(), nil)
	}
	r, err := http.NewRequestWithContext(s.context(), method, u.String(), strings.NewReader(v.Encode()))
	if err == nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return r, err
}
