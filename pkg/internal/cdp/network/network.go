// Package network is a minimal drop-in for github.com/chromedp/cdproto/network,
// exposing only what this project uses: Network.enable and the
// requestWillBeSent event with its resource types.
package network

import (
	"context"
	"errors"

	"mega-analyzer/pkg/internal/cdp/cdpconn"
)

// ResourceType mirrors CDP Network.ResourceType.
type ResourceType string

// Resource types (subset).
const (
	ResourceTypeDocument   ResourceType = "Document"
	ResourceTypeStylesheet ResourceType = "Stylesheet"
	ResourceTypeImage      ResourceType = "Image"
	ResourceTypeMedia      ResourceType = "Media"
	ResourceTypeFont       ResourceType = "Font"
	ResourceTypeScript     ResourceType = "Script"
	ResourceTypeXHR        ResourceType = "XHR"
	ResourceTypeFetch      ResourceType = "Fetch"
	ResourceTypeWebSocket  ResourceType = "WebSocket"
	ResourceTypeOther      ResourceType = "Other"
)

// PostDataEntry mirrors CDP Network.PostDataEntry (Bytes is base64-encoded,
// matching cdproto's field semantics).
type PostDataEntry struct {
	Bytes string `json:"bytes,omitempty"`
}

// Request mirrors the subset of CDP Network.Request used by callers.
type Request struct {
	URL             string           `json:"url"`
	Method          string           `json:"method"`
	HasPostData     bool             `json:"hasPostData,omitempty"`
	PostData        string           `json:"postData,omitempty"`
	PostDataEntries []*PostDataEntry `json:"postDataEntries,omitempty"`
}

// EventRequestWillBeSent mirrors CDP Network.requestWillBeSent (subset).
type EventRequestWillBeSent struct {
	RequestID string       `json:"requestId,omitempty"`
	Request   *Request     `json:"request"`
	Type      ResourceType `json:"type,omitempty"`
}

func init() {
	cdpconn.RegisterEvent("Network.requestWillBeSent", func() interface{} {
		return &EventRequestWillBeSent{}
	})
}

// EnableParams is the parameter set for Network.enable.
type EnableParams struct{}

// Enable returns an action that enables network tracking.
func Enable() *EnableParams { return &EnableParams{} }

// Do executes Network.enable against the CDP connection in ctx.
func (p *EnableParams) Do(ctx context.Context) error {
	c := cdpconn.FromContext(ctx)
	if c == nil {
		return errors.New("network: no cdp connection in context")
	}
	return c.Execute(ctx, "Network.enable", map[string]interface{}{}, nil)
}
