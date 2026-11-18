package svgscan

import (
	"encoding/base64"
	"math/rand/v2"
	"strings"
	"testing"
)

func TestSVGActiveContent(t *testing.T) {
	for _, source := range []string{
		`<svg><script>ignored()</script></svg>`,
		`<svg onload = "ignored()"/>`,
		`<svg><image onerror="ignored()"/></svg>`,
		`<svg><foreignObject><div>HTML</div></foreignObject></svg>`,
		`<svg><animate onbegin = "ignored()"/></svg>`,
		`<svg><set onend="ignored()"/></svg>`,
		`<svg><animateTransform onrepeat="ignored()"/></svg>`,
		`<svg><a href="java&#x73;cript:ignored()"/></svg>`,
		`<svg><a xlink:href="java&#10;script:ignored()"/></svg>`,
		`<svg><image href="data:text/html;base64,PGgxPkhUTUw8L2gxPg=="/></svg>`,
		`<svg><image href="data:application/javascript,ignored()"/></svg>`,
		`<svg><animate attributeName="xlink:href" values="#ok;javascript:ignored()"/></svg>`,
		`<svg><set attributeName="href" to="data:image/svg+xml;base64,PHN2Zy8+"/></svg>`,
		`<svg xmlns:s="http://www.w3.org/2000/svg"><s:script/></svg>`,
	} {
		t.Run(source, func(t *testing.T) {
			r := Scan([]byte(source))
			if !r.Active() || !r.Complete {
				t.Fatalf("missed active content: %+v", r)
			}
		})
	}
}

func TestSVGInertContent(t *testing.T) {
	for _, source := range []string{
		`<svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"><path d="M0 0 L20 20"/></svg>`,
		`<svg><!-- <script> onload="example()" --><desc>&lt;script&gt; is documentation</desc></svg>`,
		`<svg><animate attributeName="opacity" values="0;1"/><animateTransform attributeName="transform"/><set attributeName="href" to="#icon"/></svg>`,
		`<svg><image href="data:image/png;base64,iVBORw0KGgo="/></svg>`,
		`<svg><image href="https://example.invalid/image.png"/></svg>`,
	} {
		r := Scan([]byte(source))
		if r.Active() || len(r.Findings) != 0 || !r.Complete {
			t.Fatalf("inert SVG flagged: %s: %+v", source, r)
		}
	}
}

func TestSVGEncodedPayload(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(rand.IntN(256))
	}
	for _, magic := range []string{"dex\n035\x00", "\x7fELF", "MZ", "PK\x03\x04"} {
		copy(data, magic)
		encoded := base64.StdEncoding.EncodeToString(data)
		for _, source := range []string{
			"<svg><!--" + encoded + "--></svg>",
			"<svg><metadata>" + encoded + "</metadata></svg>",
			"<svg><desc>" + encoded + "</desc></svg>",
			"<svg><path d=\"" + encoded + "\"/></svg>",
		} {
			r := Scan([]byte(source))
			if len(r.Findings) != 1 || r.Findings[0].Rule != "svg.embedded_payload" || r.Active() {
				t.Fatalf("payload missed: %+v", r)
			}
		}
	}
	for i := range data {
		data[i] = byte(rand.IntN(256))
	}
	r := Scan([]byte("<svg><metadata>" + base64.StdEncoding.EncodeToString(data) + "</metadata></svg>"))
	if len(r.Findings) != 1 || r.Findings[0].Severity != "low" {
		t.Fatalf("entropy alone escalated: %+v", r)
	}
}

func TestSVGIncompleteInspection(t *testing.T) {
	for _, source := range []string{`<svg onload="`, "<svg>" + strings.Repeat(" ", MaxBytes), strings.Repeat("<g>", 257)} {
		if Scan([]byte(source)).Complete {
			t.Fatal("incomplete scan presented as complete")
		}
	}
}
