package insights

import (
	"encoding/json"
	"html"
	"strings"
	"time"
)

func BuildGraph(target string, jni *JNIReport, privacy *PrivacyReport) *GraphReport {
	g := &GraphReport{GeneratedAt: time.Now(), Target: target}
	seen := map[string]struct{}{}
	addNode := func(n GraphNode) {
		if n.ID == "" {
			return
		}
		if _, ok := seen[n.ID]; ok {
			return
		}
		seen[n.ID] = struct{}{}
		g.Nodes = append(g.Nodes, n)
	}
	addEdge := func(from, to, label string) {
		if from == "" || to == "" {
			return
		}
		g.Edges = append(g.Edges, GraphEdge{From: from, To: to, Label: label})
	}
	root := "target:" + target
	addNode(GraphNode{ID: root, Label: "Target", Kind: "target"})
	if jni != nil {
		for _, lib := range jni.NativeLibraries {
			libID := "lib:" + lib.Path
			addNode(GraphNode{ID: libID, Label: lib.Name, Kind: "native_lib", Severity: severityFromScore(int(lib.Size % 100))})
			addEdge(root, libID, "contains")
		}
		for _, load := range jni.LoadLibraries {
			clsID := "class:" + load.Class
			libID := "libname:" + load.Library
			addNode(GraphNode{ID: clsID, Label: shortClass(load.Class), Kind: "java_class"})
			addNode(GraphNode{ID: libID, Label: load.Library, Kind: "native_lib"})
			addEdge(clsID, libID, "loadLibrary")
		}
		for _, b := range jni.Bindings {
			clsID := "class:" + b.JavaClass
			methodID := "method:" + b.JavaClass + "->" + b.JavaMethod
			libID := "lib:" + firstNonEmpty(b.LibraryPath, b.Library)
			addNode(GraphNode{ID: clsID, Label: shortClass(b.JavaClass), Kind: "java_class"})
			addNode(GraphNode{ID: methodID, Label: b.JavaMethod, Kind: "native_method", Severity: confidenceSeverity(b.Confidence)})
			addNode(GraphNode{ID: libID, Label: firstNonEmpty(b.Library, b.LibraryPath), Kind: "native_lib"})
			addEdge(clsID, methodID, "declares")
			addEdge(methodID, libID, "jni")
		}
	}
	if privacy != nil {
		for _, p := range privacy.Permissions {
			id := "perm:" + p.Name
			addNode(GraphNode{ID: id, Label: trimPermission(p.Name), Kind: "permission", Severity: permissionSeverity(p.Name)})
			addEdge(root, id, "requests")
		}
		for _, t := range privacy.Trackers {
			id := "tracker:" + t.Name
			addNode(GraphNode{ID: id, Label: t.Name, Kind: "tracker", Severity: "medium"})
			addEdge(root, id, "uses")
		}
		for _, f := range privacy.Flows {
			srcID := "source:" + f.Source
			sinkID := "sink:" + f.Sink
			addNode(GraphNode{ID: srcID, Label: f.Source, Kind: "privacy_source", Severity: "high"})
			addNode(GraphNode{ID: sinkID, Label: f.Sink, Kind: "privacy_sink", Severity: "medium"})
			addEdge(srcID, sinkID, "flows_to")
			if f.Endpoint != "" {
				epID := "endpoint:" + f.Endpoint
				addNode(GraphNode{ID: epID, Label: f.Endpoint, Kind: "endpoint", Severity: "medium"})
				addEdge(sinkID, epID, "sends_to")
			}
		}
	}
	g.Summary = GraphStats{Nodes: len(g.Nodes), Edges: len(g.Edges)}
	return g
}

func RenderGraphHTML(g *GraphReport) string {
	if g == nil {
		return "<html><body><h1>Graph Explorer</h1><p>No graph data.</p></body></html>"
	}
	data, _ := json.Marshal(g)
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>Mega-Analyzer Graph Explorer</title>`)
	b.WriteString(`<style>body{margin:0;background:#0b1020;color:#eef2ff;font-family:Inter,Segoe UI,Arial,sans-serif}.wrap{display:grid;grid-template-columns:320px 1fr;min-height:100vh}.side{background:#111936;border-right:1px solid #26345f;padding:22px;overflow:auto}.main{padding:22px}.stat{display:inline-block;background:#1c2a52;border:1px solid #334678;border-radius:12px;padding:10px 14px;margin:4px}.search{width:100%;box-sizing:border-box;background:#0b1020;color:#fff;border:1px solid #334678;border-radius:10px;padding:10px;margin:12px 0}.node{background:#141f42;border:1px solid #304678;border-radius:14px;padding:12px;margin:10px 0;cursor:pointer}.node:hover{border-color:#8ab4ff}.kind{font-size:12px;color:#9fb0d8}.sev-high{border-color:#ff6b6b}.sev-medium{border-color:#ffd166}.sev-low{border-color:#5dd39e}.edge{color:#b6c4ee;margin:6px 0}.detail{position:sticky;top:16px;background:#111936;border:1px solid #334678;border-radius:16px;padding:16px;margin-bottom:16px}.pill{display:inline-block;border-radius:999px;background:#26345f;padding:3px 9px;margin-right:5px}</style>`)
	b.WriteString(`</head><body><div class="wrap"><aside class="side"><h1>Graph Explorer</h1>`)
	b.WriteString(`<div class="stat"><b id="nodeCount">0</b><br>nodes</div><div class="stat"><b id="edgeCount">0</b><br>edges</div>`)
	b.WriteString(`<input class="search" id="q" placeholder="filter nodes / edges"><div id="detail" class="detail">Click a node to inspect it.</div><h2>Nodes</h2><div id="nodes"></div></aside><main class="main"><h2>Edges</h2><div id="edges"></div></main></div>`)
	b.WriteString(`<script id="graph-data" type="application/json">`)
	b.WriteString(strings.ReplaceAll(string(data), "</", "<\\/"))
	b.WriteString(`</script><script>`)
	b.WriteString(`const g=JSON.parse(document.getElementById('graph-data').textContent);const nodes=document.getElementById('nodes'),edges=document.getElementById('edges'),detail=document.getElementById('detail'),q=document.getElementById('q');nodeCount.textContent=g.nodes.length;edgeCount.textContent=g.edges.length;function esc(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}function draw(){const f=q.value.toLowerCase();nodes.innerHTML='';edges.innerHTML='';const ids=new Set();g.nodes.filter(n=>(n.label+n.kind+n.id).toLowerCase().includes(f)).forEach(n=>{ids.add(n.id);const d=document.createElement('div');d.className='node sev-'+(n.severity||'low');d.innerHTML='<b>'+esc(n.label)+'</b><div class="kind">'+esc(n.kind)+'</div>';d.onclick=()=>detail.innerHTML='<h3>'+esc(n.label)+'</h3><p><span class="pill">'+esc(n.kind)+'</span><span class="pill">'+esc(n.severity||'info')+'</span></p><pre>'+esc(JSON.stringify(n,null,2))+'</pre>';nodes.appendChild(d)});g.edges.filter(e=>ids.has(e.from)||ids.has(e.to)||e.label.toLowerCase().includes(f)).forEach(e=>{const d=document.createElement('div');d.className='edge';d.textContent=e.from+' -- '+e.label+' --> '+e.to;edges.appendChild(d)})}q.oninput=draw;draw();`)
	b.WriteString(`</script></body></html>`)
	return b.String()
}

func shortClass(cls string) string {
	cls = strings.TrimPrefix(strings.TrimSuffix(cls, ";"), "L")
	parts := strings.Split(cls, "/")
	if len(parts) == 0 {
		return cls
	}
	return parts[len(parts)-1]
}

func trimPermission(p string) string { return strings.TrimPrefix(p, "android.permission.") }

func permissionSeverity(p string) string {
	if strings.Contains(p, "SMS") || strings.Contains(p, "CONTACTS") || strings.Contains(p, "LOCATION") || strings.Contains(p, "RECORD_AUDIO") {
		return "high"
	}
	return "medium"
}

func confidenceSeverity(c float64) string {
	if c >= 0.9 {
		return "high"
	}
	if c >= 0.6 {
		return "medium"
	}
	return "low"
}

func severityFromScore(score int) string {
	if score >= 70 {
		return "high"
	}
	if score >= 35 {
		return "medium"
	}
	return "low"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func EscapeText(s string) string { return html.EscapeString(s) }
