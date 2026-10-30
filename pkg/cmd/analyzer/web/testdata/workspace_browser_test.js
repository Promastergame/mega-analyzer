/* Run in a disposable browser session on the Web UI:
   Get-Content -Raw <this-file> | agent-browser --session <name> eval --stdin
   Uses deterministic workspace responses; never creates files or starts scans. */
(async function () {
  "use strict";
  var checks = [], R = window.WorkspacePreview;
  function check(ok, label) { if (!ok) throw new Error(label); checks.push(label); }
  function byId(id) { return document.getElementById(id); }
  function waitFor(test) {
    var end = Date.now() + 8000;
    return new Promise(function (resolve, reject) {
      function poll() { if (test()) return resolve(); if (Date.now() > end) return reject(new Error("Timed out waiting for UI")); setTimeout(poll, 20); }
      poll();
    });
  }
  var md = "# Audit\n\n**bold** and `code`\n\n| Name | Value |\n| --- | --- |\n| Result | Ready |\n\n- Parent\n  - Child\n- [x] Done\n\n> Quote\n\n```json\n{\"ok\":true}\n```";
  var doc = R.markdown(md);
  check(doc.querySelector("h1").textContent === "Audit" && doc.querySelector("strong").textContent === "bold", "Markdown headings and inline formatting");
  check(doc.querySelectorAll("tbody td").length === 2 && doc.querySelector("ul ul li").textContent === "Child", "Markdown tables and nested lists");
  check(doc.querySelector("input").checked && doc.querySelector("input").disabled && doc.querySelector("blockquote") && doc.querySelector("pre code"), "Tasks, quotes and fenced code");
  var attack = R.markdown('<img src=x onerror=alert(1)>\n\n<script>alert(1)</script>\n\n[bad](javascript:alert) [data](data:text/html,test) [local](/api/scan) [ok](https://example.com)');
  check(!attack.querySelector("script,img,iframe,style") && attack.querySelectorAll("a").length === 1, "Markdown cannot create active HTML or unsafe links");
  check(attack.querySelector("a").rel === "noopener noreferrer", "External links isolate the opener");
  var rawJSON = '{"id":9007199254740993123,"tiny":1.234567890123456789e-50,"html":"<img onerror=x>","items":[true,null,{}]}';
  var formatted = R.formatJSON(rawJSON), json = R.json(formatted);
  check(formatted.includes("9007199254740993123") && formatted.includes("1.234567890123456789e-50"), "JSON formatting preserves numeric tokens exactly");
  check(json.textContent === formatted && json.querySelector(".ws-json-key") && !json.querySelector("img"), "JSON highlights without interpreting strings as HTML");
  var rejected = false;
  try { R.formatJSON('{"x":}'); } catch (e) { rejected = e instanceof SyntaxError; }
  check(rejected, "Invalid JSON is detected");
  rejected = false;
  try { R.formatJSON("[".repeat(65) + "0" + "]".repeat(65)); } catch (_) { rejected = true; }
  check(rejected, "Deep JSON has a bounded rendering cost");

  if (byId("langLabel").textContent !== "RU") byId("langBtn").click();
  var originalFetch = window.fetch, dialog = byId("workspaceDialog"), lateResolve, previewFetches = [], failList = false;
  var root = "Workspace test", scanPath = root + "/2026-10-14_120000_" + "a".repeat(32);
  var files = {
    "REPORT.md":md,
    "данные & 1.json":rawJSON,
    "broken.json":'{"x":}',
    "slow.md":"# Old response",
    "report.html":"<h1>Preview</h1><script>parent.__workspaceUnsafe=true</script>",
    "notes.txt":"original\r\ntext\r\n",
    "large.md":"unused"
  };
  function entry(name, directory) { return {name:name,path:root + "/" + name,directory:!!directory,size:name === "large.md" ? 2097153 : (files[name] || "").length,modified:"2026-10-14T12:00:00Z"}; }
  function response(value, status) { return Promise.resolve(new Response(JSON.stringify(value), {status:status || 200,headers:{"Content-Type":"application/json"}})); }
  function currentHeading() { return document.querySelector(".ws-preview-title h3"); }
  function openFile(name) {
    var card = Array.from(document.querySelectorAll(".ws-entry")).find(function (b) { return b.dataset.path === root + "/" + name; });
    if (!card) throw new Error("Missing fixture entry: " + name);
    card.click();
  }
  function ready(name) { return waitFor(function () { return currentHeading() && currentHeading().textContent === name && !document.querySelector('.ws-preview-content[aria-busy="true"]'); }); }
  function viewButton(label) { return Array.from(document.querySelectorAll(".ws-preview-tools button")).find(function (b) { return b.textContent === label; }); }
  if (dialog.open) { dialog.close(); await new Promise(function (resolve) { setTimeout(resolve, 30); }); }
  window.fetch = function (input, opts) {
    var url = new URL(String(input), location.href), path = url.searchParams.get("path") || "";
    if (url.pathname === "/api/workspace/list") {
      if (failList) { failList = false; return response({message:"Test folder unavailable"}, 503); }
      if (path === scanPath) return response({entries:[],has_more:false,next_offset:0,scan:{name:"Active scan",status:"running"}});
      if (path === root + "/Empty") return response({entries:[],has_more:false,next_offset:0});
      if (url.searchParams.get("offset") === "8") return response({entries:[entry("notes.txt"),entry("2026-10-14_120000_" + "a".repeat(32), true)],has_more:false,next_offset:10});
      return response({entries:[entry("Empty", true)].concat(Object.keys(files).filter(function (n) { return n !== "notes.txt"; }).map(function (n) { return entry(n); })),has_more:true,next_offset:8});
    }
    if (url.pathname === "/api/workspace/file") {
      previewFetches.push(path);
      if (path.endsWith("slow.md")) return new Promise(function (resolve) { lateResolve = function () { resolve(new Response(files["slow.md"])); }; }); // Ignore abort to exercise stale-response protection.
      return Promise.resolve(new Response(files[path.slice(root.length + 1)] || ""));
    }
    return originalFetch(input, opts);
  };
  try {
    window.dispatchEvent(new CustomEvent("mega:scan-created", {detail:{path:root}}));
    byId("workspaceOpen").click();
    await waitFor(function () { return byId("wsEntries").getAttribute("aria-busy") === "false" && document.querySelectorAll(".ws-entry").length === 7; });
    openFile("REPORT.md"); await ready("REPORT.md");
    check(!!document.querySelector(".ws-preview .ws-markdown table"), "Opening MD renders its report inside the workspace");
    check(document.querySelector('.ws-entry[aria-pressed="true"]').dataset.path.endsWith("REPORT.md"), "The previewed file remains visibly selected");
    viewButton("Исходник").click();
    check(document.querySelector(".ws-preview .ws-code").textContent === md, "Markdown source is byte-for-byte unchanged");
    viewButton("Просмотр").click();
    check(!!document.querySelector(".ws-markdown h1"), "Switching back restores Markdown formatting");
    if (window.matchMedia("(max-width: 700px)").matches) {
      check(dialog.classList.contains("ws-show-preview") && getComputedStyle(document.querySelector(".ws-files")).display === "none", "Mobile opens a dedicated reading pane");
      document.querySelector(".ws-mobile-back").click();
      check(!dialog.classList.contains("ws-show-preview") && document.activeElement.classList.contains("ws-entry"), "Mobile back restores focus to the file");
    }
    openFile("данные & 1.json"); await ready("данные & 1.json");
    check(document.querySelector(".ws-code").textContent === formatted, "JSON opens formatted and preserves large identifiers");
    var download = document.querySelector(".ws-preview a[download]");
    check(download.download === "данные & 1.json" && new URL(download.href).searchParams.get("path") === root + "/данные & 1.json" && !new URL(download.href).searchParams.has("preview"), "Download targets the original file with correctly encoded Unicode and ampersands");
    viewButton("Исходник").click();
    check(document.querySelector(".ws-code").textContent === rawJSON, "JSON source preserves original whitespace and numbers");
    viewButton("Перенос").click();
    check(!document.querySelector(".ws-code").classList.contains("ws-wrap"), "Line wrapping can be disabled");
    openFile("broken.json"); await ready("broken.json");
    check(document.querySelector(".ws-notice").textContent.includes("синтаксиса") && document.querySelector(".ws-code").textContent === files["broken.json"], "Malformed JSON remains readable and downloadable");
    openFile("large.md"); await ready("large.md");
    check(!previewFetches.some(function (p) { return p.endsWith("large.md"); }) && document.querySelector(".ws-preview a[download]"), "Files over the preview cap are download-only without fetching the body");
    openFile("slow.md"); openFile("REPORT.md"); await ready("REPORT.md");
    lateResolve(); await new Promise(function (resolve) { setTimeout(resolve, 40); });
    check(document.querySelector(".ws-markdown h1").textContent === "Audit", "Late responses cannot overwrite the selected file");
    openFile("report.html"); await ready("report.html");
    var frame = document.querySelector(".ws-preview iframe");
    check(frame && frame.getAttribute("sandbox") === "" && frame.srcdoc.includes("default-src &#39;none&#39;"), "HTML keeps the sandbox and resource-blocking policy");
    if (window.matchMedia("(max-width: 700px)").matches) document.querySelector(".ws-mobile-back").click();
    document.querySelector('[data-ws-filter="json"]').click();
    check(document.querySelectorAll(".ws-entry").length === 2, "JSON filter only displays JSON files");
    byId("wsSearch").value = "данные"; byId("wsSearch").dispatchEvent(new Event("input"));
    check(document.querySelectorAll(".ws-entry").length === 1, "Filename search supports Cyrillic");
    byId("wsSearch").value = "not found"; byId("wsSearch").dispatchEvent(new Event("input"));
    check(byId("wsEntries").textContent.includes("Ничего не найдено"), "Search has a distinct no-results state");
    byId("wsEntries").querySelector("button").click();
    byId("wsMore").click();
    await waitFor(function () { return byId("wsMore").hidden; });
    check(document.querySelectorAll(".ws-entry").length === 9, "Pagination appends entries without duplicates");
    byId("wsSortBtn").click();
    document.querySelector('#wsSortMenu [data-value="size"]').click();
    var sorted = Array.from(document.querySelectorAll(".ws-entry"));
    check(sorted[0].dataset.directory === "true" && sorted.find(function (b) { return b.dataset.directory !== "true"; }).dataset.path.endsWith("large.md"), "Size sorting retains folders first");
    openFile("Empty");
    await waitFor(function () { return byId("wsEntries").textContent.includes("Пока нет файлов"); });
    check(byId("wsCrumbs").lastElementChild.textContent === "Empty" && !byId("wsUseFolder").disabled, "Folder navigation updates breadcrumbs and save destination");
    byId("wsUp").click();
    await waitFor(function () { return byId("wsEntries").getAttribute("aria-busy") === "false" && !byId("wsMore").hidden; });
    byId("wsMore").click(); await waitFor(function () { return byId("wsMore").hidden; });
    openFile("2026-10-14_120000_" + "a".repeat(32));
    await waitFor(function () { return byId("wsStatus").textContent.includes("Active scan"); });
    check(byId("wsNewFolder").disabled && byId("wsUseFolder").disabled, "Scan folders retain creation and output guards");
    failList = true; byId("wsRefresh").click();
    await waitFor(function () { return byId("wsStatus").textContent.includes("Test folder unavailable"); });
    check(byId("wsEntries").querySelector("button").textContent === "Повторить", "List failures offer a working retry action");
    byId("wsEntries").querySelector("button").click();
    await waitFor(function () { return !byId("wsStatus").classList.contains("ws-error"); });
    check(dialog.scrollWidth <= dialog.clientWidth && document.documentElement.scrollWidth <= innerWidth, "Workspace fits the viewport without horizontal page overflow");
    return {passed:checks.length,width:innerWidth,checks:checks};
  } finally {
    dialog.close(); window.fetch = originalFetch;
  }
})();
