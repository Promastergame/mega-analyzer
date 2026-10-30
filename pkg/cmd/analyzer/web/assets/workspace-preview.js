/* Bounded, offline report rendering. Untrusted text is only inserted as DOM text.
   Supports report Markdown: headings, lists, quotes, tables, fences and inline links.
   Raw HTML and remote images are deliberately not interpreted. */
(function () {
  "use strict";
  var RICH_LIMIT = 262144, NODE_LIMIT = 40000;
  function node(tag, text, cls) {
    var el = document.createElement(tag);
    if (text !== undefined) el.textContent = text;
    if (cls) el.className = cls;
    return el;
  }
  function markdown(source) {
    var budget = NODE_LIMIT;
    function make(tag, text, cls) {
      if (--budget < 0) throw new Error("Report rendering budget exceeded");
      return node(tag, text, cls);
    }
    function inline(parent, value, depth) {
      if (depth > 6 || value.length > 8192) { parent.appendChild(document.createTextNode(value)); return; }
      var re = /\\([\\`*_[\]{}()#+.!|>~-])|`([^`\n]+)`|\[([^\]\n]+)\]\(([^\s)]+)\)|\*\*([^\n]+?)\*\*|__([^\n]+?)__|~~([^\n]+?)~~|\*([^*\n]+)\*|_([^_\n]+)_/g;
      var match, last = 0;
      while ((match = re.exec(value))) {
        parent.appendChild(document.createTextNode(value.slice(last, match.index)));
        var el;
        if (match[1]) el = document.createTextNode(match[1]);
        else if (match[2]) el = make("code", match[2]);
        else if (match[3]) {
          var safe = /^https?:\/\//i.test(match[4]);
          try { if (safe) new URL(match[4]); } catch (_) { safe = false; }
          el = make(safe ? "a" : "span");
          inline(el, match[3], depth + 1);
          if (safe) { el.href = match[4]; el.target = "_blank"; el.rel = "noopener noreferrer"; }
        } else {
          el = make(match[5] || match[6] ? "strong" : match[7] ? "del" : "em");
          inline(el, match[5] || match[6] || match[7] || match[8] || match[9], depth + 1);
        }
        parent.appendChild(el); last = re.lastIndex;
      }
      parent.appendChild(document.createTextNode(value.slice(last)));
    }
    function cells(line) { return line.trim().replace(/^\||\|$/g, "").split(/(?<!\\)\|/).map(function (s) { return s.trim(); }); }
    function tableRule(line) { return line && line.indexOf("|") >= 0 && cells(line).every(function (s) { return /^:?-{3,}:?$/.test(s); }); }
    function listItem(line) { return /^(\s*)([-+*]|\d+[.)])\s+(.*)$/.exec(line); }
    function blockStart(lines, i) {
      return /^(?:\s*$| {0,3}(?:#{1,6}\s|`{3,}|~{3,}|>|(?:[-*_]\s*){3,}$))/.test(lines[i]) || listItem(lines[i]) || tableRule(lines[i + 1]);
    }
    function blocks(parent, lines, depth) {
      if (depth > 12) { parent.appendChild(make("pre", lines.join("\n"))); return; }
      for (var i = 0; i < lines.length;) {
        var line = lines[i], match, el;
        if (!line.trim()) { i++; continue; }
        if ((match = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line))) {
          var fence = match[1], code = []; i++;
          while (i < lines.length && !(lines[i].trim().split("").every(function (c) { return c === fence[0]; }) && lines[i].trim().length >= fence.length)) code.push(lines[i++]);
          if (i < lines.length) i++;
          el = make("pre"); el.appendChild(make("code", code.join("\n"))); parent.appendChild(el); continue;
        }
        if ((match = /^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line))) {
          el = make("h" + match[1].length); inline(el, match[2], 0); parent.appendChild(el); i++; continue;
        }
        if (/^ {0,3}(?:[-*_]\s*){3,}$/.test(line)) { parent.appendChild(make("hr")); i++; continue; }
        if (i + 1 < lines.length && /^ {0,3}(?:=+|-+)\s*$/.test(lines[i + 1])) {
          el = make(lines[i + 1].trim()[0] === "=" ? "h1" : "h2"); inline(el, line, 0); parent.appendChild(el); i += 2; continue;
        }
        if (/^ {0,3}>/.test(line)) {
          var quote = [];
          while (i < lines.length && /^ {0,3}>/.test(lines[i])) quote.push(lines[i++].replace(/^ {0,3}> ?/, ""));
          el = make("blockquote"); blocks(el, quote, depth + 1); parent.appendChild(el); continue;
        }
        if (line.indexOf("|") >= 0 && tableRule(lines[i + 1])) {
          var headers = cells(line), table = make("table"), head = make("thead"), row = make("tr"), body = make("tbody");
          headers.forEach(function (value) { var th = make("th"); th.scope = "col"; inline(th, value, 0); row.appendChild(th); });
          head.appendChild(row); table.appendChild(head); i += 2;
          var rowsShown = 0, rowsTotal = 0;
          while (i < lines.length && lines[i].trim() && lines[i].indexOf("|") >= 0) {
            rowsTotal++;
            if (rowsShown < 500) {
              var values = cells(lines[i]); row = make("tr");
              headers.forEach(function (_, col) { var td = make("td"); inline(td, values[col] || "", 0); row.appendChild(td); }); body.appendChild(row);
              rowsShown++;
            }
            i++;
          }
          table.appendChild(body); el = make("div", undefined, "ws-table-wrap"); el.appendChild(table); parent.appendChild(el);
          if (rowsTotal > rowsShown) {
            var cut = make("p", "Показаны первые " + rowsShown + " строк из " + rowsTotal + ". Скачай оригинал, чтобы увидеть всё.", "ws-notice");
            parent.appendChild(cut);
          }
          continue;
        }
        if ((match = listItem(line))) {
          var indent = match[1].length, ordered = /^\d/.test(match[2]), list = make(ordered ? "ol" : "ul");
          if (ordered) list.start = parseInt(match[2], 10);
          while (i < lines.length) {
            match = listItem(lines[i]);
            if (!match || match[1].length !== indent || /^\d/.test(match[2]) !== ordered) break;
            var item = make("li"), itemLines = [match[3]], contentIndent = match[0].length - match[3].length; i++;
            while (i < lines.length) {
              if (!lines[i].trim()) {
                if (i + 1 < lines.length && /^\s+\S/.test(lines[i + 1]) && lines[i + 1].search(/\S/) > indent) { itemLines.push(""); i++; continue; }
                break;
              }
              if (lines[i].search(/\S/) <= indent) break;
              itemLines.push(lines[i].slice(Math.min(contentIndent, lines[i].search(/\S/)))); i++;
            }
            var task = /^\[([ xX])\]\s+/.exec(itemLines[0]);
            if (task) { var check = make("input", undefined, "ws-task"); check.type = "checkbox"; check.disabled = true; check.checked = task[1] !== " "; check.setAttribute("aria-label", (typeof window.uiLang === "string" && window.uiLang === "en") ? (check.checked ? "Done" : "Not done") : (check.checked ? "Выполнено" : "Не выполнено")); item.appendChild(check); itemLines[0] = itemLines[0].slice(task[0].length); }
            if (itemLines.length === 1) inline(item, itemLines[0], 0); else blocks(item, itemLines, depth + 1);
            list.appendChild(item);
          }
          parent.appendChild(list); continue;
        }
        var para = [line]; i++;
        while (i < lines.length && !blockStart(lines, i)) para.push(lines[i++]);
        el = make("p"); inline(el, para.join("\n"), 0); parent.appendChild(el);
      }
    }
    var article = make("article", undefined, "ws-markdown");
    blocks(article, source.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").split("\n"), 0);
    enhance(article);
    return article;
  }
  // Report niceties: risk verdicts become badges, ASCII bars become meters,
  // key: value dumps become meta cards, severity cells become pills.
  // Text-only, no HTML parsing.
  function enhance(article) {
    Array.from(article.querySelectorAll("td")).forEach(function (td) {
      var raw = td.textContent;
      var t = raw.trim().toLowerCase();
      if (/^(critical|high|medium|low|info|minimal|clean)$/.test(t) && raw.trim().length < 12) {
        var pill = document.createElement("span");
        pill.className = "ws-pill ws-pill-" + t;
        pill.textContent = raw.trim();
        td.replaceChildren(pill);
        return;
      }
      // Long paths/hashes: single-line ellipsis with full text in tooltip.
      if (raw.trim().length > 60 && /[/\\.]/.test(raw) && !/\s{2,}/.test(raw.trim()) && raw.split(/\s+/).length < 12) {
        td.classList.add("ws-ellipsis");
        td.title = raw.trim();
        return;
      }
      // Long prose (evidence): clamp to 3 lines with an expander.
      if (raw.trim().length > 200) {
        var wrap = document.createElement("div");
        wrap.className = "ws-clamp";
        while (td.firstChild) wrap.appendChild(td.firstChild);
        td.appendChild(wrap);
        var enPreview = (typeof window.uiLang === "string" && window.uiLang === "en");
        var more = document.createElement("button");
        more.type = "button"; more.className = "ws-more-btn"; more.textContent = enPreview ? "Expand" : "Развернуть";
        more.addEventListener("click", function () {
          var open = wrap.classList.toggle("ws-open");
          more.textContent = open ? (enPreview ? "Collapse" : "Свернуть") : (enPreview ? "Expand" : "Развернуть");
        });
        td.appendChild(more);
      }
    });
    Array.from(article.children).forEach(function (el) {
      if (el.tagName !== "P" && el.tagName !== "PRE") return;
      var text = el.textContent;
      var risk = /overall risk\s*:\s*(critical|high|medium|low|minimal|info|clean)/i.exec(text);
      if (risk && el.tagName === "P" && text.trim().length < 120) {
        var level = risk[1].toLowerCase();
        var badge = document.createElement("div");
        badge.className = "ws-risk ws-risk-" + level;
        var dot = document.createElement("span"); dot.className = "ws-risk-dot"; badge.appendChild(dot);
        badge.appendChild(document.createTextNode(el.textContent.trim()));
        article.replaceChild(badge, el); return;
      }
      if (el.tagName === "P" && /^[\s\[\(|█▓▒░─━\-#*\d%\/\s\]\)|.]+$/.test(text) && /[█▓▒░%]/.test(text) && text.trim().length < 160) {
        var total = (text.match(/[█▓▒░\-#*. ]/g) || []).length;
        var filled = (text.match(/[█▓]/g) || []).length + (text.match(/(\d+)\s*%/) ? 0 : 0);
        var pct = total ? Math.min(100, Math.round(filled / total * 100)) : 0;
        var m = /(\d+)\s*%/.exec(text);
        if (m) pct = Math.max(0, Math.min(100, parseInt(m[1], 10)));
        var bar = document.createElement("div"); bar.className = "ws-bar";
        bar.setAttribute("role", "img"); bar.setAttribute("aria-label", text.trim());
        var fill = document.createElement("span"); fill.style.width = pct + "%"; bar.appendChild(fill);
        article.replaceChild(bar, el); return;
      }
      if (el.tagName === "PRE") {
        var lines = text.split("\n").filter(function (l) { return l.trim(); });
        var kv = lines.filter(function (l) { return /^\s*[A-Za-z][\w ]{1,20}:\s+\S/.test(l); });
        if (lines.length >= 3 && kv.length >= Math.max(3, lines.length - 1)) {
          var grid = document.createElement("div");
          grid.className = "ws-meta-grid";
          kv.forEach(function (l) {
            var i = l.indexOf(":");
            var item = document.createElement("div"); item.className = "ws-meta-item";
            var k = document.createElement("span"); k.className = "ws-meta-k"; k.textContent = l.slice(0, i).trim();
            var v = document.createElement("span"); v.className = "ws-meta-v"; v.textContent = l.slice(i + 1).trim(); v.title = v.textContent;
            item.appendChild(k); item.appendChild(v); grid.appendChild(item);
          });
          article.replaceChild(grid, el);
        }
      }
    });
  }
  // Format lexical tokens rather than round-tripping numbers through JS floats.
  function formatJSON(source) {
    JSON.parse(source.replace(/^\uFEFF/, ""));
    var tokens = source.match(/"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\],:]/g) || [];
    var depth = 0, result = [], length = 0;
    tokens.forEach(function (token, i) {
      var value = token;
      if (token === "{" || token === "[") {
        if (++depth > 64) throw new Error("JSON nesting limit");
        if (tokens[i + 1] !== "}" && tokens[i + 1] !== "]") value += "\n" + "  ".repeat(depth);
      } else if (token === "}" || token === "]") {
        depth--;
        if (tokens[i - 1] !== "{" && tokens[i - 1] !== "[") value = "\n" + "  ".repeat(depth) + token;
      } else if (token === ",") value += "\n" + "  ".repeat(depth);
      else if (token === ":") value += " ";
      length += value.length;
      if (length > 2097152) throw new Error("JSON formatting limit");
      result.push(value);
    });
    return result.join("");
  }
  function json(source) {
    var pre = node("pre", undefined, "ws-code"), re = /"(?:\\.|[^"\\])*"(\s*:)?|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\b(?:true|false|null)\b/g;
    var match, last = 0, budget = NODE_LIMIT;
    while ((match = re.exec(source))) {
      if (--budget < 0) throw new Error("JSON highlighting limit");
      pre.appendChild(document.createTextNode(source.slice(last, match.index)));
      var cls = match[1] ? "key" : match[0][0] === '"' ? "string" : /^[-\d]/.test(match[0]) ? "number" : "literal";
      pre.appendChild(node("span", match[0], "ws-json-" + cls)); last = re.lastIndex;
    }
    pre.appendChild(document.createTextNode(source.slice(last))); return pre;
  }
  window.WorkspacePreview = {markdown:markdown, json:json, formatJSON:formatJSON, richLimit:RICH_LIMIT};
})();
