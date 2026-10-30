  // ──────────── CODE viewer ────────────
  function renderCodeShell(item){
    var c = item.code || {};
    var lang = c.language || 'text';
    var lines = c.lines || 0;
    var sub = lang.toUpperCase() + ' · ' + lines + ' lines · ' + humanSize(item.size||0)
            + (c.is_minified ? ' · minified' : '')
            + (c.is_obfuscated ? ' · obfuscated' : '');
    var findCount = (c.findings || []).length;
    return '<div class="art-shell" data-kind="code">'
      + shellHead(item, sub)
      + '<div class="art-shell-body art-code">'
      +   '<div class="art-code-tabs" role="tablist">'
      +     '<button type="button" class="art-code-tab is-active" data-pane="src" role="tab">Source</button>'
      +     '<button type="button" class="art-code-tab" data-pane="findings" role="tab">Findings'+(findCount?' <span class="badge">'+findCount+'</span>':'')+'</button>'
      +     (c.schema ? '<button type="button" class="art-code-tab" data-pane="schema" role="tab">Schema</button>' : '')
      +     '<span style="flex:1"></span>'
      +     '<button type="button" class="art-code-tab" data-wrap aria-pressed="false" title="Toggle line wrap">Wrap</button>'
      +   '</div>'
      +   '<div class="art-code-search-bar">'
      +     '<input type="text" placeholder="Search code (Ctrl+F)..." class="art-code-search-input">'
      +     '<span class="art-code-search-stats">0/0</span>'
      +     '<button type="button" class="art-code-search-btn art-code-search-prev" title="Previous match">▲</button>'
      +     '<button type="button" class="art-code-search-btn art-code-search-next" title="Next match">▼</button>'
      +   '</div>'
      +   '<pre class="art-code-pane" data-pane-body="src"></pre>'
      +   '<div class="art-findings" data-pane-body="findings" hidden></div>'
      +   (c.schema ? '<div class="art-findings" data-pane-body="schema" hidden></div>' : '')
      + '</div>'
      + shellFoot()
      + '</div>';
  }

  function bindCode(dlg, item){
    var c = item.code || {};
    var srcPane = dlg.querySelector('[data-pane-body="src"]');
    var fndPane = dlg.querySelector('[data-pane-body="findings"]');
    var schemaPane = dlg.querySelector('[data-pane-body="schema"]');

    // Decode source from data URI; otherwise try external_path (only http(s)/file).
    var text = '';
    if(item.embedded_data_uri){
      try {
        var idx = item.embedded_data_uri.indexOf(',');
        var blob = item.embedded_data_uri.substring(idx+1);
        if(item.embedded_data_uri.indexOf(';base64,') > -1){
          text = decodeBase64Utf8(blob);
        } else {
          text = decodeURIComponent(blob);
        }
      } catch(e){ text = '[failed to decode embedded payload]'; }
    } else {
      text = '[source not embedded — open external file]';
    }
    // Split once: doSearch used to re-split the whole source on every
    // keystroke, which on a multi-MB bundle is a freeze per character.
    var srcLines = text.split('\n');
    var flushTo = function(){};
    if(srcPane) flushTo = mountCode(srcPane, srcLines, c.language || 'text');

    // Findings.
    if(fndPane){
      var fs = c.findings || [];
      if(fs.length === 0){
        fndPane.innerHTML = '<div class="art-empty">No static-analysis findings.</div>';
      } else {
        var groups = {};
        fs.forEach(function(f) {
          var cat = f.category || 'General';
          if (!groups[cat]) groups[cat] = [];
          groups[cat].push(f);
        });

        var html = '';
        var cats = Object.keys(groups).sort();
        cats.forEach(function(cat) {
          html += '<div class="art-finding-group-header" style="font-size:11px; font-weight:700; color:#7eb6ff; margin:16px 0 8px; padding-bottom:4px; border-bottom:1px solid rgba(126,182,255,0.15); text-transform:uppercase; letter-spacing:0.5px;">'
                + escapeHtml(cat)
                + ' <span style="font-size:10px; color:#7d92a8; font-weight:normal; text-transform:none;">(' + groups[cat].length + ' findings)</span>'
                + '</div>';
          
          groups[cat].forEach(function(f) {
            var globalI = fs.indexOf(f);
            var sev = (f.severity || 'low').toLowerCase();
            var sevKey = sev === 'critical' ? 'crit' : sev;
            html += '<div class="art-finding" data-sev="'+escapeHtml(sevKey)+'" data-jump="'+(f.line||0)+'" data-i="'+globalI+'" style="margin-bottom:10px; cursor:pointer;">'
                  + '<div class="art-finding-head"><span>'+escapeHtml(f.title||f.id||'Finding')+'</span><span class="sev">'+escapeHtml(sev)+'</span></div>'
                  + (f.detail   ? '<div style="font-size:11px;color:#9bb2c8;margin-top:4px">'+escapeHtml(f.detail)+'</div>' : '')
                  + (f.snippet  ? '<pre class="art-finding-snippet">'+escapeHtml(f.snippet)+'</pre>' : '')
                  + (f.line     ? '<div class="art-finding-loc">line '+f.line+(f.column?', col '+f.column:'')+'</div>' : '')
                  + '</div>';
          });
        });
        fndPane.innerHTML = html;
        fndPane.querySelectorAll('.art-finding').forEach(function(el){
          el.addEventListener('click', function(){
            var line = parseInt(el.getAttribute('data-jump'),10)||0;
            switchPane(dlg, 'src');
            flushTo(line);
            jumpToLine(srcPane, line);
          });
        });
      }
    }

    // Schema (proto).
    if(schemaPane && c.schema){
      var s = c.schema;
      var html = '';
      if(s.package) html += '<div class="art-finding"><div class="art-finding-head"><span>package '+escapeHtml(s.package)+'</span></div></div>';
      if(s.imports && s.imports.length){
        html += '<div class="art-finding"><div class="art-finding-head"><span>Imports ('+s.imports.length+')</span></div>';
        html += '<pre class="art-finding-snippet">'+escapeHtml(s.imports.join('\n'))+'</pre></div>';
      }
      if(s.messages && s.messages.length){
        html += '<div class="art-finding"><div class="art-finding-head"><span>Messages ('+s.messages.length+')</span></div>';
        html += '<pre class="art-finding-snippet">'+escapeHtml(s.messages.join('\n'))+'</pre></div>';
      }
      if(s.enums && s.enums.length){
        html += '<div class="art-finding"><div class="art-finding-head"><span>Enums ('+s.enums.length+')</span></div>';
        html += '<pre class="art-finding-snippet">'+escapeHtml(s.enums.join('\n'))+'</pre></div>';
      }
      if(s.services && s.services.length){
        s.services.forEach(function(sv){
          html += '<div class="art-finding"><div class="art-finding-head"><span>service '+escapeHtml(sv.name)+'</span></div>';
          if(sv.rpcs && sv.rpcs.length){
            html += '<pre class="art-finding-snippet">'+escapeHtml(sv.rpcs.join('\n'))+'</pre>';
          }
          html += '</div>';
        });
      }
      schemaPane.innerHTML = html || '<div class="art-empty">Empty schema.</div>';
    }

    // Tab switching.
    dlg.querySelectorAll('[data-pane]').forEach(function(t){
      t.addEventListener('click', function(){ switchPane(dlg, t.getAttribute('data-pane')); });
    });
    var wrapBt = dlg.querySelector('[data-wrap]');
    if(wrapBt) wrapBt.addEventListener('click', function(){
      var on = srcPane.classList.toggle('wrap');
      wrapBt.setAttribute('aria-pressed', on ? 'true' : 'false');
      wrapBt.classList.toggle('is-active', on);
    });

    var exp = dlg.querySelector('[data-export]');
    if(exp) exp.addEventListener('click', function(){ requestExport(item); });

    // Copy to clipboard listener
    var copyBtn = dlg.querySelector('[data-copy]');
    if(copyBtn){
      copyBtn.addEventListener('click', function(){
        navigator.clipboard.writeText(text).then(function(){
          copyBtn.innerHTML = iconCheckSvg;
          setTimeout(function(){ copyBtn.innerHTML = iconCopySvg; }, 1500);
        });
      });
    }

    // Interactive Search Logic
    var searchBar = dlg.querySelector('.art-code-search-bar');
    var searchInput = dlg.querySelector('.art-code-search-input');
    var searchStats = dlg.querySelector('.art-code-search-stats');
    var searchPrev = dlg.querySelector('.art-code-search-prev');
    var searchNext = dlg.querySelector('.art-code-search-next');

    var searchMatches = [];
    var currentMatchIndex = -1;

    function doSearch() {
      srcPane.querySelectorAll('.row.hl-search-current').forEach(function(r){
        r.classList.remove('hl-search-current');
      });

      var query = (searchInput.value || '').toLowerCase();
      searchMatches = [];
      currentMatchIndex = -1;

      if(!query) {
        searchStats.textContent = '0/0';
        return;
      }

      for(var i=0; i<srcLines.length; i++) {
        if(srcLines[i].toLowerCase().indexOf(query) !== -1) {
          searchMatches.push(i + 1);
        }
      }

      if(searchMatches.length > 0) {
        currentMatchIndex = 0;
        updateMatchHighlight();
      } else {
        searchStats.textContent = '0/0';
      }
    }

    function updateMatchHighlight() {
      searchStats.textContent = (currentMatchIndex + 1) + '/' + searchMatches.length;

      var lineNum = searchMatches[currentMatchIndex];
      flushTo(lineNum); // the row may not have streamed in yet
      var row = srcPane.querySelector('.row[data-line="' + lineNum + '"]');
      if(row) {
        srcPane.querySelectorAll('.row.hl-search-current').forEach(function(r){
          r.classList.remove('hl-search-current');
        });
        row.classList.add('hl-search-current');
        row.scrollIntoView({block: 'center'});
      }
    }

    function goNext() {
      if(searchMatches.length === 0) return;
      currentMatchIndex = (currentMatchIndex + 1) % searchMatches.length;
      updateMatchHighlight();
    }

    function goPrev() {
      if(searchMatches.length === 0) return;
      currentMatchIndex = (currentMatchIndex - 1 + searchMatches.length) % searchMatches.length;
      updateMatchHighlight();
    }

    if(searchInput) {
      // Debounced: a scan of a 20k-line source per keystroke is felt.
      var searchTimer = 0;
      searchInput.addEventListener('input', function(){
        clearTimeout(searchTimer);
        searchTimer = setTimeout(doSearch, 120);
      });
      searchInput.addEventListener('keydown', function(e){
        if(e.key === 'Enter') {
          e.preventDefault();
          if(e.shiftKey) goPrev();
          else goNext();
        }
      });
    }

    if(searchNext) searchNext.addEventListener('click', goNext);
    if(searchPrev) searchPrev.addEventListener('click', goPrev);

    // Focus input on Ctrl+F inside this code dialog
    dlg.addEventListener('keydown', function(e){
      if((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault();
        if(searchInput) {
          searchInput.focus();
          searchInput.select();
        }
      }
    });

    // Ctrl+A selection override for code pane to copy only the code
    dlg.addEventListener('keydown', function(e){
      if((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a'){
        var activeTab = dlg.querySelector('.art-code-tab.is-active');
        if(activeTab && activeTab.getAttribute('data-pane') === 'src' && srcPane) {
          e.preventDefault();
          var range = document.createRange();
          range.selectNodeContents(srcPane);
          var sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
        }
      }
    });
  }

  function switchPane(dlg, name){
    dlg.querySelectorAll('[data-pane]').forEach(function(t){
      t.classList.toggle('is-active', t.getAttribute('data-pane') === name);
    });
    dlg.querySelectorAll('[data-pane-body]').forEach(function(b){
      b.hidden = b.getAttribute('data-pane-body') !== name;
    });
    var searchBar = dlg.querySelector('.art-code-search-bar');
    if(searchBar) {
      searchBar.style.display = (name === 'src') ? 'flex' : 'none';
    }
  }

  function jumpToLine(pane, line){
    if(!pane || !line) return;
    var row = pane.querySelector('[data-line="'+line+'"]');
    if(!row) return;
    pane.querySelectorAll('.row.hl').forEach(function(r){ r.classList.remove('hl'); });
    row.classList.add('hl');
    row.scrollIntoView({block:'center'});
  }

  // Lightweight syntax highlighter — token-class based, no dependencies.
  var MAX_CODE_LINES = 20000;

  function rowsHTML(lines, from, to, lang){
    var out = '';
    for(var i=from;i<to;i++){
      // Line number comes from the CSS ::before on .row — one element per
      // line instead of two halves the DOM for a 20k-line bundle.
      out += '<span class="row" data-line="'+(i+1)+'">'+colorise(lines[i], lang)+'</span>';
    }
    return out;
  }

  // Full render — only for small payloads (JSON details). Big sources go
  // through mountCode so the dialog isn't blocked building megabytes of DOM.
  function highlight(text, lang){
    var lines = text.split('\n');
    var capped = lines.length > MAX_CODE_LINES;
    if(capped) lines = lines.slice(0, MAX_CODE_LINES);
    var out = rowsHTML(lines, 0, lines.length, lang);
    if(capped) out += '<span class="row"><span class="tk-com">[truncated for display]</span></span>';
    return out;
  }

  // Streams lines into the pane: the first chunk lands synchronously so the
  // viewer opens instantly, the rest fills in while the browser is idle.
  // Returns a flushTo(line) that force-renders up to a line when search or a
  // finding needs to jump there before streaming caught up.
  function mountCode(pane, lines, lang){
    var FIRST = 600, CHUNK = 1500;
    var total = Math.min(lines.length, MAX_CODE_LINES);
    var done = 0;
    var idle = window.requestIdleCallback || function(fn){ return setTimeout(fn, 16); };
    pane.textContent = '';
    function render(upTo){
      if(done >= upTo) return;
      var end = Math.min(upTo, total);
      pane.insertAdjacentHTML('beforeend', rowsHTML(lines, done, end, lang));
      done = end;
      if(done >= total && lines.length > MAX_CODE_LINES){
        pane.insertAdjacentHTML('beforeend', '<span class="row"><span class="tk-com">[truncated for display]</span></span>');
      }
    }
    render(FIRST);
    (function pump(){
      if(done >= total) return;
      idle(function(){ render(done + CHUNK); pump(); });
    })();
    return function flushTo(line){ render(Math.max(line + 20, done)); };
  }

  // Highlighting rules run on the RAW line and mark hits with control-char
  // sentinels; escaping happens afterwards. Escaping first was a bug: '\''
  // became '&#39;', whose '#' then matched the comment rule and shredded the
  // generated markup, while '"' became '&quot;' so string rules never fired.
  var TK_O = '\u0001', TK_S = '\u0002', TK_C = '\u0003';
  function mark(cls, body){ return TK_O + cls + TK_S + (body || '$1') + TK_C; }
  // ponytail: single-pass regex chain, so a keyword inside an already-marked
  // string still gets its own nested span. Upgrade to a real tokenizer only if
  // the nesting ever looks wrong to someone.
  var MAX_HL_LINE = 4000;

  function colorise(line, lang){
    // Minified bundles are single multi-hundred-KB lines: styling them costs
    // more than it reveals, and the token spans are unreadable anyway.
    if(line.length > MAX_HL_LINE) return escapeHtml(line) || '&nbsp;';
    var s = line.replace(/[\u0001-\u0003]/g, '');
    if(lang === 'javascript' || lang === 'typescript' || lang === 'bundle' || lang === 'lua' || lang === 'python'){
      s = s.replace(/(\/\/[^\n]*|#[^\n]*)/g, mark('com'));
      s = s.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g, mark('str'));
      s = s.replace(/\b(function|return|if|else|for|while|var|let|const|new|try|catch|throw|class|extends|super|this|typeof|instanceof|import|export|from|default|async|await|yield|null|undefined|true|false|in|of)\b/g, mark('key'));
      s = s.replace(/\b(\d+\.?\d*)\b/g, mark('num'));
    } else if(lang === 'go' || lang === 'rust' || lang === 'swift' || lang === 'dart' || lang === 'kotlin'){
      s = s.replace(/(\/\/[^\n]*)/g, mark('com'));
      s = s.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`[^`]*`)/g, mark('str'));
      s = s.replace(/\b(func|fn|let|var|val|const|mut|pub|priv|struct|enum|impl|trait|interface|class|return|if|else|for|while|match|switch|case|break|continue|import|package|type|defer|go|chan|select|async|await|override|open|sealed|data|object|companion|when|is|as|in|guard|self|Self|super|nil|null|true|false|void|static|final|abstract|throws|throw|try|catch|where|extension|protocol|some|any)\b/g, mark('key'));
      s = s.replace(/\b(\d+\.?\d*)\b/g, mark('num'));
    } else if(lang === 'c' || lang === 'cpp' || lang === 'csharp' || lang === 'java'){
      s = s.replace(/(\/\/[^\n]*)/g, mark('com'));
      s = s.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g, mark('str'));
      s = s.replace(/\b(auto|break|case|char|const|continue|default|do|double|else|enum|extern|float|for|goto|if|inline|int|long|register|return|short|signed|sizeof|static|struct|switch|typedef|union|unsigned|void|volatile|while|class|namespace|template|typename|virtual|public|private|protected|new|delete|this|throw|try|catch|using|override|final|abstract|interface|extends|implements|import|package|synchronized|throws|native|transient|assert|boolean|byte|instanceof|super|null|true|false|string|var|dynamic|async|await|yield|get|set|partial|sealed|readonly|ref|out|event|delegate|where|select|from|internal|unsafe|fixed|stackalloc|lock|checked|unchecked|base|is|as|in|of)\b/g, mark('key'));
      s = s.replace(/(#\s*(?:include|define|ifdef|ifndef|endif|pragma|if|else|elif|undef|error|warning)[^\n]*)/g, mark('fn'));
      s = s.replace(/\b(\d+\.?\d*[fFdDlLuU]*)\b/g, mark('num'));
    } else if(lang === 'ruby' || lang === 'php'){
      s = s.replace(/(#[^\n]*|\/\/[^\n]*)/g, mark('com'));
      s = s.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g, mark('str'));
      s = s.replace(/\b(def|end|class|module|require|include|attr_accessor|attr_reader|attr_writer|if|else|elsif|unless|while|until|for|do|begin|rescue|ensure|raise|return|yield|self|nil|true|false|and|or|not|in|then|function|echo|public|private|protected|static|final|abstract|namespace|use|new|throw|try|catch|finally|foreach|as|array|isset|empty|unset|global|const)\b/g, mark('key'));
      s = s.replace(/(\$[A-Za-z_][A-Za-z0-9_]*|@[A-Za-z_][A-Za-z0-9_]*)/g, mark('att'));
      s = s.replace(/\b(\d+\.?\d*)\b/g, mark('num'));
    } else if(lang === 'html' || lang === 'xml'){
      s = s.replace(/(<\/?[a-zA-Z0-9-:]+)/g, mark('tag'));
      s = s.replace(/(\b[a-zA-Z-:]+)=("[^"]*"|'[^']*')/g, mark('att') + '=' + mark('str', '$2'));
      s = s.replace(/(<!--.*?-->)/g, mark('com'));
    } else if(lang === 'css'){
      s = s.replace(/(\/\*.*?\*\/)/g, mark('com'));
      s = s.replace(/([a-zA-Z-]+)(\s*:)/g, mark('key') + '$2');
      s = s.replace(/(#[a-fA-F0-9]{3,8}|\b\d+(?:px|em|rem|%|s|ms)?)/g, mark('num'));
    } else if(lang === 'proto'){
      s = s.replace(/(\/\/[^\n]*)/g, mark('com'));
      s = s.replace(/("(?:[^"\\]|\\.)*")/g, mark('str'));
      s = s.replace(/\b(syntax|package|import|message|enum|service|rpc|returns|repeated|optional|required|reserved|map|stream|option|extend|oneof)\b/g, mark('key'));
      s = s.replace(/\b(int32|int64|uint32|uint64|sint32|sint64|fixed32|fixed64|sfixed32|sfixed64|float|double|bool|string|bytes)\b/g, mark('fn'));
      s = s.replace(/\b(\d+)\b/g, mark('num'));
    } else if(lang === 'json'){
      s = s.replace(/("(?:[^"\\]|\\.)*")(\s*:)/g, mark('att') + '$2');
      s = s.replace(/(:\s*)("(?:[^"\\]|\\.)*")/g, '$1' + mark('str', '$2'));
      s = s.replace(/\b(true|false|null)\b/g, mark('key'));
      s = s.replace(/\b(-?\d+\.?\d*)\b/g, mark('num'));
    } else if(lang === 'yaml' || lang === 'toml' || lang === 'ini' || lang === 'properties'){
      s = s.replace(/(#[^\n]*)/g, mark('com'));
      s = s.replace(/^(\s*[A-Za-z0-9_.:-]+)(\s*[:=])/gm, mark('att') + '$2');
      s = s.replace(/("(?:[^"\\]|\\.)*"|'[^']*')/g, mark('str'));
      s = s.replace(/\b(true|false|null|yes|no|on|off)\b/gi, mark('key'));
      s = s.replace(/\b(-?\d+\.?\d*)\b/g, mark('num'));
    } else if(lang === 'sql'){
      s = s.replace(/(--[^\n]*)/g, mark('com'));
      s = s.replace(/('(?:[^'\\]|\\.)*')/g, mark('str'));
      s = s.replace(/\b(SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TABLE|INDEX|JOIN|LEFT|RIGHT|INNER|OUTER|ON|AND|OR|NOT|IN|IS|NULL|AS|ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|UNION|SET|VALUES|INTO|DISTINCT|COUNT|SUM|AVG|MAX|MIN|BETWEEN|LIKE|EXISTS|CASE|WHEN|THEN|ELSE|END|BEGIN|COMMIT|ROLLBACK|GRANT|REVOKE|PRIMARY|KEY|FOREIGN|REFERENCES|CONSTRAINT|DEFAULT|CHECK|UNIQUE|VIEW|TRIGGER|PROCEDURE|FUNCTION|DECLARE|CURSOR|FETCH|EXEC|EXECUTE)\b/gi, mark('key'));
      s = s.replace(/\b(\d+\.?\d*)\b/g, mark('num'));
    } else if(lang === 'shell'){
      s = s.replace(/(#[^\n]*)/g, mark('com'));
      s = s.replace(/("(?:[^"\\]|\\.)*"|'[^']*')/g, mark('str'));
      s = s.replace(/(\$[A-Za-z_][A-Za-z0-9_]*)/g, mark('att'));
    }
    // Escape once at the end — sentinels survive it, then become real tags.
    return escapeHtml(s)
      .replace(/\u0001(\w+)\u0002/g, '<span class="tk-$1">')
      .split('\u0003').join('</span>') || '&nbsp;';
  }

