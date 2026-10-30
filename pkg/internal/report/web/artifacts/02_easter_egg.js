  // ──────────── Easter-egg scanner ────────────
  // Sweeps every embedded payload for hidden strings: URLs, emails, CTF-style
  // flags, credits, debug toggles, and stray base64 blobs. Purely client-side,
  // operates only on data already embedded in this report.
  var eggBtn = document.getElementById('art-egg-btn');
  if(eggBtn){
    eggBtn.addEventListener('click', function(){
      eggBtn.classList.add('is-busy');
      eggBtn.disabled = true;
      // Defer so the busy state paints before the (sync) sweep runs.
      setTimeout(function(){
        try { runEasterEggScan(); }
        finally { eggBtn.classList.remove('is-busy'); eggBtn.disabled = false; }
      }, 16);
    });
  }

  function decodeMaybeBase64(dataUri){
    if(!dataUri) return '';
    try {
      var comma = dataUri.indexOf(',');
      var b64 = comma >= 0 ? dataUri.slice(comma+1) : dataUri;
      return atob(b64);
    } catch(e){ return ''; }
  }

  function runEasterEggScan(){
    var panel = document.getElementById('art-egg-results');
    if(!panel) return;
    var patterns = [
      {kind:'flag',   label:'Flags / credits / hidden notes', re:/(flag\{[^}]{2,80}\}|ctf\{[^}]{2,80}\}|HTB\{[^}]{2,80}\}|easter\s?egg|hidden|secret\s*[:=]|backdoor|made\s+by\s+[\w .,-]{2,40}|greetz|shoutout|TODO\s*[:=]|FIXME\s*[:=]|debug\s*=\s*true|isDebug\s*=\s*true)/gi},
      {kind:'url',    label:'URLs / endpoints', re:/https?:\/\/[a-z0-9.\-]+(?:\:[0-9]+)?(?:\/[^\s"'<>)]{0,120})?/gi},
      {kind:'email',  label:'Emails', re:/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/gi},
      {kind:'ip',     label:'IP addresses', re:/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b(?::[0-9]{1,5})?/g},
      {kind:'base64', label:'Long base64 blobs', re:/[A-Za-z0-9+\/]{60,}={0,2}/g},
    ];
    var groups = {}; patterns.forEach(function(p){ groups[p.kind] = {label:p.label, hits:[], seen:{}}; });
    var MAX_PER_GROUP = 40;
    var totalChars = 0, CHAR_BUDGET = 6 * 1024 * 1024; // cap total scanned text

    view.items.forEach(function(it){
      var texts = [];
      // Pre-extracted string lists are the richest source.
      if(it.native){
        (it.native.suspicious_strings||[]).forEach(function(s){ texts.push(s); });
        (it.native.recovered_strings||[]).forEach(function(s){ texts.push(s); });
      }
      if(it.code && it.code.findings){
        it.code.findings.forEach(function(f){ if(f.snippet) texts.push(f.snippet); });
      }
      // Embedded text/code payloads — decode and scan the raw body.
      if(it.embedded_data_uri && (it.type === 'code' || it.type === 'image' && (it.mime||'').indexOf('svg') !== -1)){
        if(totalChars < CHAR_BUDGET){
          var body = decodeMaybeBase64(it.embedded_data_uri);
          totalChars += body.length;
          if(body) texts.push(body);
        }
      }
      var blob = texts.join('\n');
      if(!blob) return;
      var src = (it.path || it.id).split('/').pop();
      patterns.forEach(function(p){
        var g = groups[p.kind];
        p.re.lastIndex = 0;
        var m, n = 0;
        while((m = p.re.exec(blob)) !== null && g.hits.length < MAX_PER_GROUP){
          var val = m[0];
          if(p.kind === 'base64' && /^[0-9a-f]+$/i.test(val) && val.length % 2 === 0) { /* likely hex hash, still show */ }
          var key = val.slice(0, 200);
          if(g.seen[key]) { if(++n > 5000) break; continue; }
          g.seen[key] = true;
          g.hits.push({val: key, src: src});
          if(++n > 5000) break;
        }
      });
    });

    var html = '<h3><svg class="icon icon-egg" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 21c-4.4 0 -8 -1.79 -8 -6c0 -5.5 4 -12 8 -12s8 6.5 8 12c0 4.21 -3.6 6 -8 6" /></svg> Easter-egg sweep</h3>';
    var any = false;
    patterns.forEach(function(p){
      var g = groups[p.kind];
      if(g.hits.length === 0) return;
      any = true;
      html += '<div class="art-egg-group"><h4>' + escapeHtml(g.label) + ' (' + g.hits.length + (g.hits.length >= MAX_PER_GROUP ? '+' : '') + ')</h4>';
      g.hits.forEach(function(h){
        html += '<div class="art-egg-hit" data-kind="' + p.kind + '">' + escapeHtml(h.val)
              + '<span class="src">in ' + escapeHtml(h.src) + '</span></div>';
      });
      html += '</div>';
    });
    if(!any) html += '<p class="art-egg-empty">No hidden strings, URLs, flags or base64 blobs found in embedded artifacts.</p>';
    panel.innerHTML = html;
    panel.hidden = false;
    panel.scrollIntoView({behavior:'smooth', block:'nearest'});
  }

  // Reveal blur
  document.querySelectorAll('.art-reveal').forEach(function(btn){
    btn.addEventListener('click', function(){
      var img = btn.parentElement.querySelector('.art-img');
      if(img){ img.classList.remove('is-blurred'); btn.remove(); }
    });
  });

  // Card actions
  document.querySelectorAll('[data-art-open]').forEach(function(btn){
    btn.addEventListener('click', function(){ openViewer(items[btn.getAttribute('data-art-open')]); });
  });
  document.querySelectorAll('[data-art-details]').forEach(function(btn){
    btn.addEventListener('click', function(){ openDetails(items[btn.getAttribute('data-art-details')]); });
  });
  document.querySelectorAll('[data-art-export]').forEach(function(btn){
    btn.addEventListener('click', function(){
      if(!allowExport) return;
      requestExport(items[btn.getAttribute('data-art-export')]);
    });
  });

