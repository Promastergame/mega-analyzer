  // ──────────── Shell builder ────────────
  function shellHead(item, sub){
    var pathTxt = escapeHtml(item.path || item.id);
    var subTxt  = escapeHtml(sub || (item.type + ' · ' + humanSize(item.size||0)));
    var showCopy = (item.type === 'code' || sub === 'JSON details');
    return ''
      + '<div class="art-shell-head">'
      +   '<div>'
      +     '<div class="art-shell-title" title="'+pathTxt+'">'+pathTxt+'</div>'
      +     '<div class="art-shell-sub">'+subTxt+'</div>'
      +   '</div>'
      +   (showCopy ? '<button type="button" class="art-iconbtn" data-copy aria-label="Copy code" title="Copy code" style="display:inline-flex;align-items:center;justify-content:center">' + iconCopySvg + '</button>' : '')
      +   (allowExport ? '<button type="button" class="art-iconbtn" data-export aria-label="Export">⬇</button>' : '')
      +   '<button type="button" class="art-iconbtn is-danger" data-close aria-label="Close (Esc)" title="Close (Esc)">✕</button>'
      + '</div>';
  }
  function shellFoot(extra){
    return '<div class="art-shell-foot">'
      + '<span><kbd>Esc</kbd> close · <kbd>Click outside</kbd> close</span>'
      + (extra ? '<span>'+extra+'</span>' : '')
      + '</div>';
  }

  function renderArchiveShell(item) {
    var files = (item.archive && item.archive.files) || [];
    var html = '<div class="art-shell" data-kind="archive">';
    html += shellHead(item, 'Archive Explorer · ' + files.length + ' files');
    html += '<div class="art-shell-body" style="padding: 20px; overflow-y: auto; max-height: calc(100vh - 180px);">';
    
    if (files.length === 0) {
      html += '<div class="art-empty">Empty archive or parse warning</div>';
    } else {
      var tree = {};
      files.forEach(function(f) {
        var parts = f.path.split('/');
        var current = tree;
        for (var i = 0; i < parts.length; i++) {
          var part = parts[i];
          if (i === parts.length - 1) {
            if (!current._files) current._files = [];
            current._files.push(f);
          } else {
            if (!current[part]) current[part] = {};
            current = current[part];
          }
        }
      });

      function renderNode(nodeName, node, depth) {
        var out = '';
        var keys = Object.keys(node).filter(function(k) { return k !== '_files'; }).sort();
        var files = node._files || [];
        var padding = depth * 16;
        
        keys.forEach(function(dirName) {
          var dirId = 'dir_' + Math.random().toString(36).substring(2, 9);
          out += '<div class="art-zip-dir" style="padding-left: ' + padding + 'px; margin: 4px 0;">'
            + '<button type="button" class="art-zip-toggle" data-toggle="' + dirId + '" style="background: none; border: none; color: #7eb6ff; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 6px; font-size: 13px; font-family: Inter, sans-serif; padding: 4px 6px; border-radius: 4px; transition: background 0.2s;">'
            +   '<svg class="folder-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>'
            +   escapeHtml(dirName)
            + '</button>'
            + '<div class="art-zip-content" id="' + dirId + '" style="margin-left: 8px;">'
            +   renderNode(dirName, node[dirName], depth + 1)
            + '</div>'
            + '</div>';
        });

        files.forEach(function(f) {
          var base = f.path.split('/').pop();
          out += '<div class="art-zip-file" style="padding-left: ' + (padding + 20) + 'px; display: flex; justify-content: space-between; align-items: center; font-size: 12px; font-family: ui-monospace, monospace; color: #dbe9f6; padding-top: 4px; padding-bottom: 4px; border-bottom: 1px solid rgba(255,255,255,0.03);">'
            + '<span style="display: flex; align-items: center; gap: 6px;">'
            +   '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>'
            +   escapeHtml(base)
            + '</span>'
            + '<span style="color: #7d92a8; font-size: 11px;">' + humanSize(f.size) + ' (' + Math.round((f.compressed_size / (f.size || 1)) * 100) + '%)</span>'
            + '</div>';
        });
        return out;
      }

      html += '<div class="art-zip-tree" style="background: rgba(0,0,0,0.2); padding: 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.05);">'
        + renderNode('root', tree, 0)
        + '</div>';
    }

    html += '</div>';
    html += shellFoot('Click folder to collapse/expand');
    html += '</div>';
    return html;
  }

  function bindArchive(dlg, item) {
    dlg.querySelectorAll('.art-zip-toggle').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var contentId = btn.getAttribute('data-toggle');
        var content = dlg.querySelector('#' + contentId);
        if (content) {
          var hidden = content.style.display === 'none';
          content.style.display = hidden ? 'block' : 'none';
          btn.style.opacity = hidden ? '1' : '0.7';
        }
      });
    });
    var exp = dlg.querySelector('[data-export]');
    if(exp) exp.addEventListener('click', function(){ requestExport(item); });
  }

  function renderFallbackShell(item){
    var why = item.embedded_data_uri || item.external_path
      ? 'This artifact type has no specialized viewer yet.'
      : 'No inline data was embedded for this artifact.';
    var hint = item.external_path
      ? 'External copy at <code>'+escapeHtml(item.external_path)+'</code>'
      : '';
    return '<div class="art-shell">'
      + shellHead(item)
      + '<div class="art-shell-body" style="padding:24px"><div class="art-empty">'+escapeHtml(why)+'</div>'
      + (hint ? '<div class="art-empty">'+hint+'</div>' : '')
      + '</div>'
      + shellFoot()
      + '</div>';
  }

  function renderDetailsShell(item){
    var jsonText = JSON.stringify(item, null, 2);
    var highlighted = highlight(jsonText, 'json');
    var pre = '<pre class="art-code-pane wrap" style="padding:16px">'+highlighted+'</pre>';
    return '<div class="art-shell">' + shellHead(item, 'JSON details') +
           '<div class="art-shell-body art-code">'+pre+'</div>' + shellFoot() + '</div>';
  }

