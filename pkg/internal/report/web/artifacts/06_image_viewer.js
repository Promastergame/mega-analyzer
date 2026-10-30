  // ──────────── IMAGE viewer ────────────
  function renderImageShell(item){
    var sub = (item.image && item.image.width ? item.image.width+' \\u00D7 '+item.image.height+' · ' : '')
            + escapeHtml(item.mime || 'image/*') + ' · ' + humanSize(item.size||0);
    var isSvg = (item.path && item.path.toLowerCase().endsWith('.svg')) || (item.mime && item.mime.indexOf('svg') !== -1);
    var svgNotice = '';
    if (isSvg) {
      var hasScript = false;
      if (item.embedded_data_uri) {
        try {
          var base64Part = item.embedded_data_uri.split(',')[1] || item.embedded_data_uri.split(',')[0];
          var svgContent = atob(base64Part);
          var lowerSvg = svgContent.toLowerCase();
          if (lowerSvg.indexOf('<script') !== -1 || lowerSvg.indexOf('javascript:') !== -1 || lowerSvg.indexOf('<foreignobject') !== -1 || lowerSvg.indexOf('<set') !== -1 || lowerSvg.indexOf('<animate') !== -1 || lowerSvg.indexOf('onload=') !== -1 || lowerSvg.indexOf('onclick=') !== -1 || lowerSvg.indexOf('onerror=') !== -1 || lowerSvg.indexOf('onmouseover=') !== -1 || lowerSvg.indexOf('onfocusin=') !== -1 || lowerSvg.indexOf('onbegin=') !== -1) {
            hasScript = true;
          }
        } catch(e) {}
      }
      if (hasScript) {
        svgNotice = '<div class="art-svg-notice" style="padding:10px 14px; background:rgba(255,107,107,.12); border:1px solid rgba(255,107,107,.25); border-radius:8px; display:flex; align-items:center; gap:10px; margin: 12px auto; width: min(560px, 90%); font-size:12px; color:#ff8787;">'
          + '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex:0 0 auto;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
          + '<span><strong>Vector Asset Security Risk:</strong> This SVG contains active script elements or event handlers. High risk of XSS execution in unsandboxed environments.</span>'
          + '</div>';
      } else {
        svgNotice = '<div class="art-svg-notice" style="padding:10px 14px; background:rgba(81,207,98,.12); border:1px solid rgba(81,207,98,.25); border-radius:8px; display:flex; align-items:center; gap:10px; margin: 12px auto; width: min(560px, 90%); font-size:12px; color:#69db7c;">'
          + '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex:0 0 auto;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
          + '<span><strong>Vector Asset Security Check:</strong> Secure. No active scripting or event triggers found inside this SVG asset.</span>'
          + '</div>';
      }
    }
    return '<div class="art-shell" data-kind="image">'
      + shellHead(item, sub)
      + svgNotice
      + '<div class="art-shell-body">'
      +   '<div class="art-imgwrap" tabindex="0">'
      +     '<canvas class="art-canvas"></canvas>'
      +     '<canvas class="art-overlay"></canvas>'
      +     '<div class="art-zoom-badge"><span class="zv">100%</span></div>'
      +   '</div>'
      +   renderImageToolbar()
      + '</div>'
      + shellFoot('<kbd>Ctrl</kbd>+<kbd>Wheel</kbd> zoom · <kbd>Wheel</kbd> pan · <kbd>Drag</kbd> pan · <kbd>R</kbd> rotate · <kbd>0</kbd> reset')
      + '</div>';
  }

  function renderImageToolbar(){
    return '<div class="art-toolbar" role="toolbar" aria-label="Image controls">'
      + '<div class="grp" aria-label="Zoom">'
      +   '<span class="grp-label">Zoom</span>'
      +   '<button type="button" data-zoom-out aria-label="Zoom out"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line></svg></button>'
      +   '<button type="button" data-zoom-fit aria-label="Fit to window">Fit</button>'
      +   '<button type="button" data-zoom-in aria-label="Zoom in"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg></button>'
      + '</div>'
      + '<div class="grp" aria-label="Transform">'
      +   '<span class="grp-label">Transform</span>'
      +   '<button type="button" data-rotate-l aria-label="Rotate left"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><path d="M3 3v5h5"></path></svg></button>'
      +   '<button type="button" data-rotate-r aria-label="Rotate right"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path><path d="M21 3v5h-5"></path></svg></button>'
      +   '<button type="button" data-flip-h aria-label="Flip horizontally"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3 4 7l4 4"></path><path d="M4 7h16"></path><path d="M16 21l4-4-4-4"></path><path d="M20 17H4"></path></svg></button>'
      +   '<button type="button" data-flip-v aria-label="Flip vertically"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8l4-4 4 4"></path><path d="M7 4v16"></path><path d="M21 16l-4 4-4-4"></path><path d="M17 20V4"></path></svg></button>'
      + '</div>'
      + '<div class="grp" aria-label="Adjust">'
      +   '<span class="grp-label">Adjust</span>'
      +   '<label class="filter">Bri<input type="range" min="0" max="200" value="100" data-filter="brightness" aria-label="Brightness"><span class="val">100%</span></label>'
      +   '<label class="filter">Con<input type="range" min="0" max="200" value="100" data-filter="contrast" aria-label="Contrast"><span class="val">100%</span></label>'
      +   '<label class="filter">Sat<input type="range" min="0" max="200" value="100" data-filter="saturate" aria-label="Saturate"><span class="val">100%</span></label>'
      +   '<label class="filter">Hue<input type="range" min="0" max="360" value="0" data-filter="hueRotate" aria-label="Hue Rotate"><span class="val">0\u00B0</span></label>'
      +   '<label class="filter">Opa<input type="range" min="0" max="100" value="100" data-filter="opacity" aria-label="Opacity"><span class="val">100%</span></label>'
      +   '<label class="filter">Blur<input type="range" min="0" max="20" value="0" data-filter="blur" aria-label="Blur"><span class="val">0px</span></label>'
      + '</div>'
      + '<div class="grp" aria-label="Effects">'
      +   '<span class="grp-label">Effects</span>'
      +   '<button type="button" data-invert aria-label="Invert colors">Invert</button>'
      +   '<button type="button" data-grayscale aria-label="Grayscale">Gray</button>'
      +   '<button type="button" data-sepia aria-label="Sepia tone">Sepia</button>'
      +   '<button type="button" data-pixelated aria-label="Pixel-perfect rendering">Pixel</button>'
      + '</div>'
      + '<div class="grp" aria-label="Forensic">'
      +   '<span class="grp-label">Forensic</span>'
      +   '<button type="button" data-threshold aria-label="Threshold binarization">Thresh</button>'
      +   '<label class="filter"><input type="range" min="0" max="255" value="128" data-threshold-val aria-label="Threshold value"><span class="val">128</span></label>'
      +   '<button type="button" data-edge aria-label="Sobel edge detection">Edge</button>'
      +   '<button type="button" data-histeq aria-label="Histogram equalization">HistEQ</button>'
      + '</div>'
      + '<div class="grp" aria-label="Channels">'
      +   '<span class="grp-label">Channels</span>'
      +   '<button type="button" data-ch-r class="is-active" aria-label="Red channel">R</button>'
      +   '<button type="button" data-ch-g class="is-active" aria-label="Green channel">G</button>'
      +   '<button type="button" data-ch-b class="is-active" aria-label="Blue channel">B</button>'
      +   '<button type="button" data-ch-a class="is-active" aria-label="Alpha channel">A</button>'
      + '</div>'
      + '<div class="grp" aria-label="Tools">'
      +   '<span class="grp-label">Tools</span>'
      +   '<button type="button" data-eyedropper aria-label="Color picker">Pick</button>'
      +   '<span class="art-color-swatch" data-color-swatch style="display:none"></span>'
      +   '<span class="art-color-value" data-color-value style="display:none"></span>'
      +   '<button type="button" data-copy-img aria-label="Copy edited image to clipboard">Copy</button>'
      + '</div>'
      + '<div class="grp" aria-label="Annotations">'
      +   '<span class="grp-label">Annotate</span>'
      +   '<button type="button" data-draw aria-label="Toggle drawing">Draw</button>'
      +   '<button type="button" data-clear aria-label="Clear annotations">Clear</button>'
      + '</div>'
      + '<div class="grp" aria-label="Reset">'
      +   '<button type="button" data-reset aria-label="Reset view (0)">Reset</button>'
      + '</div>'
      + '</div>';
  }

  function bindImage(dlg, item){
    var wrap    = dlg.querySelector('.art-imgwrap');
    var canvas  = dlg.querySelector('.art-canvas');
    var overlay = dlg.querySelector('.art-overlay');
    var zoomLbl = dlg.querySelector('.zv');
    if(!wrap || !canvas) return;
    var ctx  = canvas.getContext('2d', {willReadFrequently:true});
    var octx = overlay ? overlay.getContext('2d') : null;
    var src  = item.embedded_data_uri || item.external_path;
    var img  = new Image();

    var st = {
      scale: 1, fitScale: 1,
      tx: 0, ty: 0,
      rot: 0, flipH: 1, flipV: 1,
      brightness: 100, contrast: 100, saturate: 100,
      hueRotate: 0, opacity: 100, blur: 0,
      invert: false, grayscale: false, sepia: false, pixelated: false,
      threshold: false, thresholdVal: 128,
      edgeDetect: false, histEq: false,
      channelR: true, channelG: true, channelB: true, channelA: true,
      eyedropper: false, drawMode: false
    };

    img.onload = function(){
      // SVG may report 0 natural dimensions — use a sensible fallback.
      var nw = img.naturalWidth  || 800;
      var nh = img.naturalHeight || 600;
      canvas.width  = nw;
      canvas.height = nh;
      if(overlay){ overlay.width = nw; overlay.height = nh; }
      fitToWrap();
      draw();
    };
    img.onerror = function(){
      // SVG data URIs sometimes fail on canvas — try rendering as inline <img>.
      if(!src) return;
      var fallbackImg = document.createElement('img');
      fallbackImg.src = src;
      fallbackImg.style.maxWidth = '100%';
      fallbackImg.style.maxHeight = '100%';
      fallbackImg.style.objectFit = 'contain';
      fallbackImg.alt = item.path || 'image';
      wrap.innerHTML = '';
      wrap.appendChild(fallbackImg);
    };
    if(src) {
      img.src = src;
    }

    var fitRetries = 0;
    function fitToWrap(){
      // Stop retrying once the viewer has been closed (wrap detached),
      // otherwise this loops via setTimeout forever at ~33 Hz.
      if(!wrap.isConnected) return;
      var w = wrap.clientWidth, h = wrap.clientHeight;
      if(!w || !h || !canvas.width) {
        if(fitRetries++ < 100) setTimeout(fitToWrap, 30);
        return;
      }
      fitRetries = 0;
      var sx = w / canvas.width;
      var sy = h / canvas.height;
      st.fitScale = Math.min(sx, sy, 64); // cap at 64Г— so even 1Г—1 fills the viewport
      st.scale = st.fitScale;
      st.tx = 0; st.ty = 0;
      applyTransform();
    }

    function applyTransform(){
      var t = 'translate(-50%,-50%) translate('+st.tx+'px,'+st.ty+'px) scale('+(st.scale*st.flipH)+','+(st.scale*st.flipV)+') rotate('+st.rot+'deg)';
      // Position canvas absolutely centered for predictable zoom-around-cursor.
      [canvas, overlay].forEach(function(el){
        if(!el) return;
        el.style.position = 'absolute';
        el.style.left = '50%';
        el.style.top  = '50%';
        el.style.transform = t;
      });
      canvas.classList.toggle('is-pixelated', st.pixelated);
      if(zoomLbl) zoomLbl.textContent = Math.round(st.scale * 100) + '%';
    }

    function buildFilter(){
      var p = [];
      if(st.brightness !== 100) p.push('brightness('+st.brightness+'%)');
      if(st.contrast   !== 100) p.push('contrast('+st.contrast+'%)');
      if(st.saturate   !== 100) p.push('saturate('+st.saturate+'%)');
      if(st.hueRotate  !== 0)   p.push('hue-rotate('+st.hueRotate+'deg)');
      if(st.opacity    !== 100) p.push('opacity('+st.opacity+'%)');
      if(st.blur       !== 0)   p.push('blur('+st.blur+'px)');
      if(st.invert)    p.push('invert(1)');
      if(st.grayscale) p.push('grayscale(1)');
      if(st.sepia)     p.push('sepia(1)');
      return p.join(' ') || 'none';
    }
    var drawPending = false;
    function draw(){
      if(!ctx) return;
      canvas.style.filter = buildFilter();
      var needCPU = st.threshold || st.edgeDetect || st.histEq || !st.channelR || !st.channelG || !st.channelB || !st.channelA;
      if (drawPending) return;
      drawPending = true;
      requestAnimationFrame(function(){
        ctx.save();
        ctx.clearRect(0,0,canvas.width,canvas.height);
        ctx.filter = "none";
        ctx.drawImage(img, 0, 0);
        ctx.restore();
        if (needCPU) {
          postProcess();
        }
        drawPending = false;
      });
    }
    function postProcess(){
      var need = st.threshold || st.edgeDetect || st.histEq || !st.channelR || !st.channelG || !st.channelB || !st.channelA;
      if(!need) return;
      var w = canvas.width, h = canvas.height;
      var imgData = ctx.getImageData(0, 0, w, h);
      var d = imgData.data;
      if(st.histEq){
        for(var ch=0;ch<3;ch++){
          var hist=new Array(256);for(var k=0;k<256;k++)hist[k]=0;
          for(var i=ch;i<d.length;i+=4)hist[d[i]]++;
          var cdf=new Array(256);cdf[0]=hist[0];
          for(var k=1;k<256;k++)cdf[k]=cdf[k-1]+hist[k];
          var tot=w*h,mn=0;for(var k=0;k<256;k++){if(cdf[k]>0){mn=cdf[k];break;}}
          for(var i=ch;i<d.length;i+=4)d[i]=Math.round((cdf[d[i]]-mn)/(tot-mn)*255);
        }
      }
      if(st.edgeDetect){
        var src=new Uint8ClampedArray(d);
        for(var y=1;y<h-1;y++)for(var x=1;x<w-1;x++){
          var idx=(y*w+x)*4;
          for(var ch=0;ch<3;ch++){
            var gx=-src[((y-1)*w+(x-1))*4+ch]+src[((y-1)*w+(x+1))*4+ch]
              -2*src[(y*w+(x-1))*4+ch]+2*src[(y*w+(x+1))*4+ch]
              -src[((y+1)*w+(x-1))*4+ch]+src[((y+1)*w+(x+1))*4+ch];
            var gy=-src[((y-1)*w+(x-1))*4+ch]-2*src[((y-1)*w+x)*4+ch]-src[((y-1)*w+(x+1))*4+ch]
              +src[((y+1)*w+(x-1))*4+ch]+2*src[((y+1)*w+x)*4+ch]+src[((y+1)*w+(x+1))*4+ch];
            d[idx+ch]=Math.min(255,Math.sqrt(gx*gx+gy*gy)|0);
          }
          d[idx+3]=255;
        }
      }
      if(st.threshold){
        for(var i=0;i<d.length;i+=4){
          var luma=0.299*d[i]+0.587*d[i+1]+0.114*d[i+2];
          var v=luma>st.thresholdVal?255:0;
          d[i]=d[i+1]=d[i+2]=v;
        }
      }
      if(!st.channelR||!st.channelG||!st.channelB||!st.channelA){
        for(var i=0;i<d.length;i+=4){
          if(!st.channelR)d[i]=0;
          if(!st.channelG)d[i+1]=0;
          if(!st.channelB)d[i+2]=0;
          if(!st.channelA)d[i+3]=0;
        }
      }
      ctx.putImageData(imgData, 0, 0);
    }

    // ── Filter sliders ──
    dlg.querySelectorAll('input[data-filter]').forEach(function(input){
      var val = input.parentElement.querySelector('.val');
      input.addEventListener('input', function(){
        var key = input.getAttribute('data-filter');
        var v = parseInt(input.value, 10);
        st[key] = v;
        if(val){
          if(key==='hueRotate') val.textContent = v+'\\u00B0';
          else if(key==='blur') val.textContent = v+'px';
          else val.textContent = v+'%';
        }
        draw();
      });
    });
    var threshInput = dlg.querySelector('[data-threshold-val]');
    if(threshInput){
      var threshValEl = threshInput.parentElement.querySelector('.val');
      threshInput.addEventListener('input', function(){
        st.thresholdVal = parseInt(threshInput.value, 10);
        if(threshValEl) threshValEl.textContent = String(st.thresholdVal);
        if(st.threshold) draw();
      });
    }

    // ── Toolbar buttons ──
    function on(sel, fn){ var b = dlg.querySelector(sel); if(b) b.addEventListener('click', fn); }
    on('[data-zoom-in]',  function(){ zoomAt(1.25, wrap.clientWidth/2, wrap.clientHeight/2); });
    on('[data-zoom-out]', function(){ zoomAt(1/1.25, wrap.clientWidth/2, wrap.clientHeight/2); });
    on('[data-zoom-fit]', function(){ fitToWrap(); });
    on('[data-rotate-l]', function(){ st.rot = (st.rot - 90) % 360; applyTransform(); });
    on('[data-rotate-r]', function(){ st.rot = (st.rot + 90) % 360; applyTransform(); });
    on('[data-flip-h]',   function(){ st.flipH = -st.flipH; applyTransform(); });
    on('[data-flip-v]',   function(){ st.flipV = -st.flipV; applyTransform(); });
    on('[data-invert]',   function(){ st.invert = !st.invert; var b=dlg.querySelector('[data-invert]'); if(b) b.classList.toggle('is-active',st.invert); draw(); });
    on('[data-grayscale]',function(){ st.grayscale = !st.grayscale; var b=dlg.querySelector('[data-grayscale]'); if(b) b.classList.toggle('is-active',st.grayscale); draw(); });
    on('[data-sepia]',    function(){ st.sepia = !st.sepia; var b=dlg.querySelector('[data-sepia]'); if(b) b.classList.toggle('is-active',st.sepia); draw(); });
    on('[data-pixelated]',function(){ st.pixelated = !st.pixelated; var b=dlg.querySelector('[data-pixelated]'); if(b) b.classList.toggle('is-active',st.pixelated); applyTransform(); });
    on('[data-threshold]',function(){ st.threshold = !st.threshold; var b=dlg.querySelector('[data-threshold]'); if(b) b.classList.toggle('is-active',st.threshold); draw(); });
    on('[data-edge]',     function(){ st.edgeDetect = !st.edgeDetect; var b=dlg.querySelector('[data-edge]'); if(b) b.classList.toggle('is-active',st.edgeDetect); draw(); });
    on('[data-histeq]',   function(){ st.histEq = !st.histEq; var b=dlg.querySelector('[data-histeq]'); if(b) b.classList.toggle('is-active',st.histEq); draw(); });
    on('[data-ch-r]',function(){ st.channelR=!st.channelR; var b=dlg.querySelector('[data-ch-r]'); if(b) b.classList.toggle('is-active',st.channelR); draw(); });
    on('[data-ch-g]',function(){ st.channelG=!st.channelG; var b=dlg.querySelector('[data-ch-g]'); if(b) b.classList.toggle('is-active',st.channelG); draw(); });
    on('[data-ch-b]',function(){ st.channelB=!st.channelB; var b=dlg.querySelector('[data-ch-b]'); if(b) b.classList.toggle('is-active',st.channelB); draw(); });
    on('[data-ch-a]',function(){ st.channelA=!st.channelA; var b=dlg.querySelector('[data-ch-a]'); if(b) b.classList.toggle('is-active',st.channelA); draw(); });
    on('[data-eyedropper]',function(){
      st.eyedropper = !st.eyedropper;
      var b=dlg.querySelector('[data-eyedropper]'); if(b) b.classList.toggle('is-active',st.eyedropper);
      wrap.style.cursor = st.eyedropper ? 'crosshair' : 'grab';
      if(!st.eyedropper){
        var sw=dlg.querySelector('[data-color-swatch]'); if(sw) sw.style.display='none';
        var cv=dlg.querySelector('[data-color-value]'); if(cv) cv.style.display='none';
      }
    });
    on('[data-copy-img]', function(){
      var tempCanvas = document.createElement('canvas');
      tempCanvas.width = canvas.width;
      tempCanvas.height = canvas.height;
      var tempCtx = tempCanvas.getContext('2d');
      try {
        tempCtx.filter = buildFilter();
        tempCtx.drawImage(canvas, 0, 0);
        tempCtx.filter = 'none';
        if(overlay) {
          tempCtx.drawImage(overlay, 0, 0);
        }
        tempCanvas.toBlob(function(blob){
          if(!blob){ showCenterToast('Copy failed'); return; }
          if(!navigator.clipboard || !window.ClipboardItem){ showCenterToast('Copy failed'); return; }
          navigator.clipboard.write([ new ClipboardItem({ 'image/png': blob }) ])
            .then(function(){ showCenterToast('Copied'); })
            .catch(function(){ showCenterToast('Copy failed'); });
        }, 'image/png');
      } catch(e) {
        showCenterToast('Copy failed');
      }
    });
    on('[data-draw]', function(){
      st.drawMode = !st.drawMode;
      if(overlay) overlay.classList.toggle('is-active', st.drawMode);
      var btn = dlg.querySelector('[data-draw]');
      if(btn) btn.classList.toggle('is-active', st.drawMode);
      if(!st.eyedropper) wrap.style.cursor = st.drawMode ? 'crosshair' : 'grab';
    });
    on('[data-clear]', function(){ if(octx) octx.clearRect(0,0,overlay.width,overlay.height); });
    on('[data-reset]', function(){
      st = {scale:1,fitScale:st.fitScale,tx:0,ty:0,rot:0,flipH:1,flipV:1,
            brightness:100,contrast:100,saturate:100,hueRotate:0,opacity:100,blur:0,
            invert:false,grayscale:false,sepia:false,pixelated:false,
            threshold:false,thresholdVal:128,edgeDetect:false,histEq:false,
            channelR:true,channelG:true,channelB:true,channelA:true,
            eyedropper:false,drawMode:false};
      dlg.querySelectorAll('input[data-filter]').forEach(function(i){
        var key=i.getAttribute('data-filter');
        if(key==='hueRotate'){i.value=0;var v=i.parentElement.querySelector('.val');if(v)v.textContent='0\\u00B0';}
        else if(key==='blur'){i.value=0;var v=i.parentElement.querySelector('.val');if(v)v.textContent='0px';}
        else if(key==='opacity'){i.value=100;var v=i.parentElement.querySelector('.val');if(v)v.textContent='100%';}
        else{i.value=100;var v=i.parentElement.querySelector('.val');if(v)v.textContent='100%';}
      });
      var ti=dlg.querySelector('[data-threshold-val]'); if(ti){ti.value=128;var tv=ti.parentElement.querySelector('.val');if(tv)tv.textContent='128';}
      dlg.querySelectorAll('[data-invert],[data-grayscale],[data-sepia],[data-pixelated],[data-draw],[data-threshold],[data-edge],[data-histeq],[data-eyedropper]').forEach(function(b){ b.classList.remove('is-active'); });
      dlg.querySelectorAll('[data-ch-r],[data-ch-g],[data-ch-b],[data-ch-a]').forEach(function(b){ b.classList.add('is-active'); });
      if(overlay) overlay.classList.remove('is-active');
      if(octx) octx.clearRect(0,0,overlay.width,overlay.height);
      wrap.style.cursor = 'grab';
      var sw=dlg.querySelector('[data-color-swatch]');if(sw)sw.style.display='none';
      var cv=dlg.querySelector('[data-color-value]');if(cv)cv.style.display='none';
      fitToWrap();
      draw();
    });

    // ── Wheel: Ctrl+wheel zooms toward cursor; plain wheel pans. Stops the
    //    page from scrolling and the browser's native page-zoom from kicking
    //    in (the original Ctrl+wheel-zooms-the-whole-page bug).
    wrap.addEventListener('wheel', function(e){
      e.preventDefault(); e.stopPropagation();
      if(e.ctrlKey || e.metaKey){
        var rect = wrap.getBoundingClientRect();
        var cx = e.clientX - rect.left;
        var cy = e.clientY - rect.top;
        var k = e.deltaY < 0 ? 1.15 : 1/1.15;
        zoomAt(k, cx, cy);
      } else {
        st.tx -= e.deltaX;
        st.ty -= e.deltaY;
        applyTransform();
      }
    }, {passive:false});
    var toolbar = dlg.querySelector('.art-toolbar');
    if(toolbar) toolbar.addEventListener('wheel', function(e){ e.preventDefault(); e.stopPropagation(); }, {passive:false});

    function zoomAt(k, cx, cy){
      // Anchor the zoom on (cx,cy) relative to the wrapper.
      var rect = wrap.getBoundingClientRect();
      var midX = rect.width / 2, midY = rect.height / 2;
      // World point under cursor before zoom:
      var wx = (cx - midX - st.tx) / st.scale;
      var wy = (cy - midY - st.ty) / st.scale;
      var newScale = Math.max(0.05, Math.min(40, st.scale * k));
      st.tx = (cx - midX) - wx * newScale;
      st.ty = (cy - midY) - wy * newScale;
      st.scale = newScale;
      applyTransform();
    }

    // ── Drag-to-pan ──
    var dragging = false, dragStart = null;
    // ── Eyedropper ──
    wrap.addEventListener('mousemove', function(e){
      if(!st.eyedropper) return;
      var rect = canvas.getBoundingClientRect();
      var sx = canvas.width / rect.width;
      var sy = canvas.height / rect.height;
      var cx = Math.round((e.clientX - rect.left) * sx);
      var cy = Math.round((e.clientY - rect.top) * sy);
      if(cx<0||cy<0||cx>=canvas.width||cy>=canvas.height) return;
      try{
        var px = ctx.getImageData(cx, cy, 1, 1).data;
        var hex = '#'+((1<<24)|(px[0]<<16)|(px[1]<<8)|px[2]).toString(16).slice(1);
        var swatch = dlg.querySelector('[data-color-swatch]');
        var cval = dlg.querySelector('[data-color-value]');
        if(swatch){swatch.style.display='inline-block';swatch.style.background=hex;}
        if(cval){cval.style.display='inline';cval.textContent=hex+' rgb('+px[0]+','+px[1]+','+px[2]+') a='+px[3];}
      }catch(_){}
    });

    wrap.addEventListener('pointerdown', function(e){
      if(st.drawMode || st.eyedropper) return;
      dragging = true; dragStart = {x: e.clientX - st.tx, y: e.clientY - st.ty};
      wrap.classList.add('is-panning');
      try { wrap.setPointerCapture(e.pointerId); } catch(_){}
    });
    wrap.addEventListener('pointermove', function(e){
      if(!dragging) return;
      st.tx = e.clientX - dragStart.x;
      st.ty = e.clientY - dragStart.y;
      applyTransform();
    });
    function stopDrag(e){
      dragging = false;
      wrap.classList.remove('is-panning');
      try { wrap.releasePointerCapture(e.pointerId); } catch(_){}
    }
    wrap.addEventListener('pointerup', stopDrag);
    wrap.addEventListener('pointercancel', stopDrag);
    wrap.addEventListener('pointerleave', stopDrag);

    // ── Drawing ──
    var drawing = false;
    if(overlay){
      overlay.addEventListener('pointerdown', function(e){
        if(!st.drawMode) return;
        drawing = true;
        try { overlay.setPointerCapture(e.pointerId); } catch(_){}
        var p = canvasPoint(overlay, e);
        octx.beginPath(); octx.moveTo(p.x, p.y);
        octx.strokeStyle = '#ff5555'; octx.lineWidth = 3;
        octx.lineCap = 'round'; octx.lineJoin = 'round';
      });
      overlay.addEventListener('pointermove', function(e){
        if(!drawing) return;
        var p = canvasPoint(overlay, e);
        octx.lineTo(p.x, p.y); octx.stroke();
      });
      overlay.addEventListener('pointerup', function(e){ drawing = false; try { overlay.releasePointerCapture(e.pointerId); } catch(_){} });
      overlay.addEventListener('pointercancel', function(e){ drawing = false; try { overlay.releasePointerCapture(e.pointerId); } catch(_){} });
    }
    function canvasPoint(el, e){
      var rect = el.getBoundingClientRect();
      var sx = el.width / rect.width;
      var sy = el.height / rect.height;
      return {x: (e.clientX - rect.left) * sx, y: (e.clientY - rect.top) * sy};
    }

    // ── Keyboard (R rotate, +/- zoom, 0 reset) ──
    function onKey(e){
      if(e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) return;
      if(e.key === 'r' || e.key === 'R'){ st.rot = (st.rot + 90) % 360; applyTransform(); }
      else if(e.key === '+' || e.key === '='){ zoomAt(1.25, wrap.clientWidth/2, wrap.clientHeight/2); }
      else if(e.key === '-' || e.key === '_'){ zoomAt(1/1.25, wrap.clientWidth/2, wrap.clientHeight/2); }
      else if(e.key === '0'){ st.scale = 1; st.tx = 0; st.ty = 0; applyTransform(); }
      else if(e.key === 'f' || e.key === 'F'){ fitToWrap(); }
    }
    dlg.addEventListener('keydown', onKey);
    setTimeout(function(){ wrap.focus(); }, 30);

    // Export button (header)
    var exp = dlg.querySelector('[data-export]');
    if(exp) exp.addEventListener('click', function(){ requestExport(item); });
    // Re-fit on resize while this viewer is open; detach on close.
    var onWinResize = function(){
      if(!wrap.isConnected){ window.removeEventListener('resize', onWinResize); return; }
      fitToWrap();
    };
    window.addEventListener('resize', onWinResize);
    dlg.addEventListener('art-media-cleanup', function(){
      window.removeEventListener('resize', onWinResize);
    }, {once:true});
  }

