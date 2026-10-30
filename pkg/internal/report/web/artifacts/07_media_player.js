  // ──────────── MEDIA player (audio/video) ────────────
  function renderAudioShell(item){
    var src = item.embedded_data_uri || item.external_path || '';
    return '<div class="art-shell" data-kind="audio">'
      + shellHead(item, escapeHtml(item.mime || 'audio/*') + ' · ' + humanSize(item.size||0))
      + '<div class="art-shell-body">'
      +   '<div class="art-spectro-tabs" role="tablist">'
      +     '<button type="button" class="art-spectro-tab is-active" data-atab="player" role="tab">Player</button>'
      +     '<button type="button" class="art-spectro-tab" data-atab="waveform" role="tab">Waveform</button>'
      +     '<button type="button" class="art-spectro-tab" data-atab="spectrogram" role="tab">Spectrogram</button>'
      +   '</div>'
      +   '<div class="art-media" data-apane="player">'
      +     '<div class="art-media-art" aria-hidden="true">'
      +       '<svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>'
      +     '</div>'
      +     '<div class="art-media-info">'
      +       '<p class="t">'+escapeHtml(baseName(item.path||item.id))+'</p>'
      +       '<p class="s">'+escapeHtml(item.mime||'audio/*')+'</p>'
      +     '</div>'
      +     '<audio data-media preload="metadata"' + (src ? ' src="' + escapeHtml(src) + '"' : '') + '></audio>'
      +     renderPlayer()
      +   '</div>'
      +   '<div class="art-spectro-wrap" data-apane="waveform" hidden style="position:relative;">'
      +     '<canvas data-waveform-canvas style="display:block; width:100%; height:100%;"></canvas>'
      +     '<div class="art-waveform-playhead" data-waveform-playhead style="position:absolute; top:0; bottom:0; left:0; width:2px; background:#ff4757; pointer-events:none; transform:translate3d(0px,0px,0px); display:none; transition:transform 0.1s linear; z-index:5;"></div>'
      +     '<div class="art-spectro-msg" data-waveform-msg>Click to decode audio and render waveform</div>'
      +   '</div>'
      +   '<div class="art-spectro-wrap" data-apane="spectrogram" hidden>'
      +     '<canvas data-spectro-canvas></canvas>'
      +     '<div class="art-spectro-msg" data-spectro-msg>Click to decode audio and render spectrogram</div>'
      +     '<div class="art-spectro-legend" data-spectro-legend></div>'
      +     '<div class="art-spectro-legend-labels" data-spectro-legend-labels></div>'
      +   '</div>'
      + '</div>'
      + shellFoot('<kbd>Space</kbd> play/pause · <kbd>←</kbd>/<kbd>→</kbd> seek')
      + '</div>';
  }
  function renderVideoShell(item){
    var src = item.embedded_data_uri || item.external_path || '';
    return '<div class="art-shell" data-kind="video">'
      + shellHead(item, escapeHtml(item.mime || 'video/*') + ' · ' + humanSize(item.size||0))
      + '<div class="art-shell-body">'
      +   '<div class="art-media">'
      +     '<video data-media class="art-video-frame" playsinline preload="metadata"' + (src ? ' src="' + escapeHtml(src) + '"' : '') + '></video>'
      +     renderPlayer()
      +   '</div>'
      + '</div>'
      + shellFoot('<kbd>Space</kbd> play/pause · <kbd>←</kbd>/<kbd>→</kbd> seek · <kbd>M</kbd> mute')
      + '</div>';
  }
  function renderPlayer(){
    return '<div class="art-player" role="group" aria-label="Media controls">'
      + '<button type="button" class="pp" data-pp aria-label="Play">'
      +   '<svg class="icon-play" width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="display:block; margin:auto;"><path d="M8 5v14l11-7z"/></svg>'
      +   '<svg class="icon-pause" width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="display:none; margin:auto;"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>'
      + '</button>'
      + '<div class="seek">'
      +   '<input type="range" data-seek min="0" max="1000" value="0" step="1" aria-label="Seek">'
      +   '<div class="row"><span data-cur>0:00</span><span data-dur>0:00</span></div>'
      + '</div>'
      + '<div class="vol">'
      +   '<button type="button" class="art-iconbtn" data-mute aria-label="Mute">'
      +     '<svg class="icon-unmute" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:block; margin:auto;"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"/></svg>'
      +     '<svg class="icon-mute" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none; margin:auto;"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>'
      +   '</button>'
      +   '<input type="range" data-vol min="0" max="100" value="100" aria-label="Volume">'
      + '</div>'
      + '<button type="button" class="art-speed" data-speed title="Playback speed">1×</button>'
      + '<div class="art-visualizer" data-visualizer>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      +   '<div class="bar"></div>'
      + '</div>'
      + '</div>';
  }

  function bindMedia(dlg, item, kind){
    var media = dlg.querySelector('[data-media]');
    if(!media) return;
    var pp     = dlg.querySelector('[data-pp]');
    var seek   = dlg.querySelector('[data-seek]');
    var cur    = dlg.querySelector('[data-cur]');
    var dur    = dlg.querySelector('[data-dur]');
    var muteBt = dlg.querySelector('[data-mute]');
    var vol    = dlg.querySelector('[data-vol]');

    function fmt(t){
      if(!isFinite(t)) return '0:00';
      var s = Math.max(0, Math.floor(t));
      var m = Math.floor(s/60); s = s%60;
      return m + ':' + (s<10?'0':'') + s;
    }
    function setPP(){
      if(!pp) return;
      var playIcon = pp.querySelector('.icon-play');
      var pauseIcon = pp.querySelector('.icon-pause');
      var visualizer = dlg.querySelector('[data-visualizer]');
      if(media.paused){
        if(playIcon) playIcon.style.display = 'block';
        if(pauseIcon) pauseIcon.style.display = 'none';
        if(visualizer) visualizer.classList.remove('is-playing');
      } else {
        if(playIcon) playIcon.style.display = 'none';
        if(pauseIcon) pauseIcon.style.display = 'block';
        if(visualizer) visualizer.classList.add('is-playing');
      }
      pp.setAttribute('aria-label', media.paused ? 'Play' : 'Pause');
    }
    function setMuteState(){
      if(!muteBt) return;
      var unmuteIcon = muteBt.querySelector('.icon-unmute');
      var muteIcon = muteBt.querySelector('.icon-mute');
      if(media.muted){
        if(unmuteIcon) unmuteIcon.style.display = 'none';
        if(muteIcon) muteIcon.style.display = 'block';
      } else {
        if(unmuteIcon) unmuteIcon.style.display = 'block';
        if(muteIcon) muteIcon.style.display = 'none';
      }
    }
    function updatePlayhead(){
      var playhead = dlg.querySelector('[data-waveform-playhead]');
      if(playhead && isFinite(media.duration) && media.duration > 0){
        var cvs = dlg.querySelector('[data-waveform-canvas]');
        if(cvs && audioDecoded){
          playhead.style.display = 'block';
          var pct = media.currentTime / media.duration;
          var x = pct * cvs.clientWidth;
          playhead.style.transform = 'translate3d(' + x + 'px,0px,0px)';
        } else {
          playhead.style.display = 'none';
        }
      }
    }

    if(pp) pp.addEventListener('click', function(){
      if(media.paused) media.play().catch(function(){}); else media.pause();
    });
    if(seek) seek.addEventListener('input', function(){
      if(isFinite(media.duration) && media.duration > 0){
        media.currentTime = (parseInt(seek.value,10)/1000) * media.duration;
      }
    });
    media.addEventListener('timeupdate', function(){
      if(cur) cur.textContent = fmt(media.currentTime);
      if(seek && isFinite(media.duration) && media.duration > 0){
        seek.value = String(Math.round((media.currentTime/media.duration)*1000));
      }
      updatePlayhead();
    });
    media.addEventListener('loadedmetadata', function(){
      if(dur) dur.textContent = fmt(media.duration);
    });
    media.addEventListener('play',  setPP);
    media.addEventListener('pause', setPP);
    media.addEventListener('ended', setPP);

    if(muteBt) muteBt.addEventListener('click', function(){
      media.muted = !media.muted;
      setMuteState();
    });
    if(vol) vol.addEventListener('input', function(){
      media.volume = parseInt(vol.value,10)/100;
      media.muted = media.volume === 0;
      setMuteState();
    });

    // ── Playback speed cycle ──
    var speedBt = dlg.querySelector('[data-speed]');
    var speeds = [1, 1.25, 1.5, 2, 0.5, 0.75];
    var speedIdx = 0;
    if(speedBt){
      speedBt.addEventListener('click', function(){
        speedIdx = (speedIdx + 1) % speeds.length;
        media.playbackRate = speeds[speedIdx];
        speedBt.textContent = speeds[speedIdx] + '×';
        speedBt.classList.toggle('is-active', speeds[speedIdx] !== 1);
      });
    }

    // Keyboard shortcuts (don't fire when focus is in an input).
    dlg.addEventListener('keydown', function(e){
      if(e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) return;
      if(e.key === ' '){ e.preventDefault(); if(media.paused) media.play().catch(function(){}); else media.pause(); }
      else if(e.key === 'ArrowLeft')  { media.currentTime = Math.max(0, media.currentTime - 5); }
      else if(e.key === 'ArrowRight') { if(isFinite(media.duration)) media.currentTime = Math.min(media.duration, media.currentTime + 5); }
      else if(e.key === 'm' || e.key === 'M'){ media.muted = !media.muted; setMuteState(); }
    });

    // Clicking the waveform canvas to seek
    var cvs = dlg.querySelector('[data-waveform-canvas]');
    if(cvs){
      cvs.style.cursor = 'pointer';
      cvs.addEventListener('click', function(e){
        if(!audioDecoded || !isFinite(media.duration) || media.duration <= 0) return;
        var rect = cvs.getBoundingClientRect();
        var clickX = e.clientX - rect.left;
        var pct = clickX / rect.width;
        media.currentTime = pct * media.duration;
        updatePlayhead();
      });
    }

    setPP();
    setMuteState();
    var exp = dlg.querySelector('[data-export]');
    if(exp) exp.addEventListener('click', function(){ requestExport(item); });

    // ── Real audio-reactive visualizer (Web Audio FFT) ──
    // The CSS keyframe bars are only a fallback; once playback starts we tap
    // the actual audio stream with an AnalyserNode and drive the bars (and a
    // soft glow on the album art) from live frequency data.
    (function(){
      var bars = dlg.querySelectorAll('[data-visualizer] .bar');
      var artEl = dlg.querySelector('.art-media-art');
      if(!bars.length) return;
      var actx=null, analyser=null, srcNode=null, freq=null, raf=0;
      function ensureGraph(){
        if(actx) return true;
        try {
          actx = new (window.AudioContext||window.webkitAudioContext)();
          srcNode = actx.createMediaElementSource(media);
          analyser = actx.createAnalyser();
          analyser.fftSize = 64;
          analyser.smoothingTimeConstant = 0.8;
          srcNode.connect(analyser);
          analyser.connect(actx.destination);
          freq = new Uint8Array(analyser.frequencyBinCount);
          return true;
        } catch(e){ return false; }
      }
      function loop(){
        if(!analyser){ return; }
        analyser.getByteFrequencyData(freq);
        var n = bars.length;
        var step = Math.floor(freq.length / n) || 1;
        var sum = 0;
        for(var i=0;i<n;i++){
          var v = freq[i*step] / 255;          // 0..1
          var h = 3 + v*v*26;                   // emphasize peaks
          bars[i].style.height = h.toFixed(1)+'px';
          bars[i].style.opacity = (0.35 + v*0.65).toFixed(2);
          sum += v;
        }
        if(artEl){
          var energy = sum / n;
          artEl.style.boxShadow = '0 16px 48px rgba(126,182,255,'+(0.25+energy*0.5).toFixed(2)
            +'), inset 0 0 0 1px rgba(255,255,255,0.2)';
          artEl.style.transform = 'translateY('+(-energy*6).toFixed(1)+'px) scale('+(1+energy*0.03).toFixed(3)+')';
        }
        raf = requestAnimationFrame(loop);
      }
      media.addEventListener('play', function(){
        if(!ensureGraph()) return;            // fall back to CSS bars on failure
        if(actx.state === 'suspended') actx.resume();
        var vis = dlg.querySelector('[data-visualizer]');
        if(vis) vis.classList.add('is-live');  // disables CSS keyframes
        cancelAnimationFrame(raf); loop();
      });
      function stop(){
        cancelAnimationFrame(raf); raf=0;
        bars.forEach(function(b){ b.style.height=''; b.style.opacity=''; });
        if(artEl){ artEl.style.transform=''; }
      }
      media.addEventListener('pause', stop);
      media.addEventListener('ended', stop);
      // Release the AudioContext when the dialog closes.
      dlg.addEventListener('art-media-cleanup', function(){
        try { stop(); if(actx) actx.close(); } catch(_){}
      });
    })();

    var audioDecoded = null;
    dlg.querySelectorAll('[data-atab]').forEach(function(tab){
      tab.addEventListener('click', function(){
        var name = tab.getAttribute('data-atab');
        dlg.querySelectorAll('[data-atab]').forEach(function(t){ t.classList.toggle('is-active', t.getAttribute('data-atab')===name); });
        dlg.querySelectorAll('[data-apane]').forEach(function(p){ p.hidden = p.getAttribute('data-apane')!==name; });
        if((name==='waveform'||name==='spectrogram') && !audioDecoded){
          decodeAndRender();
        }
      });
    });
    // Click-to-decode on the message overlays
    var wfMsg = dlg.querySelector('[data-waveform-msg]');
    var spMsg = dlg.querySelector('[data-spectro-msg]');
    if(wfMsg) wfMsg.style.cursor='pointer';
    if(spMsg) spMsg.style.cursor='pointer';
    if(wfMsg) wfMsg.addEventListener('click', function(){ decodeAndRender(); });
    if(spMsg) spMsg.addEventListener('click', function(){ decodeAndRender(); });

    function decodeAndRender(){
      if(audioDecoded) return;
      var src = item.embedded_data_uri || item.external_path;
      if(!src) return;
      if(wfMsg) wfMsg.textContent = 'Decoding audio...';
      if(spMsg) spMsg.textContent = 'Decoding audio...';
      try{
        var actx = new (window.AudioContext||window.webkitAudioContext)();
        // Fetch the audio data
        if(src.indexOf('data:')===0){
          // data URI — decode base64
          var parts = src.split(',');
          var raw = atob(parts[1]||parts[0]);
          var buf = new ArrayBuffer(raw.length);
          var view = new Uint8Array(buf);
          for(var i=0;i<raw.length;i++) view[i]=raw.charCodeAt(i);
          actx.decodeAudioData(buf, function(decoded){
            audioDecoded = decoded;
            renderWaveform(decoded);
            renderSpectrogram(decoded);
          }, function(err){
            if(wfMsg) wfMsg.textContent = 'Failed to decode: '+err;
            if(spMsg) spMsg.textContent = 'Failed to decode: '+err;
          });
        } else {
          // external path — fetch
          fetch(src).then(function(r){return r.arrayBuffer();}).then(function(buf){
            actx.decodeAudioData(buf, function(decoded){
              audioDecoded = decoded;
              renderWaveform(decoded);
              renderSpectrogram(decoded);
            });
          }).catch(function(err){
            if(wfMsg) wfMsg.textContent = 'Failed to fetch: '+err;
            if(spMsg) spMsg.textContent = 'Failed to fetch: '+err;
          });
        }
      }catch(err){
        if(wfMsg) wfMsg.textContent = 'AudioContext not supported';
        if(spMsg) spMsg.textContent = 'AudioContext not supported';
      }
    }

    function renderWaveform(decoded){
      var cvs = dlg.querySelector('[data-waveform-canvas]');
      if(!cvs) return;
      if(wfMsg) wfMsg.style.display='none';
      var wc = cvs.getContext('2d');
      var samples = decoded.getChannelData(0);
      var W = Math.min(4096, cvs.parentElement.clientWidth*2||2048);
      var H = Math.min(512, cvs.parentElement.clientHeight*2||400);
      cvs.width = W; cvs.height = H;
      wc.fillStyle = '#0a0e15';
      wc.fillRect(0,0,W,H);
      // Draw center line
      wc.strokeStyle = 'rgba(126,182,255,.15)';
      wc.beginPath(); wc.moveTo(0,H/2); wc.lineTo(W,H/2); wc.stroke();
      // Draw waveform
      var step = Math.max(1, Math.floor(samples.length / W));
      wc.strokeStyle = '#7eb6ff';
      wc.lineWidth = 1;
      wc.beginPath();
      for(var x=0;x<W;x++){
        var si = Math.floor(x * samples.length / W);
        var mn=1, mx=-1;
        for(var j=0;j<step&&si+j<samples.length;j++){
          var v=samples[si+j];
          if(v<mn)mn=v; if(v>mx)mx=v;
        }
        var y1 = (1-mx)/2*H, y2 = (1-mn)/2*H;
        wc.moveTo(x,y1); wc.lineTo(x,y2);
      }
      wc.stroke();
      // RMS envelope
      wc.strokeStyle = 'rgba(255,208,102,.4)';
      wc.lineWidth = 1;
      wc.beginPath();
      var blockSize = Math.max(1, Math.floor(samples.length / W));
      for(var x=0;x<W;x++){
        var si = x * blockSize;
        var sum = 0;
        for(var j=0;j<blockSize&&si+j<samples.length;j++) sum+=samples[si+j]*samples[si+j];
        var rms = Math.sqrt(sum/blockSize);
        wc.moveTo(x, H/2 - rms*H/2); wc.lineTo(x, H/2 + rms*H/2);
      }
      wc.stroke();
    }

    function renderSpectrogram(decoded){
      var cvs = dlg.querySelector('[data-spectro-canvas]');
      if(!cvs) return;
      if(spMsg) spMsg.style.display='none';
      var sc = cvs.getContext('2d');
      var samples = decoded.getChannelData(0);
      var sr = decoded.sampleRate;
      var fftSize = 2048;
      var hop = 512;
      var cols = Math.floor((samples.length - fftSize) / hop);
      if(cols<1) return;
      var freqBins = fftSize/2;
      var W = Math.min(cols, 4096);
      var H = Math.min(freqBins, 512);
      cvs.width = W; cvs.height = H;
      var imgData = sc.createImageData(W, H);
      var d = imgData.data;
      // Hanning window
      var win = new Float32Array(fftSize);
      for(var i=0;i<fftSize;i++) win[i]=0.5*(1-Math.cos(2*Math.PI*i/(fftSize-1)));
      // Simple DFT via radix-2 FFT
      function fft(re, im){
        var n=re.length;
        for(var i=1,j=0;i<n;i++){
          var bit=n>>1;
          for(;j&bit;bit>>=1) j^=bit;
          j^=bit;
          if(i<j){var t=re[i];re[i]=re[j];re[j]=t;t=im[i];im[i]=im[j];im[j]=t;}
        }
        for(var len=2;len<=n;len*=2){
          var ang=2*Math.PI/len;
          var wRe=Math.cos(ang),wIm=-Math.sin(ang);
          for(var i=0;i<n;i+=len){
            var curRe=1,curIm=0;
            for(var j=0;j<len/2;j++){
              var uRe=re[i+j],uIm=im[i+j];
              var vRe=re[i+j+len/2]*curRe-im[i+j+len/2]*curIm;
              var vIm=re[i+j+len/2]*curIm+im[i+j+len/2]*curRe;
              re[i+j]=uRe+vRe; im[i+j]=uIm+vIm;
              re[i+j+len/2]=uRe-vRe; im[i+j+len/2]=uIm-vIm;
              var tmpR=curRe*wRe-curIm*wIm;
              curIm=curRe*wIm+curIm*wRe; curRe=tmpR;
            }
          }
        }
      }
      // Colormap: black→blue→cyan→yellow→white (like spectrogram tools)
      function spectroColor(val){
        var t=Math.max(0,Math.min(1,val));
        var r,g,b;
        if(t<0.25){r=0;g=0;b=t*4;}
        else if(t<0.5){r=0;g=(t-0.25)*4;b=1;}
        else if(t<0.75){r=(t-0.5)*4;g=1;b=1-(t-0.5)*4;}
        else{r=1;g=1;b=(t-0.75)*4;}
        return [Math.round(r*255),Math.round(g*255),Math.round(b*255)];
      }
      var re = new Float32Array(fftSize);
      var im = new Float32Array(fftSize);
      var colStep = Math.max(1, cols/W);
      var maxMag = 0;
      // First pass: compute magnitudes and find max
      var mags = new Float32Array(W * freqBins);
      for(var col=0;col<W;col++){
        var off = Math.floor(col * colStep) * hop;
        for(var i=0;i<fftSize;i++){re[i]=(off+i<samples.length?samples[off+i]:0)*win[i];im[i]=0;}
        fft(re, im);
        for(var i=0;i<freqBins;i++){
          var mag = Math.sqrt(re[i]*re[i]+im[i]*im[i]);
          mags[col*freqBins+i]=mag;
          if(mag>maxMag)maxMag=mag;
        }
      }
      // Second pass: render with dB scale
      var ref = maxMag > 0 ? maxMag : 1;
      for(var col=0;col<W;col++){
        for(var row=0;row<H;row++){
          var fi = Math.floor(row * freqBins / H);
          var mag = mags[col*freqBins+fi];
          var db = 20*Math.log10(mag/ref+1e-10);
          var norm = Math.max(0, Math.min(1, (db+80)/80)); // -80dB to 0dB range
          var c = spectroColor(norm);
          var px = ((H-1-row)*W+col)*4;
          d[px]=c[0]; d[px+1]=c[1]; d[px+2]=c[2]; d[px+3]=255;
        }
      }
      sc.putImageData(imgData, 0, 0);
      // Legend gradient
      var leg = dlg.querySelector('[data-spectro-legend]');
      if(leg) leg.style.background='linear-gradient(to bottom,#fff,#ff0,#0ff,#00f,#000)';
      var labels = dlg.querySelector('[data-spectro-legend-labels]');
      if(labels){
        var nyq = sr/2;
        labels.innerHTML = '<span>'+Math.round(nyq)+'Hz</span><span>'+Math.round(nyq*0.75)+'Hz</span><span>'+Math.round(nyq*0.5)+'Hz</span><span>'+Math.round(nyq*0.25)+'Hz</span><span>0Hz</span>';
      }
    }
  }

