  var dataEl = document.getElementById('artifacts-data');
  if(!dataEl) return;
  var view; try { view = JSON.parse(dataEl.textContent); } catch(e){ return; }
  if(!view || !view.items) return;
  var items = {};
  view.items.forEach(function(it){ items[it.id] = it; });
  var allowExport = view.allow_export === true;
  var iconCopySvg = '<svg viewBox="0 0 24 24" style="width:16px;height:16px;stroke:currentColor;stroke-width:2;fill:none;stroke-linecap:round;stroke-linejoin:round;display:block;"><path d="M7 9.667a2.667 2.667 0 0 1 2.667 -2.667h8.666a2.667 2.667 0 0 1 2.667 2.667v8.666a2.667 2.667 0 0 1 -2.667 2.667h-8.666a2.667 2.667 0 0 1 -2.667 -2.667l0 -8.666" /><path d="M4.012 16.737a2.005 2.005 0 0 1 -1.012 -1.737v-10c0 -1.1 .9 -2 2 -2h10c.75 0 1.412 .412 1.738 1.012l-8.738 8.738a2.667 2.667 0 0 0 -2.667 2.667l-1.321 1.321" /></svg>';
  var iconCheckSvg = '<svg viewBox="0 0 24 24" style="width:16px;height:16px;stroke:#51cf66;stroke-width:2;fill:none;stroke-linecap:round;stroke-linejoin:round;display:block;"><path d="M5 12l5 5l10 -10" /></svg>';

