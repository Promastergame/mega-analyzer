/* Offline OpenAPI 3 reference and same-origin request console. No dependencies. */
(function () {
  "use strict";
  const operations = document.getElementById("operations"), status = document.getElementById("spec-status");
  const token = document.getElementById("token"), search = document.getElementById("search");
  let spec = {}, generation = 0;
  const methods = ["get", "post", "put", "patch", "delete", "head", "options"];
  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (cls) node.className = cls;
    return node;
  }
  function resolve(value) {
    const seen = new Set();
    while (value && value.$ref && value.$ref.startsWith("#/") && !seen.has(value.$ref)) {
      seen.add(value.$ref);
      value = value.$ref.slice(2).split("/").reduce((v, k) => v && v[k.replace(/~1/g, "/").replace(/~0/g, "~")], spec);
    }
    return value || {};
  }
  function example(schema, depth) {
    schema = resolve(schema);
    if (schema.example !== undefined) return schema.example;
    if (schema.default !== undefined) return schema.default;
    if (schema.enum) return schema.enum[0];
    if (depth > 4) return null;
    if (schema.type === "array") return [example(schema.items, depth + 1)];
    if (schema.properties) return Object.fromEntries(Object.entries(schema.properties).map(([k, v]) => [k, example(v, depth + 1)]));
    if (schema.type === "boolean") return false;
    if (schema.type === "number" || schema.type === "integer") return 0;
    return "";
  }
  function filter() {
    let count = 0;
    const query = search.value.trim().toLowerCase();
    operations.querySelectorAll(".operation").forEach(node => { node.hidden = !node.dataset.search.includes(query); if (!node.hidden) count++; });
    document.getElementById("empty").hidden = count > 0;
  }
  function renderOperation(path, method, raw, pathParameters) {
    const operation = resolve(raw), card = el("details", undefined, "operation");
    card.dataset.search = (method + " " + path + " " + operation.summary + " " + operation.description).toLowerCase();
    const summary = el("summary");
    summary.append(el("span", method.toUpperCase(), "method " + method), el("code", path, "path"), el("span", operation.summary || "", "summary"));
    const detail = el("div", undefined, "detail"), form = el("form");
    detail.append(el("p", operation.description || operation.summary || path, "description"));
    const inputs = [], params = new Map();
    (pathParameters || []).concat(operation.parameters || []).map(resolve).forEach(p => params.set(p.in + ":" + p.name, p));
    params.forEach(p => {
      const label = el("label", p.name + " · " + p.in + (p.required ? " (required)" : "")), input = el("input");
      input.required = !!p.required; input.placeholder = p.description || resolve(p.schema).type || "value";
      const initial = p.example !== undefined ? p.example : resolve(p.schema).default;
      if (initial !== undefined) input.value = String(initial);
      label.append(input); form.append(label); inputs.push({parameter:p, input});
    });
    const content = resolve(operation.requestBody).content || {};
    let body = null, multipart = [];
    if (content["application/json"]) {
      const label = el("label", "Request body · application/json"); body = el("textarea"); body.spellcheck = false;
      body.value = JSON.stringify(content["application/json"].example || example(content["application/json"].schema, 0), null, 2);
      label.append(body); form.append(label);
    } else if (content["multipart/form-data"]) {
      const schema = resolve(content["multipart/form-data"].schema);
      Object.entries(schema.properties || {}).forEach(([name, rawSchema]) => {
        const field = resolve(rawSchema), label = el("label", name + " · multipart"), input = el("input");
        input.type = field.format === "binary" ? "file" : "text"; input.required = (schema.required || []).includes(name);
        label.append(input); form.append(label); multipart.push({name, input});
      });
    }
    const send = el("button", "Send " + method.toUpperCase() + " request"); send.type = "submit";
    const message = el("span", "", "request-status"); message.setAttribute("role", "status");
    const response = el("pre", "", "response"); response.hidden = true;
    form.append(send, message, response);
    form.addEventListener("submit", async event => {
      event.preventDefault(); send.disabled = true; message.textContent = "Sending…"; response.hidden = false;
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 30000);
      try {
        let target = path;
        const headers = {Accept:"application/json"}, query = new URLSearchParams();
        inputs.forEach(({parameter:p, input}) => {
          if (!input.value && !p.required) return;
          if (p.in === "path") target = target.replace("{" + p.name + "}", encodeURIComponent(input.value));
          if (p.in === "query") query.set(p.name, input.value);
          if (p.in === "header" && !/^(host|origin|cookie|authorization|x-mega-analyzer-token)$/i.test(p.name)) headers[p.name] = input.value;
        });
        const url = new URL(target, location.origin);
        if (!target.startsWith("/") || target.startsWith("//") || url.origin !== location.origin) throw new Error("Only endpoints on this server are allowed.");
        url.search = query.toString();
        if (token.value) headers["X-Mega-Analyzer-Token"] = token.value;
        const options = {method:method.toUpperCase(), headers, signal:controller.signal, redirect:"error"};
        if (body && method !== "get" && method !== "head") { options.body = JSON.stringify(JSON.parse(body.value)); headers["Content-Type"] = "application/json"; }
        if (multipart.length) { options.body = new FormData(); multipart.forEach(({name,input}) => { const v = input.type === "file" ? input.files[0] : input.value; if (v !== undefined) options.body.append(name, v); }); }
        const result = await fetch(url, options), rawText = await result.text();
        message.textContent = "HTTP " + result.status; message.classList.toggle("error", !result.ok);
        let output = rawText; try { output = JSON.stringify(JSON.parse(rawText), null, 2); } catch (_) {}
        response.textContent = output || "(empty response)";
      } catch (error) { message.textContent = "Request failed"; response.textContent = error.name === "AbortError" ? "Request timed out after 30 seconds." : error.message; }
      finally { clearTimeout(timer); send.disabled = false; }
    });
    const schemas = el("details", undefined, "schema"); schemas.append(el("summary", "Response schemas"), el("pre", JSON.stringify(operation.responses || {}, null, 2)));
    detail.append(form, schemas); card.append(summary, detail); operations.append(card);
  }
  async function load() {
    const serial = ++generation; status.textContent = "Loading the local API specification…";
    try {
      const headers = token.value ? {"X-Mega-Analyzer-Token":token.value} : {};
      const result = await fetch("/api/v1/swagger.json", {headers});
      if (!result.ok) throw new Error("Could not load specification (HTTP " + result.status + "). Check the API token.");
      const data = await result.json(); if (serial !== generation) return;
      spec = data; operations.replaceChildren();
      Object.entries(spec.paths || {}).forEach(([path,item]) => methods.forEach(method => { if (item[method]) renderOperation(path, method, item[method], item.parameters); }));
      status.textContent = "Version " + spec.info.version + " · " + operations.childElementCount + " endpoints · Available offline";
      filter();
    } catch (error) { if (serial === generation) status.textContent = error.message; }
  }
  document.getElementById("controls").addEventListener("submit", event => { event.preventDefault(); load(); });
  document.getElementById("download-spec").addEventListener("click", async event => {
    event.preventDefault();
    try {
      const result = await fetch("/api/v1/swagger.json", {headers:token.value ? {"X-Mega-Analyzer-Token":token.value} : {}});
      if (!result.ok) throw new Error("Download failed (HTTP " + result.status + "). Check the API token.");
      const url = URL.createObjectURL(await result.blob()), link = el("a");
      link.href = url; link.download = "openapi.json"; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) { status.textContent = error.message; }
  });
  search.addEventListener("input", filter); load();
})();
