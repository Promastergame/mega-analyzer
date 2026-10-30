# Browser console dependency

`pkg/cmd/analyzer/web/assets/novnc.js` bundles the unmodified noVNC 1.6.0
`core/rfb.js` module and its dependencies. It is loaded locally on demand;
the running application does not fetch a CDN or execute npm.

Source: https://github.com/novnc/noVNC/tree/v1.6.0

Reproduction, from an extracted official v1.6.0 source archive:

```text
esbuild core/rfb.js --bundle --format=esm --minify --legal-comments=eof --outfile=novnc.js
```

Bundler: esbuild 0.25.10. The npm noVNC distribution is not used as the
build input because its CommonJS conversion contains top-level await.

License notices and complete license texts are included in
`assets/novnc-LICENSE.txt`, served at `/static/novnc-LICENSE.txt`.
noVNC uses MPL-2.0; incorporated code also carries BSD and MIT notices.
