// Package webui serves the Mega-Analyzer control surface: the single-page app,
// the scan/job API, the SSE log stream, the live-device bridge and the artifact
// downloads.
//
// Layout
//
//	server.go          Server type, Options, bind + graceful shutdown
//	router.go          the one and only route table
//	security.go        panic recovery, security headers, local-origin guard, token
//	static.go          embedded asset serving (ETag, Range, 304)
//	assets.go          //go:embed of assets/*, content hashes
//	assets/            index.html, app.css, app.js, error.html
//	handlers_*.go      one file per endpoint family, methods on *Server
//	job.go / store.go  scan job buffer + registry
//	runner.go          spawning the analyzer, log fan-out
//	logstream.go       line splitting, ANSI stripping, progress detection
//	validate.go        argument / path / URL allowlists
//	modes.go           analysis modes and CLI argument building
//	device_*.go        adb, AVD, VirtualBox, VMware discovery
//	hostinfo.go        host platform detection (incl. Android/Termux)
//	upload.go          multipart intake, sandbox file listing/download
//	deps.go            handlers owned by other packages, injected
//
// Everything that used to be a package-level closure inside a 780-line
// runWebUI is now a method on Server, so state is injected instead of global.
package web
