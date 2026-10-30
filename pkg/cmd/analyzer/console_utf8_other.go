//go:build !windows

package main

// Go writes UTF-8 already. Do not force an unavailable locale or transcode
// analyzed files, binary streams or third-party tool output.
func configureConsoleUTF8() error { return nil }
