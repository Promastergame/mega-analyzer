package web

// runWebUI keeps the old entry point alive for the migrated tests. Production
// code should build a Server explicitly so it can be shut down and injected.
func runWebUI(port int) error {
	s, err := New(Options{Port: port, OpenBrowser: shouldOpenWebUIBrowser()})
	if err != nil {
		return err
	}
	return s.ListenAndServe()
}
