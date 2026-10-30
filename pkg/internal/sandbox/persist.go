package sandbox

// PersistReport rewrites a completed sandbox report after a coordination layer
// attaches derived results such as NCER. The original report paths are reused.
func PersistReport(report *Report) error {
	if report == nil {
		return nil
	}
	return writeReports(report)
}
