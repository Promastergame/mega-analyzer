package pipeline

// Runtime components are intentionally scanned in full. A basename, path, ELF
// header or embedded version string cannot authenticate a stock component.
// Future suppression must require a reviewed content hash and version baseline,
// retain its reason in the report, and scan changed content on any mismatch.
