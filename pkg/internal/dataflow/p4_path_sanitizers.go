// Filesystem safety requires a control-dependent containment check. Historical
// blanket sanitizer rules for URL encoding / canonicalization were unsound:
// normalization can resolve to an outside path and does not mutate File objects.
// The independent Java counterexample and precision_v2_test.go cover this.
package dataflow
