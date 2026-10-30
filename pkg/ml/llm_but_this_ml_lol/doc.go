// Package llmkeys is a small, fully offline "smart" secret classifier.
//
// Dumb scanners flag a finding the moment they see the word "private_key" or a
// known prefix like "AKIA" — even when the value behind it is junk such as
// "123456789", "test" or "your_key_here". This package looks at the *value*
// itself and decides whether it is a real-looking credential or noise.
//
// It learns from two embedded, synthetic datasets (no real secrets are shipped):
//
//   - keys_dataset.json  — example credentials for 30 services (positives)
//   - negatives.json     — placeholders, docs examples, UUIDs, hashes, code
//     references and other look-alikes (negatives)
//
// Classification combines four cheap signals: an exact-match against the learned
// junk database, placeholder/template markers, length, Shannon entropy and
// known credential-family prefixes.
//
// On top of the core classifier the package offers an offline analysis toolkit
// for turning a bag of scanned strings into decision-ready knowledge, all
// deterministic and dependency-free:
//
//   - Feature extraction (features.go): a structured, explainable feature
//     vector per value (entropy, character-class ratios, structural shape).
//   - Memoized classification (cache.go): a bounded LRU over Classify, since
//     large binaries repeat the same string constants many times.
//   - Similarity & fingerprinting (similarity.go): coarse structural signatures
//     and a [0,1] similarity score for "same kind of token?" questions.
//   - Clustering (cluster.go): group candidate secrets by shape/family so a
//     report shows a handful of clusters instead of dozens of raw strings.
//   - Anomaly detection (anomaly.go): rank unknown-format, credential-shaped
//     strings that carry no known prefix — the classifier's blind spot.
//   - Insights (insights.go): a compact summary (family histogram, severity
//     bands, clusters, anomalies) over everything a scanner extracted.
package llmkeys
