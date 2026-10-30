package llmkeys

import "sort"

// Clustering groups a set of candidate values into structurally coherent
// buckets, so a report can say "3 GitHub-shaped tokens, 1 private key, 5
// unknown high-entropy blobs" instead of listing forty raw strings. Two
// grouping strategies are offered:
//
//   - ClusterByFingerprint: fast, exact grouping by Fingerprint
//     (family+shape+size+entropy band). O(n). Deterministic. Good default for
//     large candidate sets.
//   - ClusterSimilar: greedy similarity clustering with a tunable threshold,
//     which can merge near-but-not-identical shapes. O(n²), so it is capped.

// Cluster is a group of structurally similar values.
type Cluster struct {
	// Fingerprint is the shared signature (see Fingerprint). Empty for
	// similarity clusters, which have no single fingerprint.
	Fingerprint string
	// Family is the credential family shared by the members ("" if unknown or
	// mixed).
	Family string
	// Representative is a member chosen to stand for the cluster (the longest
	// member, which is usually the most complete/least truncated).
	Representative string
	// Members are the distinct values in the cluster.
	Members []string
	// Size is len(Members).
	Size int
	// SecretCount is how many members the classifier calls secrets.
	SecretCount int
	// MaxConfidence is the highest member confidence.
	MaxConfidence float64
}

// maxSimilarityClusterInputs bounds the O(n²) similarity clusterer so a huge
// candidate set cannot stall a scan. Above this, callers should use Cluster.
const maxSimilarityClusterInputs = 2000

// ClusterByFingerprint groups values by exact Fingerprint. Duplicate values
// collapse into a single member. The returned clusters are sorted by descending
// size, then by fingerprint for stable output.
func ClusterByFingerprint(values []string) []Cluster {
	groups := make(map[string]*Cluster)
	seenMember := make(map[string]map[string]bool)

	for _, raw := range values {
		f, verdict := ExtractWithVerdict(raw)
		fp := FingerprintFeatures(f)
		c := groups[fp]
		if c == nil {
			c = &Cluster{Fingerprint: fp, Family: f.Family}
			groups[fp] = c
			seenMember[fp] = make(map[string]bool)
		}
		if seenMember[fp][raw] {
			continue
		}
		seenMember[fp][raw] = true
		c.Members = append(c.Members, raw)
		if verdict.IsSecret {
			c.SecretCount++
		}
		if verdict.Confidence > c.MaxConfidence {
			c.MaxConfidence = verdict.Confidence
		}
	}

	out := make([]Cluster, 0, len(groups))
	for _, c := range groups {
		finalizeCluster(c)
		out = append(out, *c)
	}
	sortClusters(out)
	return out
}

// ClusterSimilar groups values greedily: each value joins the first existing
// cluster whose representative it is at least threshold-similar to (see
// Similarity), otherwise it seeds a new cluster. threshold is clamped to
// [0,1]; a sensible default is 0.6. Inputs beyond maxSimilarityClusterInputs
// are truncated and the remainder is ignored (use Cluster for very large sets).
func ClusterSimilar(values []string, threshold float64) []Cluster {
	threshold = clamp(threshold, 0.0, 1.0)
	if len(values) > maxSimilarityClusterInputs {
		values = values[:maxSimilarityClusterInputs]
	}

	// Deduplicate while preserving first-seen order.
	seen := make(map[string]bool, len(values))
	uniq := make([]string, 0, len(values))
	feats := make(map[string]Features, len(values))
	verds := make(map[string]Verdict, len(values))
	for _, raw := range values {
		if seen[raw] {
			continue
		}
		seen[raw] = true
		f, v := ExtractWithVerdict(raw)
		feats[raw] = f
		verds[raw] = v
		uniq = append(uniq, raw)
	}

	type acc struct {
		cluster *Cluster
		repVal  string
		repFeat Features
	}
	var accs []*acc

	for _, val := range uniq {
		f := feats[val]
		v := verds[val]
		var chosen *acc
		best := threshold
		for _, a := range accs {
			s := similarityFeatures(a.repVal, val, a.repFeat, f)
			if s >= best {
				best = s
				chosen = a
			}
		}
		if chosen == nil {
			c := &Cluster{Family: f.Family}
			chosen = &acc{cluster: c, repVal: val, repFeat: f}
			accs = append(accs, chosen)
		}
		c := chosen.cluster
		c.Members = append(c.Members, val)
		if v.IsSecret {
			c.SecretCount++
		}
		if v.Confidence > c.MaxConfidence {
			c.MaxConfidence = v.Confidence
		}
		// Mixed families collapse to "".
		if c.Family != f.Family {
			c.Family = ""
		}
	}

	out := make([]Cluster, 0, len(accs))
	for _, a := range accs {
		finalizeCluster(a.cluster)
		out = append(out, *a.cluster)
	}
	sortClusters(out)
	return out
}

// finalizeCluster fills Size and picks the longest member as Representative.
func finalizeCluster(c *Cluster) {
	c.Size = len(c.Members)
	rep := ""
	for _, m := range c.Members {
		if len(m) > len(rep) {
			rep = m
		}
	}
	c.Representative = rep
}

func sortClusters(cs []Cluster) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].Size != cs[j].Size {
			return cs[i].Size > cs[j].Size
		}
		if cs[i].MaxConfidence != cs[j].MaxConfidence {
			return cs[i].MaxConfidence > cs[j].MaxConfidence
		}
		return cs[i].Representative < cs[j].Representative
	})
}
