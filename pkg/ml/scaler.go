package ml

// StandardScaler performs standard score normalization (z-score normalization),
// scaling features so that they have 0 mean and 1 variance.
type StandardScaler struct {
	Means   []float64 `json:"means"`
	StdDevs []float64 `json:"std_devs"`
}

// NewStandardScaler creates a new StandardScaler instance.
func NewStandardScaler() *StandardScaler {
	return &StandardScaler{}
}

// Fit computes the mean and standard deviation for each feature from X.
func (s *StandardScaler) Fit(X [][]float64) {
	if len(X) == 0 {
		return
	}
	nFeat := len(X[0])
	s.Means = make([]float64, nFeat)
	for _, row := range X {
		for j, x := range row {
			if j < nFeat {
				s.Means[j] += x
			}
		}
	}
	for j := range s.Means {
		s.Means[j] /= float64(len(X))
	}
	s.StdDevs = perFeatureStd(X)
}

// Transform standardizes a single feature vector using the fitted means and std devs.
func (s *StandardScaler) Transform(x []float64) []float64 {
	if len(x) == 0 || len(s.Means) == 0 || len(s.StdDevs) == 0 {
		return x
	}
	out := make([]float64, len(x))
	for i, val := range x {
		if i < len(s.Means) && i < len(s.StdDevs) {
			std := s.StdDevs[i]
			if std == 0 {
				std = 1
			}
			out[i] = (val - s.Means[i]) / std
		} else {
			out[i] = val
		}
	}
	return out
}

// TransformBatch standardizes a batch of feature vectors.
func (s *StandardScaler) TransformBatch(X [][]float64) [][]float64 {
	if len(X) == 0 {
		return nil
	}
	out := make([][]float64, len(X))
	for i, row := range X {
		out[i] = s.Transform(row)
	}
	return out
}
