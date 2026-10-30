package fusion

import (
	"errors"
	"math"
)

// OnlineLogistic is an AdaGrad-tuned logistic regression classifier designed
// for the continuous-learning loop inside [Intelligence]. It learns
// incrementally: one Update call per sample, no batch retraining.
//
// Regularisation: L2 penalty applied per update keeps weights bounded even
// under distribution shift (λ = OnlineL2, default 0).
//
// Thread-safety: not safe for concurrent access; wrap in a mutex if needed.
type OnlineLogistic struct {
	weights  []float64 // one weight per feature
	bias     float64
	gWeights []float64 // AdaGrad accumulated gradient squares (weights)
	gBias    float64   // AdaGrad accumulated gradient square (bias)
	lr       float64   // learning rate η
	l2       float64   // L2 regularisation coefficient
	samples  int
	dims     int
}

// NewOnlineLogistic creates an OnlineLogistic classifier for feature vectors
// of length dims. lr is the initial AdaGrad learning rate (e.g. 0.1); l2 is
// the L2 regularisation coefficient (e.g. 1e-5 or 0 for none).
func NewOnlineLogistic(dims int, lr, l2 float64) *OnlineLogistic {
	if dims <= 0 {
		dims = 1
	}
	if lr <= 0 {
		lr = 0.1
	}
	if l2 < 0 {
		l2 = 0
	}
	return &OnlineLogistic{
		weights:  make([]float64, dims),
		gWeights: make([]float64, dims),
		lr:       lr,
		l2:       l2,
		dims:     dims,
	}
}

// Dims returns the expected feature-vector width.
func (m *OnlineLogistic) Dims() int { return m.dims }

// Samples returns the total number of Update calls made so far.
func (m *OnlineLogistic) Samples() int { return m.samples }

// PredictProba returns the predicted probability that x belongs to class 1.
// The result is always in [0,1].
func (m *OnlineLogistic) PredictProba(x []float64) float64 {
	if len(x) != m.dims {
		return 0.5
	}
	return sigmoid(m.dotBias(x))
}

// Update performs one SGD step with AdaGrad adaptive learning rate, then
// applies L2 regularisation. label must be 0 or 1.
//
// Returns the predicted probability before the weight update (useful for
// tracking progressive accuracy during training).
func (m *OnlineLogistic) Update(x []float64, label int) (float64, error) {
	if len(x) != m.dims {
		return 0, errors.New("fusion: feature width mismatch")
	}
	if label != 0 && label != 1 {
		return 0, errors.New("fusion: label must be 0 or 1")
	}

	proba := sigmoid(m.dotBias(x))
	err := float64(label) - proba // gradient direction

	// AdaGrad + L2 update for weights.
	for i, xi := range x {
		g := err * xi
		m.gWeights[i] += g * g
		step := m.lr / (math.Sqrt(m.gWeights[i]) + 1e-8)
		m.weights[i] = m.weights[i]*(1-step*m.l2) + step*g
	}

	// Bias (no regularisation on bias).
	m.gBias += err * err
	m.bias += (m.lr / (math.Sqrt(m.gBias) + 1e-8)) * err

	m.samples++
	return proba, nil
}

// Weights returns a copy of the current weight vector (for inspection).
func (m *OnlineLogistic) Weights() []float64 {
	w := make([]float64, m.dims)
	copy(w, m.weights)
	return w
}

func (m *OnlineLogistic) dotBias(x []float64) float64 {
	s := m.bias
	for i, xi := range x {
		s += m.weights[i] * xi
	}
	return s
}

func sigmoid(z float64) float64 {
	if z >= 0 {
		e := math.Exp(-z)
		return 1 / (1 + e)
	}
	e := math.Exp(z)
	return e / (1 + e)
}
